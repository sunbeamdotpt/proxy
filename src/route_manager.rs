// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Route manager — drives the compiler and owns the lifecycle of the compiled
//! routing table.
//!
//! Upstream configuration sources (Gateway API, TOML, future XDS/nginx/Caddy)
//! each produce a canonical [`ir::RouteTable`]. The manager accepts those
//! tables, compiles them into a [`CompiledRouteTable`], resolves conflicts
//! across sources by priority, versions the result, and atomically hot-swaps
//! the table used by the proxy.

use crate::ir::compile::{CompileError, CompiledL4Config, CompiledRouteTable};
use crate::ir::{ListenerConfig, RouteTable};
use crate::proxy::{CompiledRewrites, SunbeamProxy};
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

/// Identifier for a route source.
pub type SourceId = Arc<str>;

const DEFAULT_SOURCE: &str = "gateway-api";

/// A successfully compiled version of the route table.
#[derive(Clone, Debug)]
pub struct Version {
    /// Stable identifier for this version.
    pub id: Uuid,
    /// Source that produced the update.
    pub source: SourceId,
    /// When the version was applied.
    pub applied_at: Instant,
    /// Compiled route table.
    pub table: Arc<CompiledRouteTable>,
    /// Compiled L4 configuration.
    pub l4_config: Arc<CompiledL4Config>,
    /// Compiled rewrite rules for this version.
    pub rewrites: Arc<CompiledRewrites>,
}

/// Lightweight summary of a version for inspection/rollback decisions.
#[derive(Clone, Debug)]
pub struct VersionSummary {
    /// Version identifier.
    pub id: Uuid,
    /// Source that produced the update.
    pub source: SourceId,
    /// When the version was applied.
    pub applied_at: Instant,
}

/// Central manager for the proxy's compiled routing table.
///
/// `RouteManager` is `Send + Sync` and is intended to be shared via an `Arc`
/// between the proxy and the background configuration watchers.
pub struct RouteManager {
    /// Current compiled route table.
    current: Arc<ArcSwap<CompiledRouteTable>>,
    /// Current compiled L4 configuration.
    l4_config: Arc<ArcSwap<CompiledL4Config>>,
    /// Current compiled rewrite rules.
    rewrites: Arc<ArcSwap<CompiledRewrites>>,
    /// Per-source raw route tables.
    sources: Mutex<HashMap<SourceId, RouteTable>>,
    /// Priority for each source. Higher values win ties.
    priorities: Mutex<HashMap<SourceId, i64>>,
    /// Applied versions, oldest first.
    history: Mutex<VecDeque<Version>>,
    /// Maximum number of versions to retain.
    max_history: usize,
}

impl RouteManager {
    /// Create a new route manager with the given version history limit.
    ///
    /// The manager starts with an empty compiled table so the proxy can be
    /// constructed before any configuration source has reported.
    pub fn new(max_history: usize) -> Self {
        let empty_table = CompiledRouteTable::default();
        let empty_l4 = CompiledL4Config::default();
        let empty_rewrites = SunbeamProxy::compile_rewrites_from_ir(&empty_table);
        Self {
            current: Arc::new(ArcSwap::from_pointee(empty_table)),
            l4_config: Arc::new(ArcSwap::from_pointee(empty_l4)),
            rewrites: Arc::new(ArcSwap::from_pointee(empty_rewrites)),
            sources: Mutex::new(HashMap::new()),
            priorities: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::with_capacity(max_history.max(1))),
            max_history,
        }
    }

    /// Return a handle to the atomic compiled route table.
    pub fn current(&self) -> Arc<ArcSwap<CompiledRouteTable>> {
        Arc::clone(&self.current)
    }

    /// Return a handle to the atomic compiled L4 configuration.
    pub fn l4_config(&self) -> Arc<ArcSwap<CompiledL4Config>> {
        Arc::clone(&self.l4_config)
    }

    /// Return a handle to the atomic compiled rewrite table.
    pub fn rewrites(&self) -> Arc<ArcSwap<CompiledRewrites>> {
        Arc::clone(&self.rewrites)
    }

    /// Set the priority for a source. Higher priority sources win when both
    /// claim the same hostname/prefix.
    pub fn set_priority(&self, source: impl Into<SourceId>, priority: i64) {
        self.priorities
            .lock()
            .unwrap()
            .insert(source.into(), priority);
    }

    /// Apply a new route table from a source.
    ///
    /// The table is merged with any other known sources, compiled, and
    /// atomically swapped into place. If compilation fails, the current table
    /// and source state are left unchanged.
    pub fn apply(
        &self,
        source: impl Into<SourceId>,
        table: RouteTable,
    ) -> Result<(), CompileError> {
        let source: SourceId = source.into();

        // Build a tentative source map with the new table and compile it
        // before committing anything.
        let mut tentative_sources = {
            let sources = self.sources.lock().unwrap();
            sources.clone()
        };
        tentative_sources.insert(source.clone(), table);

        let merged = Self::merge_sources(&tentative_sources, &self.priorities.lock().unwrap());
        let compiled_l4 = Arc::new(CompiledL4Config::compile(merged.clone())?);
        let compiled = CompiledRouteTable::compile(merged)?;
        let compiled_rewrites = Arc::new(SunbeamProxy::compile_rewrites_from_ir(&compiled));
        let compiled_arc = Arc::new(compiled);

        // Commit: swap the atomic tables first, then record the source and
        // version history.
        self.current.store(Arc::clone(&compiled_arc));
        self.l4_config.store(Arc::clone(&compiled_l4));
        self.rewrites.store(Arc::clone(&compiled_rewrites));

        {
            let mut sources = self.sources.lock().unwrap();
            *sources = tentative_sources;
        }

        let version = Version {
            id: Uuid::new_v4(),
            source,
            applied_at: Instant::now(),
            table: compiled_arc,
            l4_config: compiled_l4,
            rewrites: compiled_rewrites,
        };

        {
            let mut history = self.history.lock().unwrap();
            if history.len() >= self.max_history {
                history.pop_front();
            }
            history.push_back(version);
        }

        tracing::info!("route table updated");
        Ok(())
    }

    /// Roll back to an earlier version.
    ///
    /// `steps` is the number of versions to go back: `1` restores the
    /// previously applied version. Returns `true` if a rollback was performed.
    pub fn rollback(&self, steps: usize) -> bool {
        if steps == 0 {
            return false;
        }
        let mut history = self.history.lock().unwrap();
        if steps >= history.len() {
            return false;
        }
        let new_len = history.len() - steps;
        let target = history.get(new_len - 1).cloned();
        if let Some(target) = target {
            self.current.store(target.table);
            self.l4_config.store(target.l4_config);
            self.rewrites.store(target.rewrites);
            history.truncate(new_len);
            tracing::info!(steps, "route table rolled back");
            true
        } else {
            false
        }
    }

    /// Return a summary of retained versions, oldest first.
    pub fn versions(&self) -> Vec<VersionSummary> {
        let history = self.history.lock().unwrap();
        history
            .iter()
            .map(|v| VersionSummary {
                id: v.id,
                source: Arc::clone(&v.source),
                applied_at: v.applied_at,
            })
            .collect()
    }

    /// Merge route tables from all known sources according to priority.
    fn merge_sources(
        sources: &HashMap<SourceId, RouteTable>,
        priorities: &HashMap<SourceId, i64>,
    ) -> RouteTable {
        let mut ordered: Vec<(&SourceId, &RouteTable)> = sources.iter().collect();
        // Higher priority sources are processed first so their L4 routes appear
        // earlier in the compiled order. For listeners and TLS certs we keep the
        // first (highest-priority) entry with a given id.
        ordered.sort_by(|(a_id, _), (b_id, _)| {
            let a_priority = priorities.get(*a_id).copied().unwrap_or(0);
            let b_priority = priorities.get(*b_id).copied().unwrap_or(0);
            b_priority
                .cmp(&a_priority)
                .then_with(|| a_id.as_ref().cmp(b_id.as_ref()))
        });

        let mut merged = RouteTable::default();
        let mut listeners: BTreeMap<Arc<str>, ListenerConfig> = BTreeMap::new();
        let mut tls_certs: BTreeMap<Arc<str>, crate::ir::TlsCertConfig> = BTreeMap::new();

        for (_, table) in ordered {
            for l in &table.listeners {
                listeners
                    .entry(Arc::clone(&l.id))
                    .or_insert_with(|| l.clone());
            }
            merged.hosts.extend(table.hosts.clone());
            merged.acme_routes.extend(table.acme_routes.clone());
            merged.l4_routes.extend(table.l4_routes.clone());
            for c in &table.tls_certs {
                tls_certs
                    .entry(Arc::clone(&c.id))
                    .or_insert_with(|| c.clone());
            }
        }

        merged.listeners = listeners.into_values().collect();
        merged.tls_certs = tls_certs.into_values().collect();
        merged
    }

    /// Spawn a background thread that applies incoming `RouteTable`s.
    ///
    /// Returns the manager and a sender for the default source
    /// (`"gateway-api"`). The receiver drains pending updates and keeps only
    /// the latest table before each apply, which prevents a backlog of stale
    /// snapshots.
    pub fn spawn(max_history: usize) -> (Arc<Self>, mpsc::Sender<RouteTable>) {
        let manager = Arc::new(Self::new(max_history));
        let (tx, rx) = mpsc::channel::<RouteTable>();
        let mgr = Arc::clone(&manager);

        std::thread::spawn(move || {
            let mut last: Option<RouteTable> = None;
            while let Ok(table) = rx.recv() {
                // Drain pending updates; only the latest snapshot matters.
                let mut latest = table;
                while let Ok(t) = rx.try_recv() {
                    latest = t;
                }
                // Skip no-op updates before compiling.
                if last.as_ref() == Some(&latest) {
                    continue;
                }
                if let Err(e) = mgr.apply(DEFAULT_SOURCE, latest.clone()) {
                    tracing::warn!(error = %e, "route manager: failed to apply update");
                } else {
                    last = Some(latest);
                }
            }
        });

        (manager, tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        Action, BackendProtocol, HostRoute, HostnameMatch, PathMatch, RequestMatch, RouteAction,
        Rule, WeightedBackend,
    };
    use std::collections::HashMap;

    fn simple_backend() -> RouteAction {
        RouteAction {
            backends: vec![WeightedBackend {
                backend: "svc:80".into(),
                weight: 1,
                protocol: BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            }],
            timeout: None,
            request_filters: vec![],
            response_filters: vec![],
            mirror_backends: vec![],
            mirror_fractions: vec![],
            cache: None,
            body_rewrites: vec![],
            auth: None,
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }
    }

    fn route_table_for_host(hostname: &str) -> RouteTable {
        RouteTable {
            listeners: vec![],
            hosts: vec![HostRoute {
                hostname: HostnameMatch::Exact(hostname.into()),
                listener_ids: vec![],
                listener_hostname: None,
                listener_port: None,
                gateway_api: true,
                disable_secure_redirection: false,
                rules: vec![Rule {
                    matches: vec![RequestMatch {
                        path: Some(PathMatch::Prefix("/".into())),
                        ..Default::default()
                    }],
                    action: Action::Route(simple_backend()),
                    rule_order: 0,
                }],
            }],
            acme_routes: HashMap::new(),
            l4_routes: vec![],
            tls_certs: vec![],
        }
    }

    #[test]
    fn new_manager_has_empty_table() {
        let mgr = RouteManager::new(10);
        let current = mgr.current().load();
        assert!(current.exact_hosts.is_empty());
        assert!(current.wildcard_hosts.is_empty());
        assert!(current.any_host.is_none());
    }

    #[test]
    fn apply_updates_current_table() {
        let mgr = RouteManager::new(10);
        mgr.apply("gateway-api", route_table_for_host("example.com"))
            .unwrap();
        let current = mgr.current().load();
        assert!(current
            .lookup("example.com", 0, "/", "GET", &Default::default(), None)
            .is_some());
    }

    #[test]
    fn apply_records_versions() {
        let mgr = RouteManager::new(10);
        mgr.apply("gateway-api", route_table_for_host("a.test"))
            .unwrap();
        mgr.apply("gateway-api", route_table_for_host("b.test"))
            .unwrap();
        assert_eq!(mgr.versions().len(), 2);
    }

    #[test]
    fn rollback_reverts_to_previous_version() {
        let mgr = RouteManager::new(10);
        mgr.apply("gateway-api", route_table_for_host("v1.test"))
            .unwrap();
        mgr.apply("gateway-api", route_table_for_host("v2.test"))
            .unwrap();

        assert!(mgr
            .current()
            .load()
            .lookup("v2.test", 0, "/", "GET", &Default::default(), None)
            .is_some());
        assert!(mgr.rollback(1));
        assert!(mgr
            .current()
            .load()
            .lookup("v1.test", 0, "/", "GET", &Default::default(), None)
            .is_some());
        assert!(mgr
            .current()
            .load()
            .lookup("v2.test", 0, "/", "GET", &Default::default(), None)
            .is_none());
        assert_eq!(mgr.versions().len(), 1);
    }

    #[test]
    fn rollback_zero_or_too_many_is_noop() {
        let mgr = RouteManager::new(10);
        mgr.apply("gateway-api", route_table_for_host("only.test"))
            .unwrap();
        assert!(!mgr.rollback(0));
        assert!(!mgr.rollback(5));
    }

    #[test]
    fn history_drops_oldest_when_limit_reached() {
        let mgr = RouteManager::new(2);
        mgr.apply("gateway-api", route_table_for_host("a.test"))
            .unwrap();
        mgr.apply("gateway-api", route_table_for_host("b.test"))
            .unwrap();
        mgr.apply("gateway-api", route_table_for_host("c.test"))
            .unwrap();
        assert_eq!(mgr.versions().len(), 2);
        // Oldest version was evicted; rollback(1) should go to b.test.
        assert!(mgr.rollback(1));
        assert!(mgr
            .current()
            .load()
            .lookup("b.test", 0, "/", "GET", &Default::default(), None)
            .is_some());
    }

    #[test]
    fn higher_priority_source_wins_conflict() {
        let mgr = RouteManager::new(10);
        mgr.set_priority("toml", 100);
        mgr.set_priority("gateway-api", 0);

        // gateway-api claims example.com first.
        let mut gw_table = route_table_for_host("example.com");
        gw_table.hosts[0].rules[0].action = Action::Route(RouteAction {
            backends: vec![WeightedBackend {
                backend: "gw:80".into(),
                weight: 1,
                protocol: BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            }],
            ..simple_backend()
        });
        mgr.apply("gateway-api", gw_table).unwrap();

        // toml claims the same host but with higher priority.
        let mut toml_table = route_table_for_host("example.com");
        toml_table.hosts[0].rules[0].action = Action::Route(RouteAction {
            backends: vec![WeightedBackend {
                backend: "toml:80".into(),
                weight: 1,
                protocol: BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            }],
            ..simple_backend()
        });
        mgr.apply("toml", toml_table).unwrap();

        let plan = mgr
            .current()
            .load()
            .lookup("example.com", 0, "/", "GET", &Default::default(), None)
            .unwrap();
        let backend = match &plan.upstream {
            Some(up) => up.backends[0].backend.as_ref(),
            None => panic!("expected upstream"),
        };
        assert_eq!(backend, "toml:80");
    }

    #[test]
    fn spawn_channel_applies_updates() {
        let (mgr, tx) = RouteManager::spawn(10);
        tx.send(route_table_for_host("spawn.test")).unwrap();
        // Wait briefly for the background thread.
        for _ in 0..50 {
            if mgr
                .current()
                .load()
                .lookup("spawn.test", 0, "/", "GET", &Default::default(), None)
                .is_some()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(mgr
            .current()
            .load()
            .lookup("spawn.test", 0, "/", "GET", &Default::default(), None)
            .is_some());
    }

    #[test]
    fn apply_compiles_l4_config() {
        let mgr = RouteManager::new(10);
        let mut table = route_table_for_host("example.com");
        table.listeners.push(crate::ir::ListenerConfig {
            id: "tcp-l".into(),
            bind_addr: "0.0.0.0:9000".into(),
            protocol: crate::ir::Protocol::Tcp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        });
        table.l4_routes.push(crate::ir::L4Route {
            listener_id: "tcp-l".into(),
            listener_hostname: crate::ir::HostnameMatch::Any,
            match_: crate::ir::L4Match::Any,
            action: crate::ir::L4Action::TcpRelay(vec![]),
        });
        mgr.apply("gateway-api", table).unwrap();

        let l4 = mgr.l4_config().load();
        assert_eq!(l4.listeners.len(), 1);
        assert_eq!(l4.listeners[0].protocol, crate::ir::Protocol::Tcp);
        assert_eq!(l4.tcp_routes.len(), 1);
    }

    #[test]
    fn higher_priority_listener_wins_conflict() {
        let mgr = RouteManager::new(10);
        mgr.set_priority("toml", 100);
        mgr.set_priority("gateway-api", 0);

        let mut low = route_table_for_host("low.test");
        low.listeners.push(crate::ir::ListenerConfig {
            id: "shared".into(),
            bind_addr: "0.0.0.0:8000".into(),
            protocol: crate::ir::Protocol::Tcp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        });

        let mut high = route_table_for_host("high.test");
        high.listeners.push(crate::ir::ListenerConfig {
            id: "shared".into(),
            bind_addr: "0.0.0.0:9000".into(),
            protocol: crate::ir::Protocol::Udp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        });

        mgr.apply("gateway-api", low).unwrap();
        mgr.apply("toml", high).unwrap();

        let l4 = mgr.l4_config().load();
        assert_eq!(l4.listeners.len(), 1);
        assert_eq!(l4.listeners[0].protocol, crate::ir::Protocol::Udp);
        assert_eq!(l4.listeners[0].bind_addr.as_ref(), "0.0.0.0:9000");
    }

    #[test]
    fn higher_priority_tls_cert_wins_conflict() {
        let mgr = RouteManager::new(10);
        mgr.set_priority("toml", 100);
        mgr.set_priority("gateway-api", 0);

        let mut low = route_table_for_host("low.test");
        low.tls_certs.push(crate::ir::TlsCertConfig {
            id: "shared".into(),
            source: crate::ir::TlsCertSource::Files {
                cert_path: "/gw".into(),
                key_path: "/gw-key".into(),
            },
        });

        let mut high = route_table_for_host("high.test");
        high.tls_certs.push(crate::ir::TlsCertConfig {
            id: "shared".into(),
            source: crate::ir::TlsCertSource::Secret {
                namespace: "ns".into(),
                name: "sec".into(),
            },
        });

        mgr.apply("gateway-api", low).unwrap();
        mgr.apply("toml", high).unwrap();

        let l4 = mgr.l4_config().load();
        assert_eq!(l4.listeners.len(), 0);
        assert_eq!(mgr.l4_config().load().listeners.len(), 0);
        let sources = mgr.sources.lock().unwrap();
        let merged = RouteManager::merge_sources(&sources, &mgr.priorities.lock().unwrap());
        assert!(matches!(
            merged.tls_certs[0].source,
            crate::ir::TlsCertSource::Secret { .. }
        ));
    }

    #[test]
    fn rollback_restores_l4_config() {
        let mgr = RouteManager::new(10);
        let mut first = route_table_for_host("v1.test");
        first.listeners.push(crate::ir::ListenerConfig {
            id: "l4".into(),
            bind_addr: "0.0.0.0:9000".into(),
            protocol: crate::ir::Protocol::Tcp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        });
        mgr.apply("gateway-api", first).unwrap();

        let mut second = route_table_for_host("v2.test");
        second.listeners.push(crate::ir::ListenerConfig {
            id: "l4".into(),
            bind_addr: "0.0.0.0:9001".into(),
            protocol: crate::ir::Protocol::Udp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        });
        mgr.apply("gateway-api", second).unwrap();

        assert_eq!(
            mgr.l4_config().load().listeners[0].protocol,
            crate::ir::Protocol::Udp
        );
        assert!(mgr.rollback(1));
        assert_eq!(
            mgr.l4_config().load().listeners[0].protocol,
            crate::ir::Protocol::Tcp
        );
    }
}
