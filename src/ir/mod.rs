// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Intermediate Representation — the canonical routing model.
//!
//! All config sources (Gateway API, future XDS, nginx, Caddy, etc.) produce
//! a `RouteTable`. The compiler (`src/ir/compile.rs`) transforms it into a
//! `CompiledRouteTable` consumed by the proxy hot path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Canonical route table — produced by any config source, consumed by the Compiler.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RouteTable {
    /// Listeners that this route table serves.
    pub listeners: Vec<ListenerConfig>,
    /// Host-level routes.
    pub hosts: Vec<HostRoute>,
    /// Global ACME challenge routes (path → backend).
    pub acme_routes: HashMap<Arc<str>, Arc<str>>,
    /// L4 routes (TCPRoute / UDPRoute / TLSRoute).
    pub l4_routes: Vec<L4Route>,
    /// TLS certificates referenced by listeners and L4 routes.
    pub tls_certs: Vec<TlsCertConfig>,
}

/// A listener that the proxy binds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Listener identifier.
    pub id: Arc<str>,
    /// Address to bind to (e.g. "0.0.0.0:8080").
    pub bind_addr: Arc<str>,
    /// Transport protocol.
    pub protocol: Protocol,
    /// TLS configuration, if any.
    pub tls: Option<TlsConfig>,
    /// When true, plain-HTTP requests on this listener are redirected to HTTPS.
    pub redirect_http_to_https: bool,
}

/// Transport protocol for a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Plain HTTP.
    Http,
    /// TLS-terminated HTTPS (TLS terminates in the L4 manager, then HTTP to Pingora).
    Https,
    /// Raw TCP.
    Tcp,
    /// Raw UDP.
    Udp,
    /// TLS passthrough (TLSRoute).
    Tls,
}

/// TLS configuration for a listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsConfig {
    /// Reference to a certificate held by the central TLS registry.
    Registry { cert_id: Arc<str> },
    /// Static certificate files (fallback for local development).
    Files {
        /// Path to the TLS certificate file.
        cert_path: Arc<str>,
        /// Path to the TLS private key file.
        key_path: Arc<str>,
    },
}

/// All rules that share a hostname matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRoute {
    /// Hostname matching strategy.
    pub hostname: HostnameMatch,
    /// Which listeners this host route is visible on. Empty = all listeners.
    pub listener_ids: Vec<Arc<str>>,
    /// Listener hostname for isolation (matches request host when set).
    pub listener_hostname: Option<HostnameMatch>,
    /// Listener port for port-aware parentRef matching. `None` matches any port.
    pub listener_port: Option<u16>,
    /// True if this host route came from the Gateway API (strict 404 on no-match).
    /// False for legacy TOML routes (fall through to host-level backend).
    pub gateway_api: bool,
    /// When true, disable the proxy-level HTTP→HTTPS redirect for this host.
    pub disable_secure_redirection: bool,
    /// Ordered rules for this hostname.
    pub rules: Vec<Rule>,
}

/// L4 route (TCPRoute / UDPRoute / TLSRoute).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L4Route {
    /// Listener this route is attached to.
    pub listener_id: Arc<str>,
    /// Listener hostname for SNI-based listener isolation.
    pub listener_hostname: HostnameMatch,
    /// Match condition for this route.
    pub match_: L4Match,
    /// Action to take when the route matches.
    pub action: L4Action,
}

/// L4 match condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L4Match {
    /// Match any connection on the listener.
    Any,
    /// Match by SNI hostname (TLSRoute or HTTPS termination).
    Sni(HostnameMatch),
}

/// L4 action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L4Action {
    /// Relay raw TCP to weighted backends.
    TcpRelay(Vec<WeightedBackend>),
    /// Relay raw UDP to weighted backends.
    UdpRelay(Vec<WeightedBackend>),
    /// Pass through raw TLS to weighted backends.
    TlsPassthrough(Vec<WeightedBackend>),
    /// Terminate TLS and forward plaintext TCP to weighted backends.
    TlsTerminate(Vec<WeightedBackend>),
    /// Terminate TLS and forward plaintext HTTP to the given upstream address.
    TerminateAndHttp(Arc<str>),
}

/// TLS certificate configuration referenced by id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCertConfig {
    /// Certificate identifier referenced by `TlsConfig::Registry`.
    pub id: Arc<str>,
    /// Source of the certificate material.
    pub source: TlsCertSource,
}

/// Source of TLS certificate material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsCertSource {
    /// PEM files on disk.
    Files {
        /// Path to the certificate file.
        cert_path: Arc<str>,
        /// Path to the private key file.
        key_path: Arc<str>,
    },
    /// Kubernetes Secret containing `tls.crt` and `tls.key`.
    Secret {
        /// Namespace of the Secret.
        namespace: Arc<str>,
        /// Name of the Secret.
        name: Arc<str>,
    },
}

/// Hostname matching strategy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum HostnameMatch {
    /// Exact hostname match.
    Exact(Arc<str>),
    /// Prefix match on the first label (e.g. `test` matches `test` and `test.*`).
    Prefix(Arc<str>),
    /// Wildcard suffix match (e.g. *.example.com).
    Wildcard(Arc<str>),
    /// Match any hostname.
    #[default]
    Any,
}

/// A single rule: matches + action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// All request match conditions (ANDed together).
    pub matches: Vec<RequestMatch>,
    /// Action to take when all matches succeed.
    pub action: Action,
    /// Original rule order for precedence tie-breaking (lower = earlier).
    pub rule_order: usize,
}

/// What to do when a rule matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Forward to an upstream backend.
    Route(RouteAction),
    /// Return an HTTP redirect.
    Redirect(RedirectAction),
    /// Serve static files from disk.
    StaticFiles(StaticFileAction),
    /// Return a fixed HTTP response.
    FixedResponse(FixedResponseAction),
}

/// Forward the request to an upstream backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAction {
    /// Upstream backends with traffic-split weights.
    pub backends: Vec<WeightedBackend>,
    /// Request timeout.
    pub timeout: Option<Duration>,
    /// Filters applied to the request before forwarding.
    pub request_filters: Vec<RequestFilter>,
    /// Filters applied to the response before sending downstream.
    pub response_filters: Vec<ResponseFilter>,
    /// Backends to mirror traffic to (fire-and-forget).
    pub mirror_backends: Vec<Arc<str>>,
    /// Optional fraction for each mirror backend (aligned by index).
    pub mirror_fractions: Vec<Option<Fraction>>,
    /// Cache policy, if any.
    pub cache: Option<CachePolicy>,
    /// Body find/replace rules.
    pub body_rewrites: Vec<BodyRewrite>,
    /// Auth subrequest configuration, if any.
    pub auth: Option<AuthConfig>,
    /// When true, forward WebSocket upgrade headers.
    pub websocket: bool,
    /// When true, disable the proxy-level HTTP→HTTPS redirect for this route.
    pub disable_https_redirect: bool,
}

/// A fractional value used for probabilistic request mirroring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fraction {
    pub numerator: u32,
    pub denominator: u32,
}

/// Return a redirect response to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectAction {
    /// HTTP status code for the redirect.
    pub status_code: u16,
    /// Scheme to redirect to (e.g. "https").
    pub scheme: Option<Arc<str>>,
    /// Hostname to redirect to.
    pub hostname: Option<Arc<str>>,
    /// Port to redirect to.
    pub port: Option<u16>,
    /// Path rewrite for the redirect location.
    pub path: Option<PathRewrite>,
}

/// Serve static files from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticFileAction {
    /// Root directory to serve files from.
    pub root: Arc<str>,
    /// Fallback file for SPA routing (e.g. "/index.html").
    pub fallback: Option<Arc<str>>,
    /// URL rewrite rules.
    pub rewrites: Vec<RewriteRule>,
    /// Extra response headers to add.
    pub extra_headers: Vec<(Arc<str>, Arc<str>)>,
}

/// Return a fixed response without forwarding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedResponseAction {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(Arc<str>, Arc<str>)>,
    /// Response body, if any.
    pub body: Option<Arc<str>>,
}

/// Filters applied to the request before forwarding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestFilter {
    /// Set or replace a header.
    SetHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Add a header (do not replace existing).
    AddHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Remove a header.
    RemoveHeader(Arc<str>),
    /// Strip a prefix from the request path.
    StripPrefix(Arc<str>),
    /// Prepend a string to the request path.
    PrependPath(Arc<str>),
    /// Rewrite the request path.
    RewritePath(PathRewrite),
    /// Rewrite the request hostname.
    RewriteHostname(Arc<str>),
}

/// Filters applied to the response before sending downstream.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResponseFilter {
    /// Set or replace a header.
    SetHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Add a header (do not replace existing).
    AddHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Remove a header.
    RemoveHeader(Arc<str>),
    /// Add CORS headers.
    Cors(CorsConfig),
}

/// Match criteria for a single rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct RequestMatch {
    /// Path match condition, if any.
    pub path: Option<PathMatch>,
    /// HTTP method match, if any.
    pub method: Option<Arc<str>>,
    /// Header match conditions.
    pub headers: Vec<HeaderMatch>,
    /// Query parameter match conditions.
    pub query_params: Vec<QueryParamMatch>,
}

/// Path match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathMatch {
    /// Prefix path match.
    Prefix(Arc<str>),
    /// Exact path match.
    Exact(Arc<str>),
    /// Regex path match.
    Regex(Arc<str>),
}

/// Path rewrite action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathRewrite {
    /// Replace the entire path.
    FullReplace(Arc<str>),
    /// Replace a prefix of the path.
    PrefixReplace {
        /// Prefix to match.
        prefix: Arc<str>,
        /// Replacement string.
        replacement: Arc<str>,
    },
}

impl PathRewrite {
    /// If this is a `PrefixReplace` whose prefix is `/`, replace the prefix
    /// with the matched path prefix when one is known. This is required for
    /// Gateway API `ReplacePrefixMatch` semantics.
    pub fn with_matched_prefix(self, matched: Option<&Arc<str>>) -> Self {
        match self {
            PathRewrite::PrefixReplace {
                prefix,
                replacement,
            } if prefix.as_ref() == "/" => PathRewrite::PrefixReplace {
                prefix: matched.cloned().unwrap_or(prefix),
                replacement,
            },
            other => other,
        }
    }
}

/// Header match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeaderMatch {
    /// Header name.
    pub name: Arc<str>,
    /// Header match value condition.
    pub value: HeaderMatchValue,
}

/// Header match value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HeaderMatchValue {
    /// Exact header value match.
    Exact(Arc<str>),
    /// Regex header value match.
    Regex(Arc<str>),
    /// Header must be present (any value).
    Present,
    /// Header must be absent.
    Absent,
}

/// Query parameter match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryParamMatch {
    /// Query parameter name.
    pub name: Arc<str>,
    /// Query parameter match value condition.
    pub value: QueryParamMatchValue,
}

/// Query parameter match value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueryParamMatchValue {
    /// Exact query parameter value match.
    Exact(Arc<str>),
    /// Regex query parameter value match.
    Regex(Arc<str>),
}

/// Backend with a traffic-split weight.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WeightedBackend {
    /// Backend address (e.g. "http://svc:8080").
    pub backend: Arc<str>,
    /// Traffic-split weight.
    pub weight: u32,
    /// Request filters applied only when this backend is selected.
    pub request_filters: Vec<RequestFilter>,
    /// Protocol to use when communicating with the backend.
    pub protocol: BackendProtocol,
}

/// Application protocol to use for a backend connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum BackendProtocol {
    /// Plain HTTP/1.1 (default).
    #[default]
    Http,
    /// HTTP/2 prior knowledge without TLS (H2C).
    H2c,
    /// WebSocket over cleartext.
    WebSocket,
    /// WebSocket over TLS.
    WebSocketSecure,
}

/// CORS response header configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct CorsConfig {
    /// Allowed origins.
    pub allow_origins: Vec<Arc<str>>,
    /// Allowed HTTP methods.
    pub allow_methods: Vec<Arc<str>>,
    /// Allowed request headers.
    pub allow_headers: Vec<Arc<str>>,
    /// Response headers to expose.
    pub expose_headers: Vec<Arc<str>>,
    /// Max age for preflight cache.
    pub max_age: Option<i32>,
    /// Whether credentials are allowed.
    pub allow_credentials: bool,
}

/// Cache policy for a route.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CachePolicy {
    /// Whether caching is enabled.
    pub enabled: bool,
    /// Default TTL in seconds.
    pub default_ttl_secs: u64,
    /// Stale-while-revalidate duration in seconds.
    pub stale_while_revalidate_secs: u32,
    /// Maximum response body size to cache.
    pub max_file_size: usize,
}

/// Body find/replace rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BodyRewrite {
    /// String to find in the response body.
    pub find: Arc<str>,
    /// Replacement string.
    pub replace: Arc<str>,
    /// Content types to apply this rewrite to.
    pub types: Vec<Arc<str>>,
}

/// Auth subrequest configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthConfig {
    /// URL of the auth subrequest endpoint.
    pub url: Arc<str>,
    /// Headers from the auth response to capture and forward.
    pub capture_headers: Vec<Arc<str>>,
}

/// URL rewrite rule for static files.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RewriteRule {
    /// Regex pattern to match.
    pub pattern: Arc<str>,
    /// Replacement target.
    pub target: Arc<str>,
}

pub mod compile;
pub mod from_config;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_one<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    // ── RouteTable ──────────────────────────────────────────────────────

    #[test]
    fn route_table_default_is_empty() {
        let rt = RouteTable::default();
        assert!(rt.listeners.is_empty());
        assert!(rt.hosts.is_empty());
        assert!(rt.acme_routes.is_empty());
        assert!(rt.l4_routes.is_empty());
        assert!(rt.tls_certs.is_empty());
    }

    #[test]
    fn route_table_clone_and_eq() {
        let mut rt = RouteTable::default();
        rt.listeners.push(ListenerConfig {
            id: "l1".into(),
            bind_addr: "0.0.0.0:8080".into(),
            protocol: Protocol::Http,
            tls: None,
            redirect_http_to_https: false,
        });
        rt.acme_routes.insert("/challenge".into(), "backend".into());
        rt.l4_routes.push(L4Route {
            listener_id: "l1".into(),
            listener_hostname: HostnameMatch::Any,
            match_: L4Match::Any,
            action: L4Action::TcpRelay(vec![]),
        });
        let cloned = rt.clone();
        assert_eq!(rt, cloned);
    }

    // ── ListenerConfig ──────────────────────────────────────────────────

    #[test]
    fn listener_config_roundtrip() {
        let lc = ListenerConfig {
            id: "l1".into(),
            bind_addr: "0.0.0.0:443".into(),
            protocol: Protocol::Https,
            tls: Some(TlsConfig::Files {
                cert_path: "/etc/cert.pem".into(),
                key_path: "/etc/key.pem".into(),
            }),
            redirect_http_to_https: true,
        };
        let cloned = lc.clone();
        assert_eq!(lc, cloned);
    }

    // ── Protocol ────────────────────────────────────────────────────────

    #[test]
    fn protocol_variants() {
        assert_ne!(Protocol::Http, Protocol::Https);
        assert_ne!(Protocol::Tcp, Protocol::Udp);
        assert_ne!(Protocol::Udp, Protocol::Tls);
        assert_eq!(Protocol::Http, Protocol::Http);
        assert_eq!(hash_one(&Protocol::Http), hash_one(&Protocol::Http));
    }

    // ── TlsConfig ───────────────────────────────────────────────────────

    #[test]
    fn tls_config_eq() {
        let a = TlsConfig::Files {
            cert_path: "/a".into(),
            key_path: "/b".into(),
        };
        let b = TlsConfig::Files {
            cert_path: "/a".into(),
            key_path: "/b".into(),
        };
        assert_eq!(a, b);

        let registry = TlsConfig::Registry {
            cert_id: "default".into(),
        };
        assert_ne!(a, registry);
    }

    // ── L4Route / L4Match / L4Action ────────────────────────────────────

    #[test]
    fn l4_route_construction() {
        let route = L4Route {
            listener_id: "l1".into(),
            listener_hostname: HostnameMatch::Exact("tcp.example.com".into()),
            match_: L4Match::Sni(HostnameMatch::Exact("tcp.example.com".into())),
            action: L4Action::TcpRelay(vec![WeightedBackend {
                backend: "tcp://svc:8080".into(),
                weight: 1,
                protocol: BackendProtocol::Http,
                request_filters: vec![],
            }]),
        };
        assert_eq!(route.listener_id.as_ref(), "l1");
    }

    #[test]
    fn l4_match_any_eq() {
        assert_eq!(L4Match::Any, L4Match::Any);
        assert_ne!(L4Match::Any, L4Match::Sni(HostnameMatch::Exact("x".into())));
    }

    #[test]
    fn l4_action_variants() {
        let tcp = L4Action::TcpRelay(vec![]);
        let udp = L4Action::UdpRelay(vec![]);
        let tls = L4Action::TlsPassthrough(vec![]);
        let term = L4Action::TlsTerminate(vec![]);
        let http = L4Action::TerminateAndHttp("127.0.0.1:10443".into());
        assert_ne!(tcp, udp);
        assert_ne!(udp, tls);
        assert_ne!(tls, term);
        assert_ne!(term, http);
    }

    // ── TlsCertConfig ───────────────────────────────────────────────────

    #[test]
    fn tls_cert_config_eq() {
        let a = TlsCertConfig {
            id: "default".into(),
            source: TlsCertSource::Files {
                cert_path: "/a".into(),
                key_path: "/b".into(),
            },
        };
        let b = TlsCertConfig {
            id: "default".into(),
            source: TlsCertSource::Files {
                cert_path: "/a".into(),
                key_path: "/b".into(),
            },
        };
        assert_eq!(a, b);

        let secret = TlsCertConfig {
            id: "default".into(),
            source: TlsCertSource::Secret {
                namespace: "ns".into(),
                name: "sec".into(),
            },
        };
        assert_ne!(a, secret);
    }

    // ── HostRoute ───────────────────────────────────────────────────────

    #[test]
    fn host_route_construction() {
        let hr = HostRoute {
            hostname: HostnameMatch::Exact("example.com".into()),
            listener_ids: vec!["l1".into()],
            listener_hostname: None,
            listener_port: Some(80),
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![],
        };
        assert_eq!(hr.hostname, HostnameMatch::Exact("example.com".into()));
        assert_eq!(hr.listener_port, Some(80));
    }

    // ── HostnameMatch ───────────────────────────────────────────────────

    #[test]
    fn hostname_match_variants() {
        let exact = HostnameMatch::Exact("foo".into());
        let wild = HostnameMatch::Wildcard("example.com".into());
        let any = HostnameMatch::Any;

        assert_eq!(exact, HostnameMatch::Exact("foo".into()));
        assert_ne!(exact, wild);
        assert_ne!(wild, any);

        // Hash consistency
        assert_eq!(
            hash_one(&exact),
            hash_one(&HostnameMatch::Exact("foo".into()))
        );
    }

    // ── Rule ────────────────────────────────────────────────────────────

    #[test]
    fn rule_construction() {
        let rule = Rule {
            matches: vec![RequestMatch::default()],
            action: Action::FixedResponse(FixedResponseAction {
                status: 200,
                headers: vec![("X-Foo".into(), "bar".into())],
                body: Some("ok".into()),
            }),
            rule_order: 3,
        };
        assert_eq!(rule.rule_order, 3);
        assert_eq!(rule.matches.len(), 1);
    }

    // ── Action ──────────────────────────────────────────────────────────

    #[test]
    fn action_variants_eq() {
        let route = Action::Route(RouteAction {
            backends: vec![WeightedBackend {
                backend: "http://svc".into(),
                weight: 1,
                protocol: BackendProtocol::Http,
                request_filters: vec![],
            }],
            timeout: None,
            request_filters: vec![],
            response_filters: vec![],
            mirror_backends: vec![],
            mirror_fractions: vec![],
            cache: None,
            body_rewrites: vec![],
            auth: None,
            disable_https_redirect: false,
            websocket: false,
        });
        let redirect = Action::Redirect(RedirectAction {
            status_code: 302,
            scheme: Some("https".into()),
            hostname: None,
            port: None,
            path: None,
        });
        let static_files = Action::StaticFiles(StaticFileAction {
            root: "/var/www".into(),
            fallback: Some("/index.html".into()),
            rewrites: vec![],
            extra_headers: vec![],
        });
        let fixed = Action::FixedResponse(FixedResponseAction {
            status: 404,
            headers: vec![],
            body: None,
        });

        assert_ne!(route, redirect);
        assert_ne!(static_files, fixed);

        // Clone round-trip
        assert_eq!(route.clone(), route);
        assert_eq!(redirect.clone(), redirect);
        assert_eq!(static_files.clone(), static_files);
        assert_eq!(fixed.clone(), fixed);
    }

    // ── RouteAction ─────────────────────────────────────────────────────

    #[test]
    fn route_action_all_fields() {
        let ra = RouteAction {
            backends: vec![
                WeightedBackend {
                    backend: "a".into(),
                    weight: 3,
                    protocol: BackendProtocol::Http,
                    request_filters: vec![],
                },
                WeightedBackend {
                    backend: "b".into(),
                    weight: 7,
                    protocol: BackendProtocol::Http,
                    request_filters: vec![],
                },
            ],
            timeout: Some(Duration::from_secs(30)),
            request_filters: vec![
                RequestFilter::SetHeader {
                    name: "X-Id".into(),
                    value: "1".into(),
                },
                RequestFilter::StripPrefix("/api".into()),
            ],
            response_filters: vec![
                ResponseFilter::AddHeader {
                    name: "X-Out".into(),
                    value: "ok".into(),
                },
                ResponseFilter::Cors(CorsConfig::default()),
            ],
            mirror_backends: vec!["http://mirror".into()],
            mirror_fractions: vec![None],
            cache: Some(CachePolicy {
                enabled: true,
                default_ttl_secs: 60,
                stale_while_revalidate_secs: 300,
                max_file_size: 1024 * 1024,
            }),
            body_rewrites: vec![BodyRewrite {
                find: "old".into(),
                replace: "new".into(),
                types: vec!["text/html".into()],
            }],
            auth: Some(AuthConfig {
                url: "http://auth".into(),
                capture_headers: vec!["X-User".into()],
            }),
            websocket: true,
            disable_https_redirect: false,
        };
        let cloned = ra.clone();
        assert_eq!(ra, cloned);
    }

    // ── RedirectAction ──────────────────────────────────────────────────

    #[test]
    fn redirect_action_with_path_rewrite() {
        let ra = RedirectAction {
            status_code: 301,
            scheme: Some("https".into()),
            hostname: Some("new.com".into()),
            port: Some(8443),
            path: Some(PathRewrite::PrefixReplace {
                prefix: "/old".into(),
                replacement: "/new".into(),
            }),
        };
        assert_eq!(ra.status_code, 301);
        assert!(ra.path.is_some());
    }

    // ── StaticFileAction ────────────────────────────────────────────────

    #[test]
    fn static_file_action_roundtrip() {
        let sfa = StaticFileAction {
            root: "/www".into(),
            fallback: Some("/index.html".into()),
            rewrites: vec![RewriteRule {
                pattern: "^/a$".into(),
                target: "/b".into(),
            }],
            extra_headers: vec![("Cache-Control".into(), "max-age=3600".into())],
        };
        assert_eq!(sfa.clone(), sfa);
    }

    // ── FixedResponseAction ─────────────────────────────────────────────

    #[test]
    fn fixed_response_action_eq() {
        let a = FixedResponseAction {
            status: 418,
            headers: vec![("X-Tea".into(), "earl-grey".into())],
            body: Some("I'm a teapot".into()),
        };
        let b = FixedResponseAction {
            status: 418,
            headers: vec![("X-Tea".into(), "earl-grey".into())],
            body: Some("I'm a teapot".into()),
        };
        assert_eq!(a, b);
    }

    // ── RequestFilter ───────────────────────────────────────────────────

    #[test]
    fn request_filter_hash_and_eq() {
        let a = RequestFilter::SetHeader {
            name: "X".into(),
            value: "1".into(),
        };
        let b = RequestFilter::SetHeader {
            name: "X".into(),
            value: "1".into(),
        };
        assert_eq!(a, b);
        assert_eq!(hash_one(&a), hash_one(&b));

        let c = RequestFilter::RemoveHeader("Y".into());
        let d = RequestFilter::RemoveHeader("Y".into());
        assert_eq!(c, d);

        assert_ne!(a, c);
    }

    // ── ResponseFilter ──────────────────────────────────────────────────

    #[test]
    fn response_filter_variants() {
        let cors = ResponseFilter::Cors(CorsConfig {
            allow_origins: vec!["*".into()],
            allow_methods: vec!["GET".into()],
            allow_headers: vec![],
            expose_headers: vec![],
            max_age: Some(86400),
            allow_credentials: false,
        });
        let add = ResponseFilter::AddHeader {
            name: "X".into(),
            value: "v".into(),
        };
        assert_ne!(cors, add);
        assert_eq!(cors.clone(), cors);
    }

    // ── RequestMatch ────────────────────────────────────────────────────

    #[test]
    fn request_match_default() {
        let m = RequestMatch::default();
        assert!(m.path.is_none());
        assert!(m.method.is_none());
        assert!(m.headers.is_empty());
        assert!(m.query_params.is_empty());
    }

    #[test]
    fn request_match_all_fields() {
        let m = RequestMatch {
            path: Some(PathMatch::Prefix("/api".into())),
            method: Some("GET".into()),
            headers: vec![HeaderMatch {
                name: "Accept".into(),
                value: HeaderMatchValue::Exact("application/json".into()),
            }],
            query_params: vec![QueryParamMatch {
                name: "v".into(),
                value: QueryParamMatchValue::Exact("1".into()),
            }],
        };
        let cloned = m.clone();
        assert_eq!(m, cloned);
        assert_eq!(hash_one(&m), hash_one(&cloned));
    }

    // ── PathMatch ───────────────────────────────────────────────────────

    #[test]
    fn path_match_variants() {
        let p = PathMatch::Prefix("/v1".into());
        let e = PathMatch::Exact("/health".into());
        let r = PathMatch::Regex("^/api/.*".into());
        assert_ne!(p, e);
        assert_ne!(e, r);
        assert_eq!(p.clone(), p);
    }

    // ── PathRewrite ─────────────────────────────────────────────────────

    #[test]
    fn path_rewrite_eq() {
        let a = PathRewrite::FullReplace("/new".into());
        let b = PathRewrite::PrefixReplace {
            prefix: "/old".into(),
            replacement: "/new".into(),
        };
        assert_ne!(a, b);
        assert_eq!(a.clone(), a);
    }

    // ── HeaderMatch / HeaderMatchValue ──────────────────────────────────

    #[test]
    fn header_match_value_variants() {
        let exact = HeaderMatchValue::Exact("foo".into());
        let _regex = HeaderMatchValue::Regex("^bar$".into());
        let present = HeaderMatchValue::Present;
        let absent = HeaderMatchValue::Absent;

        assert_ne!(exact, present);
        assert_ne!(present, absent);
        assert_eq!(exact.clone(), exact);

        let hm = HeaderMatch {
            name: "X-Api-Key".into(),
            value: HeaderMatchValue::Present,
        };
        assert_eq!(hm.clone(), hm);
        assert_eq!(hash_one(&hm), hash_one(&hm));
    }

    // ── QueryParamMatch / QueryParamMatchValue ──────────────────────────

    #[test]
    fn query_param_match_value_eq() {
        let a = QueryParamMatchValue::Exact("foo".into());
        let b = QueryParamMatchValue::Regex("^bar$".into());
        assert_ne!(a, b);

        let qm = QueryParamMatch {
            name: "page".into(),
            value: QueryParamMatchValue::Exact("1".into()),
        };
        assert_eq!(qm.clone(), qm);
    }

    // ── WeightedBackend ─────────────────────────────────────────────────

    #[test]
    fn weighted_backend_eq_and_hash() {
        let a = WeightedBackend {
            backend: "http://a".into(),
            weight: 5,
            protocol: BackendProtocol::Http,
            request_filters: vec![],
        };
        let b = WeightedBackend {
            backend: "http://a".into(),
            weight: 5,
            protocol: BackendProtocol::Http,
            request_filters: vec![],
        };
        assert_eq!(a, b);
        assert_eq!(hash_one(&a), hash_one(&b));
    }

    // ── CorsConfig ──────────────────────────────────────────────────────

    #[test]
    fn cors_config_default() {
        let c = CorsConfig::default();
        assert!(c.allow_origins.is_empty());
        assert!(c.allow_methods.is_empty());
        assert!(!c.allow_credentials);
        assert!(c.max_age.is_none());
    }

    #[test]
    fn cors_config_all_fields() {
        let c = CorsConfig {
            allow_origins: vec!["https://app.com".into()],
            allow_methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["Content-Type".into()],
            expose_headers: vec!["X-Total".into()],
            max_age: Some(3600),
            allow_credentials: true,
        };
        assert_eq!(c.clone(), c);
        assert_eq!(hash_one(&c), hash_one(&c));
    }

    // ── CachePolicy ─────────────────────────────────────────────────────

    #[test]
    fn cache_policy_eq() {
        let a = CachePolicy {
            enabled: true,
            default_ttl_secs: 60,
            stale_while_revalidate_secs: 300,
            max_file_size: 1024,
        };
        let b = CachePolicy {
            enabled: true,
            default_ttl_secs: 60,
            stale_while_revalidate_secs: 300,
            max_file_size: 1024,
        };
        assert_eq!(a, b);
    }

    // ── BodyRewrite ─────────────────────────────────────────────────────

    #[test]
    fn body_rewrite_eq() {
        let a = BodyRewrite {
            find: "old".into(),
            replace: "new".into(),
            types: vec!["text/html".into()],
        };
        let b = BodyRewrite {
            find: "old".into(),
            replace: "new".into(),
            types: vec!["text/html".into()],
        };
        assert_eq!(a, b);
        assert_eq!(hash_one(&a), hash_one(&b));
    }

    // ── AuthConfig ──────────────────────────────────────────────────────

    #[test]
    fn auth_config_eq() {
        let a = AuthConfig {
            url: "http://auth".into(),
            capture_headers: vec!["X-User".into()],
        };
        let b = AuthConfig {
            url: "http://auth".into(),
            capture_headers: vec!["X-User".into()],
        };
        assert_eq!(a, b);
    }

    // ── RewriteRule ─────────────────────────────────────────────────────

    #[test]
    fn rewrite_rule_eq() {
        let a = RewriteRule {
            pattern: "^/a$".into(),
            target: "/b".into(),
        };
        let b = RewriteRule {
            pattern: "^/a$".into(),
            target: "/b".into(),
        };
        assert_eq!(a, b);
    }
}
