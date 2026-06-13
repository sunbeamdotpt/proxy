// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compiler — transforms `RouteTable` into `CompiledRouteTable`.
//!
//! The compiled form is a static decision tree optimized for the proxy hot path:
//! - hostname exact-match HashMap for O(1) lookup
//! - path segment trie per host for O(depth) walk
//! - adaptive discriminator at trie nodes with >DISCRIMINATOR_THRESHOLD plans
//! - phase-separated `CompiledPlan` so each Pingora phase touches only its data
//! - precedence computed once at build time

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Threshold above which a trie node gets an adaptive discriminator.
const DISCRIMINATOR_THRESHOLD: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Public API — CompiledRouteTable
// ─────────────────────────────────────────────────────────────────────────────

/// Optimized route table ready for the proxy hot path.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CompiledRouteTable {
    /// Exact route hostname → list of host nodes (different listener hostnames).
    pub exact_hosts: HashMap<Arc<str>, Vec<HostNode>>,
    /// Wildcard/prefix route hostnames — sorted by specificity descending.
    pub wildcard_hosts: Vec<(HostnameMatch, HostNode)>,
    /// Catch-all host.
    pub any_host: Option<HostNode>,
    /// ACME challenge routes.
    pub acme_routes: HashMap<Arc<str>, Arc<str>>,
}

/// A compiled host route — contains the path trie for this hostname.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNode {
    /// Route hostname matcher for this host route.
    pub hostname: HostnameMatch,
    /// Listener identifiers this host route is attached to.
    pub listener_ids: Vec<Arc<str>>,
    /// Optional listener hostname used for listener isolation.
    pub listener_hostname: Option<HostnameMatch>,
    /// True if this host route was created from a Gateway API HTTPRoute.
    pub gateway_api: bool,
    /// When true, disable the proxy-level HTTP→HTTPS redirect for this host.
    pub disable_secure_redirection: bool,
    /// Path segment trie for prefix and no-path matches.
    pub path_trie: PathTrieNode,
    /// Exact path matches keyed by the full path string (including trailing slash).
    pub exact_paths: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>>,
    /// Fallback for path regex matches that can't live in the trie.
    pub regex_plans: Vec<Arc<CompiledPlan>>,
    /// Raw static-file rewrite rules for this host, collected at compile time.
    pub static_rewrites: Vec<RewriteRule>,
}

/// A single compiled execution plan for a matched rule.
///
/// The compiler flattens all mutations into phase-specific ordered lists so the
/// proxy is a dumb executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPlan {
    /// Precedence score (higher = more specific).
    pub precedence: u64,
    /// Original rule order for tie-breaking.
    pub rule_order: usize,
    /// Gateway API flag (affects 404 fallback).
    pub gateway_api: bool,
    /// When true, disable HTTP→HTTPS redirect for this route.
    pub disable_secure_redirection: bool,
    /// Listener hostname that this route is attached to.
    pub listener_hostname: Option<HostnameMatch>,
    /// Remaining match conditions for final verification.
    pub matches: RequestMatch,

    // Phase-separated execution data
    /// Stages executed in `request_filter`. First terminal wins.
    pub request_stages: Vec<RequestStage>,
    /// Upstream selection (or terminal) executed in `upstream_peer`.
    pub upstream: Option<UpstreamAction>,
    /// Ordered mutations applied in `upstream_request_filter`.
    pub upstream_request_mutations: Vec<UpstreamRequestMutation>,
    /// Ordered mutations applied in `upstream_response_filter`.
    pub response_mutations: Vec<ResponseMutation>,
    /// Body rewrite rules for `response_body_filter`.
    pub body_rewrites: Vec<BodyRewrite>,
    /// Cache policy for cache hooks.
    pub cache: Option<CachePolicy>,
    /// WebSocket forwarding flag.
    pub websocket: bool,
}

/// Terminal actions that short-circuit before upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalAction {
    /// HTTP redirect response.
    Redirect(RedirectAction),
    /// Fixed HTTP response generated directly by the proxy.
    FixedResponse {
        /// HTTP status code.
        status: u16,
        /// Response headers as (name, value) pairs.
        headers: Vec<(Arc<str>, Arc<str>)>,
        /// Optional response body.
        body: Option<Arc<str>>,
    },
    /// 404 Not Found response.
    NotFound,
}

/// Upstream selection executed in `upstream_peer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAction {
    /// Weighted upstream backends.
    pub backends: Vec<WeightedBackend>,
    /// Request timeout, if any.
    pub timeout: Option<Duration>,
    /// Backends to mirror traffic to (fire-and-forget).
    pub mirror: Vec<Arc<str>>,
    /// Per-backend request mutations, aligned with `backends`.
    pub backend_request_mutations: Vec<Vec<UpstreamRequestMutation>>,
}

/// Stages executed in `request_filter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestStage {
    /// Auth subrequest gate.
    Auth(AuthConfig),
    /// CORS preflight response.
    CorsPreflight(CorsConfig),
    /// Static file serving.
    StaticFiles(StaticFileAction),
    /// Terminal action (redirect, fixed response, 404).
    Terminal(TerminalAction),
}

/// Mutations applied in `upstream_request_filter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamRequestMutation {
    /// Set or replace a header.
    SetHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Add a header without replacing existing values.
    AddHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Remove a header by name.
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

/// Mutations applied in `upstream_response_filter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseMutation {
    /// Set or replace a header.
    SetHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Add a header without replacing existing values.
    AddHeader {
        /// Header name.
        name: Arc<str>,
        /// Header value.
        value: Arc<str>,
    },
    /// Remove a header by name.
    RemoveHeader(Arc<str>),
    /// Add CORS response headers.
    Cors(CorsConfig),
}

/// Compilation error.
#[derive(Debug, Clone)]
pub struct CompileError {
    /// Human-readable error message.
    pub message: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "compile error: {}", self.message)
    }
}

impl std::error::Error for CompileError {}

/// Convert a route-level or backend-level request filter into an upstream
/// request mutation.
fn compile_request_filter(filter: &crate::ir::RequestFilter) -> UpstreamRequestMutation {
    match filter {
        crate::ir::RequestFilter::SetHeader { name, value } => UpstreamRequestMutation::SetHeader {
            name: Arc::clone(name),
            value: Arc::clone(value),
        },
        crate::ir::RequestFilter::AddHeader { name, value } => UpstreamRequestMutation::AddHeader {
            name: Arc::clone(name),
            value: Arc::clone(value),
        },
        crate::ir::RequestFilter::RemoveHeader(name) => {
            UpstreamRequestMutation::RemoveHeader(Arc::clone(name))
        }
        crate::ir::RequestFilter::StripPrefix(p) => {
            UpstreamRequestMutation::StripPrefix(Arc::clone(p))
        }
        crate::ir::RequestFilter::PrependPath(p) => {
            UpstreamRequestMutation::PrependPath(Arc::clone(p))
        }
        crate::ir::RequestFilter::RewritePath(pr) => {
            UpstreamRequestMutation::RewritePath(pr.clone())
        }
        crate::ir::RequestFilter::RewriteHostname(h) => {
            UpstreamRequestMutation::RewriteHostname(Arc::clone(h))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trie nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Path segment trie node.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PathTrieNode {
    /// Exact segment children (e.g. "api" → node).
    pub exact_children: HashMap<Arc<str>, PathTrieNode>,
    /// Plans whose path match is a prefix ending at this node.
    pub prefix_plans: Vec<Arc<CompiledPlan>>,
    /// Plans whose path match is exact at this node.
    pub exact_plans: Vec<Arc<CompiledPlan>>,
    /// Adaptive discriminator if plan count exceeds threshold.
    pub discriminator: Option<Discriminator>,
}

/// Adaptive discriminator — splits a plan set by the most discriminating attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discriminator {
    /// Discriminator kind and bucketed plans.
    pub kind: DiscriminatorKind,
    /// Plans that don't fit any discriminating bucket (regex matches, absent checks, etc.).
    pub fallback: Vec<Arc<CompiledPlan>>,
}

/// Kind of adaptive discriminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscriminatorKind {
    /// Split by HTTP method.
    ByMethod {
        /// Plans bucketed by exact method name.
        exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>>,
        /// Plans that match any method.
        any: Vec<Arc<CompiledPlan>>,
    },
    /// Split by an exact header value.
    ByHeader {
        /// Header name to discriminate on.
        name: Arc<str>,
        /// Plans bucketed by exact header value.
        exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>>,
        /// Plans that do not constrain this header.
        any: Vec<Arc<CompiledPlan>>,
    },
    /// Split by an exact query parameter value.
    ByQuery {
        /// Query parameter name to discriminate on.
        name: Arc<str>,
        /// Plans bucketed by exact query value.
        exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>>,
        /// Plans that do not constrain this query parameter.
        any: Vec<Arc<CompiledPlan>>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Compilation
// ─────────────────────────────────────────────────────────────────────────────

impl CompiledRouteTable {
    /// Compile an IR `RouteTable` into an optimized `CompiledRouteTable`.
    pub fn compile(ir: RouteTable) -> Result<Self, CompileError> {
        let mut exact_hosts: HashMap<Arc<str>, Vec<HostNode>> = HashMap::new();
        let mut wildcard_hosts: Vec<(HostnameMatch, HostNode)> = Vec::new();
        let mut any_host: Option<HostNode> = None;

        for host in ir.hosts {
            let node = compile_host(&host)?;
            match &host.hostname {
                HostnameMatch::Exact(s) => {
                    exact_hosts.entry(Arc::clone(s)).or_default().push(node);
                }
                HostnameMatch::Prefix(_) | HostnameMatch::Wildcard(_) => {
                    wildcard_hosts.push((host.hostname.clone(), node));
                }
                HostnameMatch::Any => {
                    any_host = Some(node);
                }
            }
        }

        // Sort wildcards by specificity descending so the first match is the most specific.
        wildcard_hosts.sort_by(|a, b| {
            specificity_score(&b.0)
                .cmp(&specificity_score(&a.0))
                .then_with(|| a.1.rules_count().cmp(&b.1.rules_count()))
        });

        Ok(CompiledRouteTable {
            exact_hosts,
            wildcard_hosts,
            any_host,
            acme_routes: ir.acme_routes,
        })
    }

    /// Empty compiled table — returns 404 for everything.
    pub fn empty() -> Self {
        Self::default()
    }
}

// Helper: count rules in a HostNode for tie-breaking.
impl HostNode {
    fn rules_count(&self) -> usize {
        self.path_trie.total_plan_count() + self.regex_plans.len()
    }
}

impl PathTrieNode {
    fn total_plan_count(&self) -> usize {
        let child_count: usize = self
            .exact_children
            .values()
            .map(|c| c.total_plan_count())
            .sum();
        self.prefix_plans.len() + self.exact_plans.len() + child_count
    }
}

fn specificity_score(hm: &HostnameMatch) -> i32 {
    match hm {
        HostnameMatch::Exact(_) => 1000,
        HostnameMatch::Prefix(_) => 500,
        HostnameMatch::Wildcard(s) => 100 + s.chars().filter(|&c| c == '.').count() as i32,
        HostnameMatch::Any => 0,
    }
}

fn compile_host(host: &HostRoute) -> Result<HostNode, CompileError> {
    // Flatten each Rule into one CompiledPlan per RequestMatch.
    let mut all_plans: Vec<Arc<CompiledPlan>> = Vec::new();

    for rule in &host.rules {
        let precedence = compute_precedence(rule);
        for m in &rule.matches {
            let plan = compile_plan(
                rule,
                precedence,
                m,
                host.gateway_api,
                host.disable_secure_redirection,
                host.listener_hostname.clone(),
            )?;
            all_plans.push(Arc::new(plan));
        }
    }

    // Split into trie-friendly prefixes, exact path lookups, and regex fallback.
    let mut trie_plans: Vec<Arc<CompiledPlan>> = Vec::new();
    let mut exact_paths: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>> = HashMap::new();
    let mut regex_plans: Vec<Arc<CompiledPlan>> = Vec::new();

    for plan in all_plans {
        match &plan.matches.path {
            Some(PathMatch::Regex(_)) => regex_plans.push(plan),
            Some(PathMatch::Exact(path)) => {
                exact_paths.entry(Arc::clone(path)).or_default().push(plan);
            }
            _ => trie_plans.push(plan),
        }
    }

    // Sort exact-path buckets by precedence/rule order.
    for bucket in exact_paths.values_mut() {
        sort_plans(bucket);
    }

    // Build path trie for prefix matches and no-path matches.
    let mut path_trie = PathTrieNode::default();
    for plan in trie_plans {
        insert_plan_into_trie(&mut path_trie, &plan)?;
    }

    // Build discriminators at nodes with many plans.
    build_discriminators(&mut path_trie);

    // Sort regex plans by precedence.
    regex_plans.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.rule_order.cmp(&b.rule_order))
    });

    // Collect static-file rewrite rules for this host.
    let mut static_rewrites = Vec::new();
    for rule in &host.rules {
        if let Action::StaticFiles(sfa) = &rule.action {
            static_rewrites.extend(sfa.rewrites.iter().cloned());
        }
    }

    Ok(HostNode {
        hostname: host.hostname.clone(),
        listener_ids: host.listener_ids.clone(),
        listener_hostname: host.listener_hostname.clone(),
        gateway_api: host.gateway_api,
        disable_secure_redirection: host.disable_secure_redirection,
        path_trie,
        exact_paths,
        regex_plans,
        static_rewrites,
    })
}

fn compute_precedence(rule: &Rule) -> u64 {
    // Gateway API precedence for HTTPRoute matches (most-significant first):
    // path length > method match > header count > query param count.
    // Rule order is used as a tie-breaker via CompiledPlan::rule_order.
    let path_len = rule
        .matches
        .iter()
        .filter_map(|m| m.path.as_ref())
        .map(|p| match p {
            PathMatch::Prefix(s) | PathMatch::Exact(s) | PathMatch::Regex(s) => s.len(),
        })
        .max()
        .unwrap_or(0);
    let method_specificity: usize = rule
        .matches
        .iter()
        .map(|m| if m.method.is_some() { 1 } else { 0 })
        .max()
        .unwrap_or(0);
    let header_count: usize = rule
        .matches
        .iter()
        .map(|m| m.headers.len())
        .max()
        .unwrap_or(0);
    let query_count: usize = rule
        .matches
        .iter()
        .map(|m| m.query_params.len())
        .max()
        .unwrap_or(0);

    ((path_len as u64) << 48)
        | ((method_specificity as u64) << 32)
        | ((header_count as u64) << 16)
        | (query_count as u64)
}

fn compile_plan(
    rule: &Rule,
    precedence: u64,
    m: &RequestMatch,
    gateway_api: bool,
    disable_secure_redirection: bool,
    listener_hostname: Option<HostnameMatch>,
) -> Result<CompiledPlan, CompileError> {
    let mut request_stages = Vec::new();
    let mut upstream_request_mutations = Vec::new();
    let mut response_mutations = Vec::new();
    let mut body_rewrites = Vec::new();
    let mut upstream: Option<UpstreamAction> = None;
    let mut cache: Option<CachePolicy> = None;
    let mut websocket = false;

    match &rule.action {
        Action::Route(ra) => {
            // Flatten request filters into upstream request mutations.
            for f in &ra.request_filters {
                upstream_request_mutations.push(compile_request_filter(f));
            }

            // Flatten response filters into response mutations.
            for f in &ra.response_filters {
                match f {
                    ResponseFilter::SetHeader { name, value } => {
                        response_mutations.push(ResponseMutation::SetHeader {
                            name: Arc::clone(name),
                            value: Arc::clone(value),
                        });
                    }
                    ResponseFilter::AddHeader { name, value } => {
                        response_mutations.push(ResponseMutation::AddHeader {
                            name: Arc::clone(name),
                            value: Arc::clone(value),
                        });
                    }
                    ResponseFilter::RemoveHeader(name) => {
                        response_mutations.push(ResponseMutation::RemoveHeader(Arc::clone(name)));
                    }
                    ResponseFilter::Cors(c) => {
                        response_mutations.push(ResponseMutation::Cors(c.clone()));
                    }
                }
            }

            body_rewrites = ra.body_rewrites.clone();
            cache = ra.cache.clone();
            websocket = ra.websocket;

            // Auth stage goes in request_stages.
            if let Some(auth) = &ra.auth {
                request_stages.push(RequestStage::Auth(auth.clone()));
            }

            let backend_request_mutations = ra
                .backends
                .iter()
                .map(|b| {
                    b.request_filters
                        .iter()
                        .map(compile_request_filter)
                        .collect()
                })
                .collect();

            upstream = Some(UpstreamAction {
                backends: ra.backends.clone(),
                timeout: ra.timeout,
                mirror: ra.mirror_backends.clone(),
                backend_request_mutations,
            });
        }
        Action::Redirect(redirect) => {
            request_stages.push(RequestStage::Terminal(TerminalAction::Redirect(
                redirect.clone(),
            )));
        }
        Action::StaticFiles(sfa) => {
            request_stages.push(RequestStage::StaticFiles(sfa.clone()));
        }
        Action::FixedResponse(fixed) => {
            request_stages.push(RequestStage::Terminal(TerminalAction::FixedResponse {
                status: fixed.status,
                headers: fixed.headers.clone(),
                body: fixed.body.clone(),
            }));
        }
    }

    // Sort mutations: the compiler preserves the order from the IR, which is
    // the order the user specified.

    Ok(CompiledPlan {
        precedence,
        rule_order: rule.rule_order,
        gateway_api,
        disable_secure_redirection,
        listener_hostname,
        matches: m.clone(),
        request_stages,
        upstream,
        upstream_request_mutations,
        response_mutations,
        body_rewrites,
        cache,
        websocket,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Trie insertion
// ─────────────────────────────────────────────────────────────────────────────

fn insert_plan_into_trie(
    trie: &mut PathTrieNode,
    plan: &Arc<CompiledPlan>,
) -> Result<(), CompileError> {
    match &plan.matches.path {
        Some(PathMatch::Prefix(prefix)) => {
            let segments = split_path(prefix.as_ref());
            let node = walk_or_create(trie, &segments);
            node.prefix_plans.push(Arc::clone(plan));
        }
        Some(PathMatch::Exact(exact)) => {
            let segments = split_path(exact.as_ref());
            let node = walk_or_create(trie, &segments);
            node.exact_plans.push(Arc::clone(plan));
        }
        Some(PathMatch::Regex(_)) => {
            // Should have been filtered out before calling this.
        }
        None => {
            // No path constraint — matches any path. Store at root as prefix "/".
            trie.prefix_plans.push(Arc::clone(plan));
        }
    }
    Ok(())
}

fn split_path(path: &str) -> Vec<Arc<str>> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(Arc::from)
        .collect()
}

fn walk_or_create<'a>(trie: &'a mut PathTrieNode, segments: &[Arc<str>]) -> &'a mut PathTrieNode {
    let mut node = trie;
    for segment in segments {
        node = node.exact_children.entry(Arc::clone(segment)).or_default();
    }
    node
}

// ─────────────────────────────────────────────────────────────────────────────
// Discriminator building
// ─────────────────────────────────────────────────────────────────────────────

fn build_discriminators(node: &mut PathTrieNode) {
    // Collect all plans at this node (prefix + exact).
    let mut all_plans: Vec<Arc<CompiledPlan>> = Vec::new();
    all_plans.extend(node.prefix_plans.iter().cloned());
    all_plans.extend(node.exact_plans.iter().cloned());

    if all_plans.len() > DISCRIMINATOR_THRESHOLD {
        node.discriminator = Some(build_discriminator(&all_plans));
    }

    // Recurse into children.
    for child in node.exact_children.values_mut() {
        build_discriminators(child);
    }
}

fn build_discriminator(plans: &[Arc<CompiledPlan>]) -> Discriminator {
    // Analyze which attribute has the most discriminating power.
    let method_count = plans.iter().filter(|p| p.matches.method.is_some()).count();
    let header_counts = count_header_occurrences(plans);
    let query_counts = count_query_occurrences(plans);

    let best_header = header_counts.into_iter().max_by_key(|(_, count)| *count);
    let best_query = query_counts.into_iter().max_by_key(|(_, count)| *count);

    let best_header_count = best_header.as_ref().map_or(0, |(_, c)| *c);
    let best_query_count = best_query.as_ref().map_or(0, |(_, c)| *c);

    // Pick the attribute with the highest count.
    if method_count >= best_header_count && method_count >= best_query_count && method_count > 0 {
        build_method_discriminator(plans)
    } else if best_header_count >= best_query_count && best_header.is_some() {
        build_header_discriminator(plans, best_header.unwrap().0)
    } else if let Some((name, _)) = best_query {
        build_query_discriminator(plans, name)
    } else {
        // No discriminating attribute found — empty discriminator.
        Discriminator {
            kind: DiscriminatorKind::ByMethod {
                exact: HashMap::new(),
                any: Vec::new(),
            },
            fallback: plans.to_vec(),
        }
    }
}

fn count_header_occurrences(plans: &[Arc<CompiledPlan>]) -> HashMap<Arc<str>, usize> {
    let mut counts: HashMap<Arc<str>, usize> = HashMap::new();
    for plan in plans {
        for hm in &plan.matches.headers {
            *counts.entry(Arc::clone(&hm.name)).or_insert(0) += 1;
        }
    }
    counts
}

fn count_query_occurrences(plans: &[Arc<CompiledPlan>]) -> HashMap<Arc<str>, usize> {
    let mut counts: HashMap<Arc<str>, usize> = HashMap::new();
    for plan in plans {
        for qm in &plan.matches.query_params {
            *counts.entry(Arc::clone(&qm.name)).or_insert(0) += 1;
        }
    }
    counts
}

fn build_method_discriminator(plans: &[Arc<CompiledPlan>]) -> Discriminator {
    let mut exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>> = HashMap::new();
    let mut any: Vec<Arc<CompiledPlan>> = Vec::new();

    for plan in plans {
        if let Some(ref method) = plan.matches.method {
            exact
                .entry(Arc::clone(method))
                .or_default()
                .push(Arc::clone(plan));
        } else {
            any.push(Arc::clone(plan));
        }
    }

    for bucket in exact.values_mut() {
        sort_plans(bucket);
    }
    sort_plans(&mut any);

    Discriminator {
        kind: DiscriminatorKind::ByMethod { exact, any },
        fallback: Vec::new(),
    }
}

fn build_header_discriminator(plans: &[Arc<CompiledPlan>], name: Arc<str>) -> Discriminator {
    let mut exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>> = HashMap::new();
    let mut any: Vec<Arc<CompiledPlan>> = Vec::new();
    let mut fallback: Vec<Arc<CompiledPlan>> = Vec::new();

    for plan in plans {
        if let Some(hm) = plan.matches.headers.iter().find(|h| h.name == name) {
            match &hm.value {
                HeaderMatchValue::Exact(v) => {
                    exact
                        .entry(Arc::clone(v))
                        .or_default()
                        .push(Arc::clone(plan));
                }
                _ => {
                    fallback.push(Arc::clone(plan));
                }
            }
        } else {
            any.push(Arc::clone(plan));
        }
    }

    for bucket in exact.values_mut() {
        sort_plans(bucket);
    }
    sort_plans(&mut any);
    sort_plans(&mut fallback);

    Discriminator {
        kind: DiscriminatorKind::ByHeader { name, exact, any },
        fallback,
    }
}

fn build_query_discriminator(plans: &[Arc<CompiledPlan>], name: Arc<str>) -> Discriminator {
    let mut exact: HashMap<Arc<str>, Vec<Arc<CompiledPlan>>> = HashMap::new();
    let mut any: Vec<Arc<CompiledPlan>> = Vec::new();
    let mut fallback: Vec<Arc<CompiledPlan>> = Vec::new();

    for plan in plans {
        if let Some(qm) = plan.matches.query_params.iter().find(|q| q.name == name) {
            match &qm.value {
                QueryParamMatchValue::Exact(v) => {
                    exact
                        .entry(Arc::clone(v))
                        .or_default()
                        .push(Arc::clone(plan));
                }
                _ => {
                    fallback.push(Arc::clone(plan));
                }
            }
        } else {
            any.push(Arc::clone(plan));
        }
    }

    for bucket in exact.values_mut() {
        sort_plans(bucket);
    }
    sort_plans(&mut any);
    sort_plans(&mut fallback);

    Discriminator {
        kind: DiscriminatorKind::ByQuery { name, exact, any },
        fallback,
    }
}

fn sort_plans(plans: &mut [Arc<CompiledPlan>]) {
    plans.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.rule_order.cmp(&b.rule_order))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime lookup
// ─────────────────────────────────────────────────────────────────────────────

impl CompiledRouteTable {
    /// Lookup a plan for the given request.
    ///
    /// Returns `Some(Arc<CompiledPlan>)` if a matching rule is found.
    pub fn lookup(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &http::header::HeaderMap,
        query: Option<&str>,
    ) -> Option<Arc<CompiledPlan>> {
        let host_node = self.find_host_node(host)?;
        host_node.lookup(path, method, headers, query)
    }

    /// Find the host node for a request hostname, respecting listener hostname
    /// isolation and specificity.
    fn find_host_node(&self, host: &str) -> Option<&HostNode> {
        let mut candidates: Vec<&HostNode> = Vec::new();

        // Exact route hostnames.
        if let Some(nodes) = self.exact_hosts.get(host) {
            candidates.extend(nodes.iter());
        }

        // Wildcard/prefix route hostnames.
        for (pattern, node) in &self.wildcard_hosts {
            if ir_hostname_matches(host, pattern) {
                candidates.push(node);
            }
        }

        // Catch-all route hostname.
        if let Some(node) = &self.any_host {
            candidates.push(node);
        }

        // Filter by listener hostname.
        candidates.retain(|n| listener_hostname_matches(host, n.listener_hostname.as_ref()));

        if candidates.is_empty() {
            return None;
        }

        // Listener isolation: pick the most specific listener hostname that
        // matches the request. If multiple candidates share that listener, prefer
        // the most specific route hostname.
        let max_listener_score = candidates
            .iter()
            .map(|n| listener_specificity_score(n.listener_hostname.as_ref()))
            .max()
            .unwrap_or(0);
        candidates.retain(|n| {
            listener_specificity_score(n.listener_hostname.as_ref()) == max_listener_score
        });

        let max_route_score = candidates
            .iter()
            .map(|n| specificity_score(&n.hostname))
            .max()
            .unwrap_or(0);
        candidates
            .iter()
            .find(|n| specificity_score(&n.hostname) == max_route_score)
            .copied()
    }

    /// Returns true if any Gateway API host node matches the request hostname,
    /// regardless of whether any route rule matches. Used to decide whether an
    /// unmatched request should get 404 instead of an HTTPS redirect.
    pub fn has_gateway_api_listener(&self, host: &str) -> bool {
        let mut candidates: Vec<&HostNode> = Vec::new();

        if let Some(nodes) = self.exact_hosts.get(host) {
            candidates.extend(nodes.iter());
        }
        for (pattern, node) in &self.wildcard_hosts {
            if ir_hostname_matches(host, pattern) {
                candidates.push(node);
            }
        }
        if let Some(node) = &self.any_host {
            candidates.push(node);
        }

        candidates
            .iter()
            .any(|n| n.gateway_api && listener_hostname_matches(host, n.listener_hostname.as_ref()))
    }

    /// True if the table contains any Gateway API routes. Used to decide whether
    /// an unmatched plain-HTTP request should receive a 404 instead of an
    /// HTTP→HTTPS redirect.
    pub fn has_gateway_api_routes(&self) -> bool {
        self.any_host.as_ref().is_some_and(|n| n.gateway_api)
            || self
                .exact_hosts
                .values()
                .any(|nodes| nodes.iter().any(|n| n.gateway_api))
            || self.wildcard_hosts.iter().any(|(_, n)| n.gateway_api)
    }
}

/// True if a listener hostname accepts the request hostname. An empty or
/// unspecified listener hostname matches any request host.
fn listener_hostname_matches(host: &str, listener: Option<&HostnameMatch>) -> bool {
    match listener {
        None => true,
        Some(HostnameMatch::Exact(s)) if s.is_empty() => true,
        Some(lh) => ir_hostname_matches(host, lh),
    }
}

/// Specificity score for a listener hostname match (higher = more specific).
fn listener_specificity_score(listener: Option<&HostnameMatch>) -> i32 {
    match listener {
        None => 0,
        Some(HostnameMatch::Any) => 0,
        Some(HostnameMatch::Exact(s)) if s.is_empty() => 0,
        Some(lh) => ir_listener_specificity_score(lh),
    }
}

impl HostNode {
    fn lookup(
        &self,
        path: &str,
        method: &str,
        headers: &http::header::HeaderMap,
        query: Option<&str>,
    ) -> Option<Arc<CompiledPlan>> {
        // Exact path matches take precedence over prefix matches.
        if let Some(bucket) = self.exact_paths.get(path) {
            for plan in bucket {
                if plan_matches(plan, method, headers, query) {
                    return Some(Arc::clone(plan));
                }
            }
        }

        // Walk the path trie for prefix matches.
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut node = &self.path_trie;

        // Collect candidates from each matching node along the path.
        let mut candidates: Vec<Arc<CompiledPlan>> = Vec::new();

        // Root node prefix plans.
        candidates.extend(resolve_node_plans(node, method, headers, query));

        for segment in &segments {
            match node.exact_children.get(*segment) {
                Some(child) => {
                    node = child;
                    candidates.extend(resolve_node_plans(node, method, headers, query));
                }
                None => break,
            }
        }

        // Check regex fallback plans.
        for plan in &self.regex_plans {
            if plan_matches(plan, method, headers, query) && plan_regex_path_matches(plan, path) {
                candidates.push(Arc::clone(plan));
            }
        }

        // Sort all candidates by precedence and pick the first full match.
        candidates.sort_by(|a, b| {
            b.precedence
                .cmp(&a.precedence)
                .then_with(|| a.rule_order.cmp(&b.rule_order))
        });

        // Deduplicate by identity — a plan might appear from both prefix and exact.
        let mut seen = std::collections::HashSet::new();
        for plan in candidates {
            let id = Arc::as_ptr(&plan);
            if seen.insert(id) && plan_matches(&plan, method, headers, query) {
                return Some(plan);
            }
        }

        None
    }
}

/// Resolve plans from a trie node, applying the discriminator if present.
fn resolve_node_plans(
    node: &PathTrieNode,
    method: &str,
    _headers: &http::header::HeaderMap,
    _query: Option<&str>,
) -> Vec<Arc<CompiledPlan>> {
    let mut result = Vec::new();

    if let Some(ref disc) = node.discriminator {
        match &disc.kind {
            DiscriminatorKind::ByMethod { exact, any } => {
                if let Some(bucket) = exact.get(method) {
                    result.extend(bucket.iter().cloned());
                }
                result.extend(any.iter().cloned());
            }
            DiscriminatorKind::ByHeader { name, exact, any } => {
                if let Some(val) = _headers.get(name.as_ref()).and_then(|v| v.to_str().ok()) {
                    if let Some(bucket) = exact.get(val) {
                        result.extend(bucket.iter().cloned());
                    }
                }
                result.extend(any.iter().cloned());
            }
            DiscriminatorKind::ByQuery { name, exact, any } => {
                if let Some(q) = _query {
                    if let Some(val) = extract_query_param(q, name.as_ref()) {
                        if let Some(bucket) = exact.get(val) {
                            result.extend(bucket.iter().cloned());
                        }
                    }
                }
                result.extend(any.iter().cloned());
            }
        }
        result.extend(disc.fallback.iter().cloned());
    } else {
        result.extend(node.prefix_plans.iter().cloned());
        result.extend(node.exact_plans.iter().cloned());
    }

    result
}

fn extract_query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        if key == name {
            Some(parts.next().unwrap_or(""))
        } else {
            None
        }
    })
}

fn plan_matches(
    plan: &CompiledPlan,
    method: &str,
    headers: &http::header::HeaderMap,
    query: Option<&str>,
) -> bool {
    let m = &plan.matches;

    // Method.
    if let Some(ref expected) = m.method {
        if !expected.as_ref().eq_ignore_ascii_case(method) {
            return false;
        }
    }

    // Headers.
    for hm in &m.headers {
        let val = headers.get(hm.name.as_ref()).and_then(|v| v.to_str().ok());
        match &hm.value {
            HeaderMatchValue::Exact(expected) => {
                if !val.is_some_and(|v| v.eq_ignore_ascii_case(expected.as_ref())) {
                    return false;
                }
            }
            HeaderMatchValue::Regex(pattern) => {
                if !val.is_some_and(|v| {
                    regex::Regex::new(pattern.as_ref())
                        .ok()
                        .is_some_and(|re| re.is_match(v))
                }) {
                    return false;
                }
            }
            HeaderMatchValue::Present => {
                if val.is_none() {
                    return false;
                }
            }
            HeaderMatchValue::Absent => {
                if val.is_some() {
                    return false;
                }
            }
        }
    }

    // Query params.
    for qm in &m.query_params {
        let query_val = query.and_then(|q| extract_query_param(q, qm.name.as_ref()));
        match &qm.value {
            QueryParamMatchValue::Exact(expected) => {
                if query_val != Some(expected.as_ref()) {
                    return false;
                }
            }
            QueryParamMatchValue::Regex(pattern) => {
                if !query_val.is_some_and(|v| {
                    regex::Regex::new(pattern.as_ref())
                        .ok()
                        .is_some_and(|re| re.is_match(v))
                }) {
                    return false;
                }
            }
        }
    }

    true
}

fn plan_regex_path_matches(plan: &CompiledPlan, path: &str) -> bool {
    if let Some(PathMatch::Regex(pattern)) = &plan.matches.path {
        regex::Regex::new(pattern.as_ref())
            .ok()
            .is_some_and(|re| re.is_match(path))
    } else {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility helpers (kept during transition)
// ─────────────────────────────────────────────────────────────────────────────

/// Match a request host against an IR HostnameMatch.
pub fn ir_hostname_matches(host: &str, hm: &HostnameMatch) -> bool {
    match hm {
        HostnameMatch::Exact(s) => host == s.as_ref(),
        HostnameMatch::Prefix(prefix) => {
            host == prefix.as_ref() || host.starts_with(&format!("{}.", prefix.as_ref()))
        }
        HostnameMatch::Wildcard(suffix) => host
            .strip_suffix(suffix.as_ref())
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|rest| !rest.is_empty()),
        HostnameMatch::Any => true,
    }
}

/// Specificity score for an IR listener hostname match.
pub fn ir_listener_specificity_score(hm: &HostnameMatch) -> i32 {
    match hm {
        HostnameMatch::Exact(s) if s.is_empty() => 0,
        HostnameMatch::Exact(_) => 1000,
        HostnameMatch::Prefix(_) => 500,
        HostnameMatch::Wildcard(s) => 100 + s.chars().filter(|&c| c == '.').count() as i32,
        HostnameMatch::Any => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_route_action() -> RouteAction {
        RouteAction {
            backends: vec![WeightedBackend {
                backend: "http://svc".into(),
                weight: 1,

                request_filters: vec![],
            }],
            timeout: None,
            request_filters: vec![],
            response_filters: vec![],
            mirror_backends: vec![],
            cache: None,
            body_rewrites: vec![],
            auth: None,
            disable_https_redirect: false,
            websocket: false,
        }
    }

    // ── Empty table ─────────────────────────────────────────────────────

    #[test]
    fn empty_table_has_no_hosts() {
        let empty = CompiledRouteTable::empty();
        assert!(empty.exact_hosts.is_empty());
        assert!(empty.wildcard_hosts.is_empty());
        assert!(empty.any_host.is_none());
        assert!(empty.acme_routes.is_empty());
    }

    // ── Hostname lookup ─────────────────────────────────────────────────

    #[test]
    fn exact_host_lookup() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Exact("example.com".into()),
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Prefix("/".into())),
                    ..Default::default()
                }],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup("example.com", "/", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("other.com", "/", "GET", &Default::default(), None)
            .is_none());
    }

    #[test]
    fn wildcard_host_lookup() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Wildcard("example.com".into()),
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup("sub.example.com", "/", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("example.com", "/", "GET", &Default::default(), None)
            .is_none());
    }

    #[test]
    fn wildcard_host_matches_multiple_subdomain_levels() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Wildcard("bar.com".into()),
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup(
                "multiple.prefixes.bar.com",
                "/",
                "GET",
                &Default::default(),
                None
            )
            .is_some());
        assert!(compiled
            .lookup("foo.bar.com", "/", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("bar.com", "/", "GET", &Default::default(), None)
            .is_none());
    }

    #[test]
    fn any_host_lookup() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup("anything.com", "/", "GET", &Default::default(), None)
            .is_some());
    }

    // ── Path trie lookup ────────────────────────────────────────────────

    #[test]
    fn prefix_match_deeper_path() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Prefix("/api".into())),
                    ..Default::default()
                }],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup("h", "/api", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("h", "/api/v1", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("h", "/api/", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("h", "/other", "GET", &Default::default(), None)
            .is_none());
    }

    #[test]
    fn exact_match_only() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Exact("/health".into())),
                    ..Default::default()
                }],
                action: Action::Route(simple_route_action()),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert!(compiled
            .lookup("h", "/health", "GET", &Default::default(), None)
            .is_some());
        assert!(compiled
            .lookup("h", "/health/", "GET", &Default::default(), None)
            .is_none());
        assert!(compiled
            .lookup("h", "/healthz", "GET", &Default::default(), None)
            .is_none());
    }

    #[test]
    fn longer_prefix_wins() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![
                Rule {
                    matches: vec![RequestMatch {
                        path: Some(PathMatch::Prefix("/".into())),
                        ..Default::default()
                    }],
                    action: Action::Route(RouteAction {
                        backends: vec![WeightedBackend {
                            backend: "root".into(),
                            weight: 1,

                            request_filters: vec![],
                        }],
                        ..simple_route_action()
                    }),
                    rule_order: 0,
                },
                Rule {
                    matches: vec![RequestMatch {
                        path: Some(PathMatch::Prefix("/api".into())),
                        ..Default::default()
                    }],
                    action: Action::Route(RouteAction {
                        backends: vec![WeightedBackend {
                            backend: "api".into(),
                            weight: 1,

                            request_filters: vec![],
                        }],
                        ..simple_route_action()
                    }),
                    rule_order: 1,
                },
            ],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("h", "/api/v1", "GET", &Default::default(), None)
            .unwrap();
        assert_eq!(
            plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
            "api"
        );
    }

    // ── Method discriminator ────────────────────────────────────────────

    #[test]
    fn method_discriminator_filters_correctly() {
        let mut rules = Vec::new();
        for i in 0..10 {
            rules.push(Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Prefix("/api".into())),
                    method: Some(format!("METHOD{}", i).into()),
                    ..Default::default()
                }],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: format!("backend-{}", i).into(),
                        weight: 1,

                        request_filters: vec![],
                    }],
                    ..simple_route_action()
                }),
                rule_order: i,
            });
        }
        // Add a catch-all rule.
        rules.push(Rule {
            matches: vec![RequestMatch {
                path: Some(PathMatch::Prefix("/api".into())),
                ..Default::default()
            }],
            action: Action::Route(RouteAction {
                backends: vec![WeightedBackend {
                    backend: "catch-all".into(),
                    weight: 1,

                    request_filters: vec![],
                }],
                ..simple_route_action()
            }),
            rule_order: 100,
        });

        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules,
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();

        // Each method should hit its specific backend.
        for i in 0..10 {
            let method = format!("METHOD{}", i);
            let plan = compiled
                .lookup("h", "/api/x", &method, &Default::default(), None)
                .unwrap();
            assert_eq!(
                plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
                format!("backend-{}", i)
            );
        }

        // Unknown method should hit catch-all.
        let plan = compiled
            .lookup("h", "/api/x", "UNKNOWN", &Default::default(), None)
            .unwrap();
        assert_eq!(
            plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
            "catch-all"
        );
    }

    // ── Redirect compilation ────────────────────────────────────────────

    #[test]
    fn redirect_compiles_to_terminal() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Exact("example.com".into()),
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Prefix("/old".into())),
                    ..Default::default()
                }],
                action: Action::Redirect(RedirectAction {
                    status_code: 301,
                    scheme: Some("https".into()),
                    hostname: Some("new.com".into()),
                    port: Some(8443),
                    path: Some(PathRewrite::FullReplace("/new".into())),
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("example.com", "/old", "GET", &Default::default(), None)
            .unwrap();
        assert_eq!(plan.request_stages.len(), 1);
        assert!(matches!(
            plan.request_stages[0],
            RequestStage::Terminal(TerminalAction::Redirect(RedirectAction {
                status_code: 301,
                ..
            }))
        ));
    }

    // ── ACME routes preserved ───────────────────────────────────────────

    #[test]
    fn acme_routes_preserved() {
        let mut rt = RouteTable::default();
        rt.acme_routes
            .insert("/challenge".into(), "solver:8080".into());
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        assert_eq!(compiled.acme_routes.len(), 1);
        assert_eq!(
            compiled.acme_routes.get("/challenge"),
            Some(&Arc::from("solver:8080"))
        );
    }

    // ── Header match compilation ────────────────────────────────────────

    #[test]
    fn header_match_compiles_and_looks_up() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch {
                    path: Some(PathMatch::Prefix("/".into())),
                    headers: vec![HeaderMatch {
                        name: "version".into(),
                        value: HeaderMatchValue::Exact("one".into()),
                    }],
                    ..Default::default()
                }],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: "v1".into(),
                        weight: 1,

                        request_filters: vec![],
                    }],
                    ..simple_route_action()
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();

        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("one"));
        let plan = compiled.lookup("h", "/", "GET", &headers, None).unwrap();
        assert_eq!(
            plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
            "v1"
        );

        // No header — should not match (gateway_api = true, so no fallback).
        assert!(compiled
            .lookup("h", "/", "GET", &Default::default(), None)
            .is_none());
    }

    // ── Body rewrite compilation ────────────────────────────────────────

    #[test]
    fn body_rewrites_compiled_into_plan() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: "svc".into(),
                        weight: 1,

                        request_filters: vec![],
                    }],
                    timeout: None,
                    request_filters: vec![],
                    response_filters: vec![],
                    mirror_backends: vec![],
                    cache: None,
                    body_rewrites: vec![BodyRewrite {
                        find: "old".into(),
                        replace: "new".into(),
                        types: vec!["text/html".into()],
                    }],
                    auth: None,
                    disable_https_redirect: false,
                    websocket: false,
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("h", "/", "GET", &Default::default(), None)
            .unwrap();
        assert_eq!(plan.body_rewrites.len(), 1);
        assert_eq!(plan.body_rewrites[0].find.as_ref(), "old");
    }

    // ── Cors compilation ────────────────────────────────────────────────

    #[test]
    fn cors_compiled_into_response_mutations() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: "svc".into(),
                        weight: 1,

                        request_filters: vec![],
                    }],
                    timeout: None,
                    request_filters: vec![],
                    response_filters: vec![ResponseFilter::Cors(CorsConfig {
                        allow_origins: vec!["*".into()],
                        allow_methods: vec!["GET".into()],
                        allow_headers: vec![],
                        expose_headers: vec![],
                        max_age: Some(86400),
                        allow_credentials: false,
                    })],
                    mirror_backends: vec![],
                    cache: None,
                    body_rewrites: vec![],
                    auth: None,
                    disable_https_redirect: false,
                    websocket: false,
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("h", "/", "GET", &Default::default(), None)
            .unwrap();
        assert_eq!(plan.response_mutations.len(), 1);
        assert!(matches!(
            plan.response_mutations[0],
            ResponseMutation::Cors(_)
        ));
    }

    // ── Request filter compilation ──────────────────────────────────────

    #[test]
    fn request_filters_compiled_into_mutations() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: "svc".into(),
                        weight: 1,

                        request_filters: vec![],
                    }],
                    timeout: None,
                    request_filters: vec![
                        RequestFilter::SetHeader {
                            name: "X-Id".into(),
                            value: "1".into(),
                        },
                        RequestFilter::StripPrefix("/api".into()),
                    ],
                    response_filters: vec![],
                    mirror_backends: vec![],
                    cache: None,
                    body_rewrites: vec![],
                    auth: None,
                    disable_https_redirect: false,
                    websocket: false,
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("h", "/", "GET", &Default::default(), None)
            .unwrap();
        assert_eq!(plan.upstream_request_mutations.len(), 2);
        assert!(matches!(
            plan.upstream_request_mutations[0],
            UpstreamRequestMutation::SetHeader { .. }
        ));
        assert!(matches!(
            plan.upstream_request_mutations[1],
            UpstreamRequestMutation::StripPrefix(_)
        ));
    }

    #[test]
    fn backend_request_filters_compiled_into_per_backend_mutations() {
        let host = HostRoute {
            listener_hostname: None,
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            gateway_api: true,
            disable_secure_redirection: false,
            rules: vec![Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(RouteAction {
                    backends: vec![
                        WeightedBackend {
                            backend: "svc-a".into(),
                            weight: 1,
                            request_filters: vec![RequestFilter::SetHeader {
                                name: "X-Backend".into(),
                                value: "a".into(),
                            }],
                        },
                        WeightedBackend {
                            backend: "svc-b".into(),
                            weight: 1,
                            request_filters: vec![RequestFilter::SetHeader {
                                name: "X-Backend".into(),
                                value: "b".into(),
                            }],
                        },
                    ],
                    timeout: None,
                    request_filters: vec![],
                    response_filters: vec![],
                    mirror_backends: vec![],
                    cache: None,
                    body_rewrites: vec![],
                    auth: None,
                    disable_https_redirect: false,
                    websocket: false,
                }),
                rule_order: 0,
            }],
        };
        let rt = RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: Default::default(),
        };
        let compiled = CompiledRouteTable::compile(rt).unwrap();
        let plan = compiled
            .lookup("h", "/", "GET", &Default::default(), None)
            .unwrap();
        let upstream = plan.upstream.as_ref().unwrap();
        assert_eq!(upstream.backend_request_mutations.len(), 2);
        assert!(matches!(
            upstream.backend_request_mutations[0][0],
            UpstreamRequestMutation::SetHeader { .. }
        ));
        assert!(matches!(
            upstream.backend_request_mutations[1][0],
            UpstreamRequestMutation::SetHeader { .. }
        ));
    }

    // ── CompileError Display ────────────────────────────────────────────

    #[test]
    fn compile_error_display() {
        let err = CompileError {
            message: "bad regex".into(),
        };
        assert_eq!(format!("{}", err), "compile error: bad regex");
    }
}
