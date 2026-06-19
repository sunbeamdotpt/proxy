// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Translate a `caddyfile-rs` AST into sunbeam-proxy's `ir::RouteTable`.

use std::sync::Arc;

use caddyfile_rs::{Address, Caddyfile, Directive, Matcher, SiteBlock};

use crate::ir::{
    Action, AuthConfig, BackendProtocol, HostRoute, HostnameMatch, ListenerConfig, PathMatch,
    PathRewrite, Protocol, RequestFilter, RequestMatch, ResponseFilter, RewriteRule, RouteAction,
    RouteTable, Rule, StaticFileAction, WeightedBackend,
};

/// Error returned when a Caddyfile cannot be translated into IR.
#[derive(Debug)]
pub struct TranslateError(pub String);

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TranslateError {}

/// Translate a parsed Caddyfile into an `ir::RouteTable`.
pub fn translate(caddyfile: &Caddyfile) -> Result<RouteTable, TranslateError> {
    let mut table = RouteTable::default();

    // Global options may define default listeners (bind, http_port, etc.).
    if let Some(global) = &caddyfile.global_options {
        for directive in &global.directives {
            if directive.name == "bind" {
                let listener = translate_bind_global(directive)?;
                table.listeners.push(listener);
            } else {
                warn_unsupported(&directive.name, "global options");
            }
        }
    }

    // Site blocks become HostRoutes (and possibly per-site listeners).
    for site in &caddyfile.sites {
        let (host_route, site_listener) = translate_site(site)?;
        table.hosts.push(host_route);
        if let Some(listener) = site_listener {
            table.listeners.push(listener);
        }
    }

    Ok(table)
}

fn translate_site(site: &SiteBlock) -> Result<(HostRoute, Option<ListenerConfig>), TranslateError> {
    let mut hostnames = Vec::new();
    let mut listener = None;

    for addr in &site.addresses {
        let (hostname, addr_listener) = translate_address(addr)?;
        hostnames.push(hostname);
        if let Some(l) = addr_listener {
            listener = Some(l);
        }
    }

    // If multiple addresses are given, we use the first hostname as the primary
    // HostRoute identity. Additional addresses create additional HostRoutes via
    // duplication, but for the spike a single HostRoute per site block is enough.
    let primary_hostname = hostnames.into_iter().next().unwrap_or(HostnameMatch::Any);

    let mut rules: Vec<Rule> = Vec::new();
    for (idx, directive) in site.directives.iter().enumerate() {
        match directive.name.as_str() {
            "bind" => {
                // Per-site bind overrides any address-derived listener.
                listener = Some(translate_bind_directive(directive)?);
            }
            "file_server" => {
                if let Some(rule) = translate_static_file_block(&site.directives, idx)? {
                    rules.push(rule);
                }
            }
            "root" | "try_files" => {
                // Standalone root/try_files without an adjacent file_server are
                // not useful; skip them and rely on the file_server block to
                // collect related directives.
                warn_unsupported(&directive.name, "site block without file_server");
            }
            "reverse_proxy" => rules.push(translate_reverse_proxy(directive, idx)?),
            "rewrite" => rules.push(translate_rewrite(directive, idx)?),
            "header" => rules.push(translate_header(directive, idx)?),
            "request_header" => rules.push(translate_request_header(directive, idx)?),
            "forward_auth" => rules.push(translate_forward_auth(directive, idx)?),
            "tls" => {
                // TLS at site level creates a listener cert or HTTPS listener.
                // For the spike we only support explicit cert/key files.
                warn_unsupported("tls", "site block");
            }
            "handle" | "handle_path" | "route" => {
                rules.extend(translate_handle_group(directive, idx)?);
            }
            _ => warn_unsupported(&directive.name, "site block"),
        }
    }

    let host_route = HostRoute {
        hostname: primary_hostname,
        listener_ids: Vec::new(),
        listener_hostname: None,
        listener_port: None,
        gateway_api: false,
        disable_secure_redirection: false,
        rules,
    };

    Ok((host_route, listener))
}

fn translate_address(
    addr: &Address,
) -> Result<(HostnameMatch, Option<ListenerConfig>), TranslateError> {
    let hostname = if addr.host.is_empty() || addr.host == ":" {
        HostnameMatch::Any
    } else if addr.host.starts_with("*.") {
        HostnameMatch::Wildcard(Arc::from(&addr.host[2..]))
    } else {
        HostnameMatch::Exact(Arc::from(addr.host.as_str()))
    };

    let listener = addr.port.map(|port| {
        let bind_addr = format!("0.0.0.0:{port}");
        let protocol = match addr.scheme {
            Some(caddyfile_rs::Scheme::Https) => Protocol::Https,
            _ => Protocol::Http,
        };
        ListenerConfig {
            id: Arc::from(bind_addr.as_str()),
            bind_addr: Arc::from(bind_addr),
            protocol,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        }
    });

    Ok((hostname, listener))
}

fn translate_bind_global(directive: &Directive) -> Result<ListenerConfig, TranslateError> {
    translate_bind_directive(directive)
}

fn translate_bind_directive(directive: &Directive) -> Result<ListenerConfig, TranslateError> {
    let addr = directive
        .arguments
        .first()
        .map(|a| a.value())
        .unwrap_or("0.0.0.0:80");
    let protocol = if addr.starts_with("https://") {
        Protocol::Https
    } else {
        Protocol::Http
    };
    let bind_addr = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    Ok(ListenerConfig {
        id: Arc::from(bind_addr),
        bind_addr: Arc::from(bind_addr),
        protocol,
        tls: None,
        redirect_http_to_https: false,
        frontend_validation: None,
    })
}

fn translate_static_file_block(
    directives: &[Directive],
    start_idx: usize,
) -> Result<Option<Rule>, TranslateError> {
    let directive = &directives[start_idx];
    if directive.name != "file_server" {
        return Ok(None);
    }

    let mut root = ".".to_string();
    let mut fallback: Option<Arc<str>> = None;
    let mut rewrites: Vec<RewriteRule> = Vec::new();

    // Scan backward for root/try_files directives that belong to this file_server.
    // caddyfile-rs parses the first path-like token of any directive as a matcher,
    // so `root /var/www` has matcher=/var/www with no arguments. We therefore fall
    // back to the matcher value when arguments are absent.
    for d in directives[..start_idx].iter().rev() {
        match d.name.as_str() {
            "root" => {
                root = directive_first_value(d).unwrap_or(".").to_string();
            }
            "try_files" => {
                rewrites.extend(translate_try_files(d)?);
                if let Some(&last) = directive_values(d).last()
                    && !last.starts_with('{')
                {
                    fallback = Some(Arc::from(last));
                }
            }
            _ => break,
        }
    }

    // file_server may have subdirectives like root, try_files.
    if let Some(block) = &directive.block {
        for sub in block {
            match sub.name.as_str() {
                "root" => {
                    root = directive_first_value(sub).unwrap_or(".").to_string();
                }
                "try_files" => {
                    rewrites.extend(translate_try_files(sub)?);
                    if let Some(&last) = directive_values(sub).last()
                        && !last.starts_with('{')
                    {
                        fallback = Some(Arc::from(last));
                    }
                }
                _ => warn_unsupported(&sub.name, "file_server block"),
            }
        }
    }

    let matcher = translate_matcher(&directive.matcher)?;
    let req_match = matcher.unwrap_or_default();

    Ok(Some(Rule {
        matches: vec![req_match],
        action: Action::StaticFiles(StaticFileAction {
            root: Arc::from(root),
            fallback,
            rewrites,
            extra_headers: Vec::new(),
        }),
        rule_order: start_idx,
    }))
}

/// Return all values for a directive, treating a leading path matcher as the
/// first argument when no explicit arguments are present.
fn directive_values(directive: &Directive) -> Vec<&str> {
    let mut values: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();
    if values.is_empty()
        && let Some(Matcher::Path(path)) = directive.matcher.as_ref()
    {
        values.push(path.as_str());
    }
    values
}

fn directive_first_value(directive: &Directive) -> Option<&str> {
    directive_values(directive).first().copied()
}

fn translate_try_files(directive: &Directive) -> Result<Vec<RewriteRule>, TranslateError> {
    let mut rewrites = Vec::new();
    let args = directive_values(directive);

    for window in args.windows(2) {
        let pattern = window[0];
        let target = window[1];
        // Only translate concrete rewrite targets (skip placeholders like {path}).
        if !target.starts_with('{') {
            rewrites.push(RewriteRule {
                pattern: Arc::from(pattern),
                target: Arc::from(target),
            });
        }
    }

    Ok(rewrites)
}

fn translate_reverse_proxy(directive: &Directive, idx: usize) -> Result<Rule, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let args: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();

    let backends: Vec<WeightedBackend> = args
        .iter()
        .map(|addr| WeightedBackend {
            backend: Arc::from(*addr),
            weight: 1,
            request_filters: Vec::new(),
            protocol: BackendProtocol::Http,
            tls: None,
        })
        .collect();

    Ok(Rule {
        matches: vec![matcher.unwrap_or_default()],
        action: Action::Route(RouteAction {
            backends,
            timeout: None,
            request_filters: Vec::new(),
            response_filters: Vec::new(),
            mirror_backends: Vec::new(),
            mirror_fractions: Vec::new(),
            cache: None,
            body_rewrites: Vec::new(),
            auth: None,
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }),
        rule_order: idx,
    })
}

fn translate_rewrite(directive: &Directive, idx: usize) -> Result<Rule, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let args: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();

    let rewrite = if let Some(ref _m) = matcher {
        // caddyfile-rs parses `rewrite /old /new` as matcher=/old, args=["/new"].
        let target = args.first().ok_or_else(|| {
            TranslateError(format!(
                "rewrite directive at index {idx} is missing a target"
            ))
        })?;
        RequestFilter::RewritePath(PathRewrite::FullReplace(Arc::from(*target)))
    } else if args.len() >= 2 {
        // Unusual but valid: rewrite <from> <to> without a matcher.
        RequestFilter::RewritePath(PathRewrite::PrefixReplace {
            prefix: Arc::from(args[0]),
            replacement: Arc::from(args[1]),
        })
    } else {
        return Err(TranslateError(format!(
            "rewrite directive at index {idx} requires at least two arguments"
        )));
    };

    Ok(Rule {
        matches: vec![matcher.unwrap_or_default()],
        action: Action::Route(RouteAction {
            backends: Vec::new(),
            timeout: None,
            request_filters: vec![rewrite],
            response_filters: Vec::new(),
            mirror_backends: Vec::new(),
            mirror_fractions: Vec::new(),
            cache: None,
            body_rewrites: Vec::new(),
            auth: None,
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }),
        rule_order: idx,
    })
}

fn translate_header(directive: &Directive, idx: usize) -> Result<Rule, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let args: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();

    let mut response_filters = Vec::new();
    if args.len() >= 2 {
        let name: Arc<str> = Arc::from(args[0]);
        if args[1].is_empty() {
            response_filters.push(ResponseFilter::RemoveHeader(name));
        } else {
            let value: Arc<str> = Arc::from(args[1]);
            response_filters.push(ResponseFilter::SetHeader { name, value });
        }
    }

    Ok(Rule {
        matches: vec![matcher.unwrap_or_default()],
        action: Action::Route(RouteAction {
            backends: Vec::new(),
            timeout: None,
            request_filters: Vec::new(),
            response_filters,
            mirror_backends: Vec::new(),
            mirror_fractions: Vec::new(),
            cache: None,
            body_rewrites: Vec::new(),
            auth: None,
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }),
        rule_order: idx,
    })
}

fn translate_request_header(directive: &Directive, idx: usize) -> Result<Rule, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let args: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();

    let mut request_filters = Vec::new();
    if args.len() >= 2 {
        let name: Arc<str> = Arc::from(args[0]);
        if args[1].is_empty() {
            request_filters.push(RequestFilter::RemoveHeader(name));
        } else {
            let value: Arc<str> = Arc::from(args[1]);
            request_filters.push(RequestFilter::SetHeader { name, value });
        }
    }

    Ok(Rule {
        matches: vec![matcher.unwrap_or_default()],
        action: Action::Route(RouteAction {
            backends: Vec::new(),
            timeout: None,
            request_filters,
            response_filters: Vec::new(),
            mirror_backends: Vec::new(),
            mirror_fractions: Vec::new(),
            cache: None,
            body_rewrites: Vec::new(),
            auth: None,
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }),
        rule_order: idx,
    })
}

fn translate_forward_auth(directive: &Directive, idx: usize) -> Result<Rule, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let args: Vec<&str> = directive.arguments.iter().map(|a| a.value()).collect();

    let url = args
        .first()
        .map(|s| Arc::from(*s))
        .ok_or_else(|| TranslateError(format!("forward_auth at index {idx} requires a URL")))?;

    Ok(Rule {
        matches: vec![matcher.unwrap_or_default()],
        action: Action::Route(RouteAction {
            backends: Vec::new(),
            timeout: None,
            request_filters: Vec::new(),
            response_filters: Vec::new(),
            mirror_backends: Vec::new(),
            mirror_fractions: Vec::new(),
            cache: None,
            body_rewrites: Vec::new(),
            auth: Some(AuthConfig {
                url,
                capture_headers: Vec::new(),
            }),
            websocket: false,
            disable_https_redirect: false,
            client_cert_id: None,
        }),
        rule_order: idx,
    })
}

fn translate_handle_group(directive: &Directive, idx: usize) -> Result<Vec<Rule>, TranslateError> {
    let matcher = translate_matcher(&directive.matcher)?;
    let strip_prefix = directive.name == "handle_path";

    let mut rules = Vec::new();
    if let Some(block) = &directive.block {
        for (inner_idx, inner) in block.iter().enumerate() {
            let mut rule = match inner.name.as_str() {
                "file_server" => translate_static_file_block(block, inner_idx)?
                    .ok_or_else(|| TranslateError("empty file_server block".to_string()))?,
                "root" | "try_files" => {
                    warn_unsupported(&inner.name, &format!("{} block", directive.name));
                    continue;
                }
                "reverse_proxy" => translate_reverse_proxy(inner, inner_idx)?,
                "rewrite" => translate_rewrite(inner, inner_idx)?,
                "header" => translate_header(inner, inner_idx)?,
                "request_header" => translate_request_header(inner, inner_idx)?,
                "forward_auth" => translate_forward_auth(inner, inner_idx)?,
                other => {
                    warn_unsupported(other, &format!("{} block", directive.name));
                    continue;
                }
            };

            // Combine outer matcher with inner matcher.
            if let Some(ref outer) = matcher {
                rule.matches[0] = combine_matches(outer.clone(), rule.matches[0].clone());
                if strip_prefix && let Some(ref path) = outer.path {
                    let prefix = match path {
                        PathMatch::Prefix(p) | PathMatch::Exact(p) => Arc::clone(p),
                        PathMatch::Regex(p) => Arc::clone(p),
                    };
                    if let Action::Route(ref mut action) = rule.action {
                        action
                            .request_filters
                            .insert(0, RequestFilter::StripPrefix(prefix));
                    }
                }
            }

            rule.rule_order = idx * 1000 + inner_idx;
            rules.push(rule);
        }
    }

    Ok(rules)
}

fn translate_matcher(matcher: &Option<Matcher>) -> Result<Option<RequestMatch>, TranslateError> {
    Ok(match matcher {
        None => None,
        Some(Matcher::All) => Some(RequestMatch::default()),
        Some(Matcher::Path(path)) => Some(RequestMatch {
            path: Some(translate_path_matcher(path)),
            ..Default::default()
        }),
        Some(Matcher::Named(name)) => {
            return Err(TranslateError(format!(
                "named matcher @{name} is not supported in this patch"
            )));
        }
    })
}

fn translate_path_matcher(path: &str) -> PathMatch {
    if path == "*" {
        PathMatch::Prefix(Arc::from("/"))
    } else if let Some(prefix) = path.strip_suffix('*') {
        PathMatch::Prefix(Arc::from(prefix))
    } else {
        PathMatch::Exact(Arc::from(path))
    }
}

fn combine_matches(outer: RequestMatch, mut inner: RequestMatch) -> RequestMatch {
    // If the outer matcher is more specific, use outer path unless inner has one.
    if inner.path.is_none() {
        inner.path = outer.path;
    }
    inner.method = inner.method.or(outer.method);
    inner.headers.extend(outer.headers);
    inner.query_params.extend(outer.query_params);
    inner
}

fn warn_unsupported(directive: &str, context: &str) {
    tracing::warn!(
        directive,
        context,
        "unsupported Caddyfile directive; skipping"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(content: &str) -> String {
        format!("example.com {{\n{}\n}}\n", content)
    }

    fn parse(input: &str) -> Caddyfile {
        caddyfile_rs::parse_str(input).expect("test input should parse")
    }

    #[test]
    fn translate_empty_caddyfile() {
        let cf = parse("");
        let table = translate(&cf).unwrap();
        assert!(table.hosts.is_empty());
        assert!(table.listeners.is_empty());
    }

    #[test]
    fn translate_site_address_exact_host() {
        let cf = parse(&site("\tfile_server"));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts.len(), 1);
        assert_eq!(
            table.hosts[0].hostname,
            HostnameMatch::Exact("example.com".into())
        );
    }

    #[test]
    fn translate_site_address_wildcard() {
        let cf = parse("*.example.com {\n\tfile_server\n}\n");
        let table = translate(&cf).unwrap();
        assert_eq!(
            table.hosts[0].hostname,
            HostnameMatch::Wildcard("example.com".into())
        );
    }

    #[test]
    fn translate_site_address_any() {
        let cf = parse(":8080 {\n\tfile_server\n}\n");
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].hostname, HostnameMatch::Any);
        assert_eq!(table.listeners.len(), 1);
        assert_eq!(table.listeners[0].bind_addr.as_ref(), "0.0.0.0:8080");
    }

    #[test]
    fn translate_bind_global() {
        let cf = parse("{\n\tbind 0.0.0.0:8080\n}\nexample.com {\n\tfile_server\n}\n");
        let table = translate(&cf).unwrap();
        assert_eq!(table.listeners.len(), 1);
        assert_eq!(table.listeners[0].bind_addr.as_ref(), "0.0.0.0:8080");
    }

    #[test]
    fn translate_bind_per_site() {
        let cf = parse("example.com {\n\tbind 127.0.0.1:3000\n\tfile_server\n}\n");
        let _table = translate(&cf).unwrap();
        let (_, listener) = translate_site(&cf.sites[0]).unwrap();
        assert_eq!(listener.unwrap().bind_addr.as_ref(), "127.0.0.1:3000");
    }

    #[test]
    fn translate_file_server_default_root() {
        let cf = parse(&site("\tfile_server"));
        let table = translate(&cf).unwrap();
        let rule = &table.hosts[0].rules[0];
        assert!(matches!(rule.action, Action::StaticFiles(_)));
        if let Action::StaticFiles(ref action) = rule.action {
            assert_eq!(action.root.as_ref(), ".");
            assert!(action.fallback.is_none());
        }
    }

    #[test]
    fn translate_file_server_with_root() {
        let cf = parse(&site("\troot /var/www\n\tfile_server"));
        let table = translate(&cf).unwrap();
        if let Action::StaticFiles(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.root.as_ref(), "/var/www");
        } else {
            panic!("expected static files action");
        }
    }

    #[test]
    fn translate_try_files_spa_fallback() {
        let cf = parse(&site(
            "\ttry_files \"{path}\" \"{path}/\" /index.html\n\tfile_server",
        ));
        let table = translate(&cf).unwrap();
        if let Action::StaticFiles(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.fallback.as_deref(), Some("/index.html"));
            assert!(!action.rewrites.is_empty());
        } else {
            panic!("expected static files action");
        }
    }

    #[test]
    fn translate_reverse_proxy_single_upstream() {
        let cf = parse(&site("\treverse_proxy /api/* localhost:8080"));
        let table = translate(&cf).unwrap();
        let rule = &table.hosts[0].rules[0];
        if let Action::Route(ref action) = rule.action {
            assert_eq!(action.backends.len(), 1);
            assert_eq!(action.backends[0].backend.as_ref(), "localhost:8080");
        } else {
            panic!("expected route action");
        }
        assert!(matches!(rule.matches[0].path, Some(PathMatch::Prefix(_))));
    }

    #[test]
    fn translate_reverse_proxy_multiple_upstreams() {
        let cf = parse(&site("\treverse_proxy localhost:8080 localhost:8081"));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.backends.len(), 2);
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_rewrite_literal() {
        let cf = parse(&site("\trewrite /old /new"));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.request_filters.len(), 1);
            assert!(matches!(
                action.request_filters[0],
                RequestFilter::RewritePath(PathRewrite::FullReplace(_))
            ));
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_header_set_and_remove() {
        let cf = parse(&site("\theader X-Custom value\n\theader X-Removed \"\""));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 2);
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(matches!(
                action.response_filters[0],
                ResponseFilter::SetHeader { .. }
            ));
        }
        if let Action::Route(ref action) = table.hosts[0].rules[1].action {
            assert!(matches!(
                action.response_filters[0],
                ResponseFilter::RemoveHeader(_)
            ));
        }
    }

    #[test]
    fn translate_request_header() {
        let cf = parse(&site("\trequest_header X-Proxy sunbeam"));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(matches!(
                action.request_filters[0],
                RequestFilter::SetHeader { .. }
            ));
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_forward_auth() {
        let cf = parse(&site("\tforward_auth localhost:9000"));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(action.auth.is_some());
            assert_eq!(action.auth.as_ref().unwrap().url.as_ref(), "localhost:9000");
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_handle_group() {
        let cf = parse(&site(
            "\thandle /api/* {\n\t\treverse_proxy localhost:8080\n\t}",
        ));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
        assert!(matches!(
            table.hosts[0].rules[0].matches[0].path,
            Some(PathMatch::Prefix(_))
        ));
    }

    #[test]
    fn translate_handle_path_strips_prefix() {
        let cf = parse(&site(
            "\thandle_path /api/* {\n\t\treverse_proxy localhost:8080\n\t}",
        ));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(
                action
                    .request_filters
                    .iter()
                    .any(|f| matches!(f, RequestFilter::StripPrefix(_)))
            );
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_unsupported_directive_warns() {
        let cf = parse(&site("\tencode gzip\n\tfile_server"));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
    }

    #[test]
    fn translate_named_matcher_errors() {
        let cf = parse(
            "@api {\n\tpath /api/*\n}\nexample.com {\n\treverse_proxy @api localhost:8080\n}\n",
        );
        let err = translate(&cf).unwrap_err();
        assert!(err.0.contains("named matcher"));
    }

    #[test]
    fn translate_rewrite_missing_arguments_errors() {
        let cf = parse(&site("\trewrite"));
        let err = translate(&cf).unwrap_err();
        assert!(err.0.contains("requires at least two arguments"));
    }

    #[test]
    fn translate_path_matcher_wildcard() {
        assert_eq!(
            translate_path_matcher("/api/*"),
            PathMatch::Prefix("/api/".into())
        );
        assert_eq!(
            translate_path_matcher("/health"),
            PathMatch::Exact("/health".into())
        );
        assert_eq!(translate_path_matcher("*"), PathMatch::Prefix("/".into()));
    }

    #[test]
    fn translate_file_server_sub_block() {
        let cf = parse(&site(
            "\tfile_server {\n\t\troot /var/www\n\t\ttry_files /index.html\n\t}",
        ));
        let table = translate(&cf).unwrap();
        if let Action::StaticFiles(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.root.as_ref(), "/var/www");
            assert_eq!(action.fallback.as_deref(), Some("/index.html"));
        } else {
            panic!("expected static files action");
        }
    }

    #[test]
    fn translate_root_without_file_server_is_skipped() {
        let cf = parse(&site("\troot /var/www"));
        let table = translate(&cf).unwrap();
        assert!(table.hosts[0].rules.is_empty());
    }

    #[test]
    fn translate_tls_directive_is_skipped() {
        let cf = parse(&site("\ttls off\n\tfile_server"));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
    }

    #[test]
    fn translate_site_address_https_scheme() {
        let cf = parse("https://example.com:8443 {\n\tfile_server\n}\n");
        let table = translate(&cf).unwrap();
        assert_eq!(table.listeners.len(), 1);
        assert!(matches!(table.listeners[0].protocol, Protocol::Https));
    }

    #[test]
    fn translate_bind_https_scheme() {
        let cf = parse("{\n\tbind https://0.0.0.0:8443\n}\nexample.com {\n\tfile_server\n}\n");
        let table = translate(&cf).unwrap();
        assert_eq!(table.listeners[0].bind_addr.as_ref(), "0.0.0.0:8443");
        assert!(matches!(table.listeners[0].protocol, Protocol::Https));
    }

    #[test]
    fn translate_rewrite_prefix_replace() {
        let cf = parse(&site("\trewrite old new"));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(matches!(
                action.request_filters[0],
                RequestFilter::RewritePath(PathRewrite::PrefixReplace { .. })
            ));
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_request_header_remove() {
        let cf = parse(&site("\trequest_header X-Removed \"\""));
        let table = translate(&cf).unwrap();
        if let Action::Route(ref action) = table.hosts[0].rules[0].action {
            assert!(matches!(
                action.request_filters[0],
                RequestFilter::RemoveHeader(_)
            ));
        } else {
            panic!("expected route action");
        }
    }

    #[test]
    fn translate_all_matcher() {
        let cf = parse(&site("\treverse_proxy * localhost:8080"));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
    }

    #[test]
    fn translate_handle_block_file_server_and_unsupported() {
        let cf = parse(&site(
            "\thandle /docs/* {\n\t\tfile_server {\n\t\t\troot /var/www\n\t\t}\n\t\tencode gzip\n\t}",
        ));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
        if let Action::StaticFiles(ref action) = table.hosts[0].rules[0].action {
            assert_eq!(action.root.as_ref(), "/var/www");
        } else {
            panic!("expected static files action");
        }
    }

    #[test]
    fn translate_handle_block_ignores_root_try_files() {
        let cf = parse(&site(
            "\thandle /docs/* {\n\t\troot /var/www\n\t\ttry_files /index.html\n\t\treverse_proxy localhost:8080\n\t}",
        ));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
    }

    #[test]
    fn translate_file_server_unsupported_subdirective() {
        let cf = parse(&site("\tfile_server {\n\t\tfoo bar\n\t}"));
        let table = translate(&cf).unwrap();
        assert_eq!(table.hosts[0].rules.len(), 1);
    }

    #[test]
    fn translate_error_display() {
        let err = TranslateError("boom".to_string());
        assert_eq!(format!("{err}"), "boom");
    }
}
