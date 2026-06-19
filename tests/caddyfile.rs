// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for Caddyfile route source support.

use std::path::Path;

use sunbeam_proxy::caddyfile::{parse_dir, parse_file};
use sunbeam_proxy::ir::{Action, HostnameMatch, PathMatch, RequestFilter, ResponseFilter};

#[test]
fn parse_file_translates_static_file_server() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"example.com {
	root /var/www
	try_files "{path}" "{path}/" /index.html
	file_server
}
"#,
    )
    .unwrap();

    let table = parse_file(&path).unwrap();
    assert_eq!(table.hosts.len(), 1);
    assert_eq!(
        table.hosts[0].hostname,
        HostnameMatch::Exact("example.com".into())
    );

    let rule = &table.hosts[0].rules[0];
    let Action::StaticFiles(ref action) = rule.action else {
        panic!("expected static files action");
    };
    assert_eq!(action.root.as_ref(), "/var/www");
    assert_eq!(action.fallback.as_deref(), Some("/index.html"));
    assert!(!action.rewrites.is_empty());
}

#[test]
fn parse_file_translates_reverse_proxy_with_path_matcher() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"example.com {
	reverse_proxy /api/* localhost:8080 localhost:8081
}
"#,
    )
    .unwrap();

    let table = parse_file(&path).unwrap();
    let rule = &table.hosts[0].rules[0];
    assert!(matches!(rule.matches[0].path, Some(PathMatch::Prefix(_))));
    let Action::Route(ref action) = rule.action else {
        panic!("expected route action");
    };
    assert_eq!(action.backends.len(), 2);
}

#[test]
fn parse_file_translates_headers_and_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"example.com {
	request_header X-Proxy sunbeam
	rewrite /old /new
	header X-Removed ""
}
"#,
    )
    .unwrap();

    let table = parse_file(&path).unwrap();
    assert_eq!(table.hosts[0].rules.len(), 3);

    let Action::Route(ref req_action) = table.hosts[0].rules[0].action else {
        panic!("expected route action");
    };
    assert!(matches!(
        req_action.request_filters[0],
        RequestFilter::SetHeader { .. }
    ));

    let Action::Route(ref rewrite_action) = table.hosts[0].rules[1].action else {
        panic!("expected route action");
    };
    assert!(matches!(
        rewrite_action.request_filters[0],
        RequestFilter::RewritePath(_)
    ));

    let Action::Route(ref resp_action) = table.hosts[0].rules[2].action else {
        panic!("expected route action");
    };
    assert!(matches!(
        resp_action.response_filters[0],
        ResponseFilter::RemoveHeader(_)
    ));
}

#[test]
fn parse_dir_merges_multiple_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("001.caddyfile"),
        r#"a.example.com {
	file_server
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("002.caddyfile"),
        r#"b.example.com {
	reverse_proxy localhost:8080
}
"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

    let table = parse_dir(dir.path()).unwrap();
    assert_eq!(table.hosts.len(), 2);
}

#[test]
fn parse_file_reports_invalid_syntax() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(&path, "example.com {\n\tfile_server\n").unwrap();

    let err = parse_file(&path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("parsing"),
        "error should mention parsing: {msg}"
    );
}

#[test]
fn parse_file_reports_missing_file() {
    let path = Path::new("/does/not/exist/Caddyfile");
    let err = parse_file(path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("reading"),
        "error should mention reading: {msg}"
    );
}
