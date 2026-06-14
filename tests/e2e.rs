// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests: spin up a real SunbeamProxy over plain HTTP, route it
//! to a tiny TCP echo-backend, and verify that the upstream receives the
//! correct X-Forwarded-Proto header.
//!
//! The proxy is started once per process in a background thread (Pingora's
//! `run_forever()` never returns, which is fine — the OS cleans everything up
//! when the test binary exits).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use pingora::server::{configuration::Opt, Server};
use pingora_proxy::http_proxy_service;
use sunbeam_proxy::{acme::AcmeRoutes, config::RouteConfig, proxy::SunbeamProxy};

/// HTTP port the test proxy listens on.  Must not conflict with other services
/// on the CI machine; kept in the ephemeral-but-not-kernel-reserved range.
const PROXY_PORT: u16 = 18_889;

// ── Echo backend ─────────────────────────────────────────────────────────────

/// Start a one-shot HTTP echo server on a random OS-assigned port.
///
/// Accepts exactly one connection, records every request header (lower-cased),
/// returns 200 OK, then exits the thread.  The captured headers are delivered
/// via the returned `Receiver`.
fn start_echo_backend() -> (u16, std::sync::mpsc::Receiver<HashMap<String, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo backend");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Clone for the BufReader so we can write the response on the original.
        let reader_stream = stream.try_clone().expect("clone stream");
        let mut reader = BufReader::new(reader_stream);
        let mut headers = HashMap::new();
        let mut skip_first = true; // first line is the request line, not a header

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break; // EOF before blank line
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if skip_first {
                skip_first = false;
                continue;
            }
            if trimmed.is_empty() {
                break; // end of HTTP headers
            }
            if let Some((k, v)) = trimmed.split_once(": ") {
                headers.insert(k.to_lowercase(), v.to_string());
            }
        }

        let _ = tx.send(headers);
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });

    (port, rx)
}

// ── Proxy startup ─────────────────────────────────────────────────────────────

/// Poll `PROXY_PORT` until it accepts a connection (proxy is ready) or 5 s elapses.
fn wait_for_proxy() {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", PROXY_PORT)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("proxy did not start on port {PROXY_PORT} within 5 s");
}

/// Start a `SunbeamProxy` that routes `Host: test.*` to `backend_port`.
///
/// Guarded by `std::sync::Once` so the background thread is started at most
/// once per test-binary process, regardless of how many tests call this.
fn start_proxy_once(backend_port: u16) {
    static PROXY_ONCE: std::sync::Once = std::sync::Once::new();
    PROXY_ONCE.call_once(|| {
        // rustls 0.23 requires an explicit crypto provider.  Ignore the error
        // in case another test (or the host binary) already installed one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let routes = vec![RouteConfig {
            host_prefix: "test".to_string(),
            backend: format!("http://127.0.0.1:{backend_port}"),
            websocket: false,
            // Allow plain-HTTP requests through so we can test header forwarding
            // without needing TLS certificates in the test environment.
            disable_secure_redirection: true,
            paths: vec![],
            static_root: None,
            fallback: None,
            rewrites: vec![],
            body_rewrites: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            cache: None,
            cors: None,
            timeout_secs: None,
            listener_hostname: None,
            gateway_api: false,
        }];
        let acme_routes: AcmeRoutes = Arc::new(RwLock::new(HashMap::new()));
        let ir = sunbeam_proxy::ir::from_config::from_route_configs(&routes);
        let table = sunbeam_proxy::ir::compile::CompiledRouteTable::compile(ir).expect("compile");
        let compiled_rewrites = SunbeamProxy::compile_rewrites_from_ir(&table);
        let l4_config = Arc::new(arc_swap::ArcSwap::from_pointee(
            sunbeam_proxy::ir::compile::CompiledL4Config::default(),
        ));
        let sni_context = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let http_context = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let proxy = SunbeamProxy {
            routes: Arc::new(arc_swap::ArcSwap::from_pointee(table)),
            l4_config,
            sni_context,
            http_context,
            acme_routes,
            ddos_detector: None,
            scanner_detector: None,
            bot_allowlist: None,
            rate_limiter: None,
            compiled_rewrites: Arc::new(arc_swap::ArcSwap::from_pointee(compiled_rewrites)),
            http_client: reqwest::Client::new(),
            pipeline_bypass_cidrs: vec![],
            trusted_proxy_cidrs: vec![],
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,

            ..Default::default()
        };

        let opt = Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        };

        thread::spawn(move || {
            let mut server = Server::new(Some(opt)).expect("create server");
            server.bootstrap();
            let mut svc = http_proxy_service(&server.configuration, proxy);
            // HTTP only — no TLS cert files needed.
            svc.add_tcp(&format!("127.0.0.1:{PROXY_PORT}"));
            server.add_service(svc);
            server.run_forever(); // blocks this thread forever
        });

        wait_for_proxy();
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A plain-HTTP request routed through the proxy must arrive at the backend
/// with `x-forwarded-proto: http`.
#[test]
fn test_plain_http_request_carries_x_forwarded_proto() {
    let (backend_port, rx) = start_echo_backend();
    start_proxy_once(backend_port);

    // Send a minimal HTTP/1.1 request.  `Host: test.local` → prefix "test"
    // matches the route configured above.
    let mut conn = TcpStream::connect(("127.0.0.1", PROXY_PORT)).expect("connect to proxy");
    conn.write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
        .expect("write request");

    // Drain the proxy response so the TCP handshake can close cleanly.
    let mut _resp = Vec::new();
    let _ = conn.read_to_end(&mut _resp);

    let headers = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("backend did not receive a request within 5 s");

    assert_eq!(
        headers.get("x-forwarded-proto").map(String::as_str),
        Some("http"),
        "expected x-forwarded-proto: http in upstream headers; got: {headers:?}",
    );
}
