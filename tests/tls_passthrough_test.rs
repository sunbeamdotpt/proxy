// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the TLS passthrough SNI router.
//!
//! Spins up real TCP listeners (SNI router, mock "Pingora internal", mock
//! passthrough backend) and sends actual TLS ClientHellos through the router
//! to verify correct routing behavior.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

use sunbeam_proxy::config::TlsPassthroughRoute;
use sunbeam_proxy::sni;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a minimal TLS ClientHello with the given SNI hostname.
/// Same logic as the unit test helper in sni.rs, extracted here for
/// integration tests.
fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut ch = Vec::new();

    // ProtocolVersion: TLS 1.2
    ch.extend_from_slice(&[0x03, 0x03]);
    // Random: 32 zero bytes
    ch.extend_from_slice(&[0u8; 32]);
    // Session ID: empty
    ch.push(0x00);
    // Cipher Suites: one suite
    ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    // Compression Methods: null
    ch.extend_from_slice(&[0x01, 0x00]);

    let mut exts = Vec::new();

    if let Some(hostname) = sni {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let entry_len = 1 + 2 + name_len;
        let sni_data_len = 2 + entry_len;

        exts.extend_from_slice(&[0x00, 0x00]); // SNI type
        exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
        exts.push(0x00); // hostname type
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(name_bytes);
    }

    // Dummy extension after SNI
    exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    // Handshake header
    let mut hs = vec![0x01];
    let ch_len = ch.len() as u32;
    hs.push((ch_len >> 16) as u8);
    hs.push((ch_len >> 8) as u8);
    hs.push(ch_len as u8);
    hs.extend_from_slice(&ch);

    // TLS record header
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);

    record
}

/// Start a TCP server that accepts one connection, reads up to 2048 bytes,
/// sends back a marker response, and returns the received bytes.
async fn echo_backend(marker: &'static [u8]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        let (mut socket, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timed out")
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let n = timeout(Duration::from_secs(2), socket.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        buf.truncate(n);

        let _ = socket.write_all(marker).await;
        socket.shutdown().await.ok();

        buf
    });

    (port, handle)
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// SNI matching a passthrough route → raw relay to backend.
/// The backend should receive the full ClientHello bytes (not TLS-terminated).
#[tokio::test]
async fn passthrough_route_relays_raw_tls_to_backend() {
    // Mock passthrough backend (what buildkitd would be)
    let (backend_port, backend_handle) = echo_backend(b"PASSTHROUGH_OK").await;

    // Mock Pingora internal (should NOT receive this connection)
    let pingora_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pingora_port = pingora_listener.local_addr().unwrap().port();

    // SNI router on a random port
    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router_port = router_listener.local_addr().unwrap().port();
    drop(router_listener); // Free the port for the router to bind

    let routes = vec![TlsPassthroughRoute {
        host_prefix: "build".to_string(),
        backend: format!("127.0.0.1:{backend_port}"),
    }];
    let pingora_addr = format!("127.0.0.1:{pingora_port}");
    let listen_addr = format!("0.0.0.0:{router_port}");

    // Spawn the SNI router
    let routes_clone = routes.clone();
    let pingora_clone = pingora_addr.clone();
    let listen_clone = listen_addr.clone();
    tokio::spawn(async move {
        sunbeam_proxy::tls_passthrough::run(&listen_clone, &routes_clone, &pingora_clone).await;
    });

    // Give the router time to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send a ClientHello with SNI "build.sunbeam.pt"
    let client_hello = build_client_hello(Some("build.sunbeam.pt"));
    let mut client = timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{router_port}")),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    client.write_all(&client_hello).await.unwrap();

    // Read the backend's marker response
    let mut resp = vec![0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut resp))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&resp[..n], b"PASSTHROUGH_OK");

    // Verify the backend received the raw ClientHello
    let received = timeout(Duration::from_secs(2), backend_handle)
        .await
        .expect("backend timed out")
        .unwrap();

    // The backend should have received our exact ClientHello bytes
    assert_eq!(
        received, client_hello,
        "backend should receive raw ClientHello"
    );

    // Verify the ClientHello is parseable
    assert_eq!(
        sni::parse_client_hello_sni(&received),
        Some("build.sunbeam.pt"),
    );
}

/// SNI not matching any passthrough route → forwarded to Pingora internal.
#[tokio::test]
async fn non_matching_sni_forwards_to_pingora() {
    // Mock Pingora internal
    let (pingora_port, pingora_handle) = echo_backend(b"PINGORA_OK").await;

    // SNI router
    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router_port = router_listener.local_addr().unwrap().port();
    drop(router_listener);

    let routes = vec![TlsPassthroughRoute {
        host_prefix: "build".to_string(),
        backend: "127.0.0.1:9999".to_string(), // won't be used
    }];
    let pingora_addr = format!("127.0.0.1:{pingora_port}");
    let listen_addr = format!("0.0.0.0:{router_port}");

    let routes_clone = routes.clone();
    let pingora_clone = pingora_addr.clone();
    let listen_clone = listen_addr.clone();
    tokio::spawn(async move {
        sunbeam_proxy::tls_passthrough::run(&listen_clone, &routes_clone, &pingora_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send a ClientHello with SNI "docs.sunbeam.pt" — not a passthrough route
    let client_hello = build_client_hello(Some("docs.sunbeam.pt"));
    let mut client = timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{router_port}")),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    client.write_all(&client_hello).await.unwrap();

    let mut resp = vec![0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut resp))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&resp[..n], b"PINGORA_OK");

    // Verify Pingora received the raw ClientHello (for TLS termination)
    let received = timeout(Duration::from_secs(2), pingora_handle)
        .await
        .expect("pingora timed out")
        .unwrap();

    assert_eq!(received, client_hello);
}

/// No SNI in the ClientHello → falls through to Pingora.
#[tokio::test]
async fn no_sni_falls_through_to_pingora() {
    let (pingora_port, pingora_handle) = echo_backend(b"PINGORA_NOSNI").await;

    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router_port = router_listener.local_addr().unwrap().port();
    drop(router_listener);

    let routes = vec![TlsPassthroughRoute {
        host_prefix: "build".to_string(),
        backend: "127.0.0.1:9999".to_string(),
    }];
    let pingora_addr = format!("127.0.0.1:{pingora_port}");
    let listen_addr = format!("0.0.0.0:{router_port}");

    let routes_clone = routes.clone();
    let pingora_clone = pingora_addr.clone();
    let listen_clone = listen_addr.clone();
    tokio::spawn(async move {
        sunbeam_proxy::tls_passthrough::run(&listen_clone, &routes_clone, &pingora_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // ClientHello with no SNI extension
    let client_hello = build_client_hello(None);
    let mut client = timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{router_port}")),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    client.write_all(&client_hello).await.unwrap();

    let mut resp = vec![0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut resp))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&resp[..n], b"PINGORA_NOSNI");

    let received = timeout(Duration::from_secs(2), pingora_handle)
        .await
        .expect("pingora timed out")
        .unwrap();

    assert_eq!(received, client_hello);
}

/// Non-TLS garbage data → forwarded to Pingora (which will reject it).
#[tokio::test]
async fn garbage_data_forwards_to_pingora() {
    let (pingora_port, pingora_handle) = echo_backend(b"PINGORA_GARBAGE").await;

    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router_port = router_listener.local_addr().unwrap().port();
    drop(router_listener);

    let routes = vec![TlsPassthroughRoute {
        host_prefix: "build".to_string(),
        backend: "127.0.0.1:9999".to_string(),
    }];
    let pingora_addr = format!("127.0.0.1:{pingora_port}");
    let listen_addr = format!("0.0.0.0:{router_port}");

    let routes_clone = routes.clone();
    let pingora_clone = pingora_addr.clone();
    let listen_clone = listen_addr.clone();
    tokio::spawn(async move {
        sunbeam_proxy::tls_passthrough::run(&listen_clone, &routes_clone, &pingora_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send plain HTTP (not TLS at all)
    let garbage = b"GET / HTTP/1.1\r\nHost: build.sunbeam.pt\r\n\r\n";
    let mut client = timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{router_port}")),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    client.write_all(garbage).await.unwrap();

    let mut resp = vec![0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut resp))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&resp[..n], b"PINGORA_GARBAGE");

    let received = timeout(Duration::from_secs(2), pingora_handle)
        .await
        .expect("pingora timed out")
        .unwrap();

    assert_eq!(&received[..], &garbage[..]);
}

/// Verify the SNI parser works on a real rustls ClientHello (not hand-crafted).
#[tokio::test]
async fn real_rustls_client_hello_passthrough() {
    let (backend_port, backend_handle) = echo_backend(b"REAL_TLS_OK").await;

    let pingora_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pingora_port = pingora_listener.local_addr().unwrap().port();

    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router_port = router_listener.local_addr().unwrap().port();
    drop(router_listener);

    let routes = vec![TlsPassthroughRoute {
        host_prefix: "build".to_string(),
        backend: format!("127.0.0.1:{backend_port}"),
    }];
    let pingora_addr = format!("127.0.0.1:{pingora_port}");
    let listen_addr = format!("0.0.0.0:{router_port}");

    let routes_clone = routes.clone();
    let pingora_clone = pingora_addr.clone();
    let listen_clone = listen_addr.clone();
    tokio::spawn(async move {
        sunbeam_proxy::tls_passthrough::run(&listen_clone, &routes_clone, &pingora_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Use a real rustls client to generate a genuine ClientHello.
    // The TLS handshake will fail (backend isn't TLS), but the router should
    // still relay the ClientHello bytes to the backend before that happens.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let root_store = rustls::RootCertStore::empty();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from("build.sunbeam.pt").unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{router_port}")),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    // The TLS handshake will fail since the backend isn't a TLS server,
    // but that's fine — we just need the ClientHello to reach the backend.
    let _ = timeout(Duration::from_secs(2), connector.connect(server_name, tcp)).await;

    // Check what the backend received
    let received = timeout(Duration::from_secs(2), backend_handle)
        .await
        .expect("backend timed out")
        .unwrap();

    // The backend should have received a valid ClientHello with our SNI
    assert!(
        !received.is_empty(),
        "backend should have received data from the real TLS client"
    );
    assert_eq!(
        sni::parse_client_hello_sni(&received),
        Some("build.sunbeam.pt"),
        "should parse SNI from real rustls ClientHello"
    );
}
