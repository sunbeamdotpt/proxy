// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! TLS passthrough router.
//!
//! Sits in front of Pingora's TLS listener on port 443.  For each inbound TCP
//! connection it peeks at the TLS ClientHello to extract the SNI hostname.
//! If the SNI matches a configured passthrough route the raw TCP stream is
//! relayed to the backend without TLS termination.  All other connections are
//! forwarded to Pingora's internal TLS listener for normal processing.

use std::net::SocketAddr;

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::config::TlsPassthroughRoute;
use crate::dual_stack::DualStackTcpListener;
use crate::sni;

/// Maximum bytes to peek from the TCP stream for SNI extraction.
/// A typical ClientHello is 200-500 bytes; 1536 covers edge cases with
/// many extensions or a large session ticket.
const PEEK_BUF_SIZE: usize = 1536;

/// Run the TLS passthrough router.  Listens on `listen_addr`, peeks SNI,
/// and routes to either a passthrough backend or `pingora_internal_addr`.
///
/// Runs forever; spawn on a dedicated OS thread + Tokio runtime.
pub async fn run(listen_addr: &str, routes: &[TlsPassthroughRoute], pingora_internal_addr: &str) {
    let port = listen_addr.rsplit(':').next().unwrap_or("443");
    let ipv6_addr = format!("[::]:{port}");
    let ipv4_addr = format!("0.0.0.0:{port}");

    let listener = match DualStackTcpListener::bind(&ipv6_addr, &ipv4_addr).await {
        Ok(l) => {
            tracing::info!(
                %listen_addr,
                passthrough_routes = routes.len(),
                %pingora_internal_addr,
                "TLS passthrough router listening (dual-stack)"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, %listen_addr, "TLS passthrough: bind failed");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let routes = routes.to_vec();
                let pingora_addr = pingora_internal_addr.to_string();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(socket, peer_addr, &routes, &pingora_addr).await
                    {
                        tracing::debug!(error = %e, %peer_addr, "tls_passthrough: connection ended");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "tls_passthrough: accept failed");
            }
        }
    }
}

fn find_passthrough_route<'a>(
    sni_host: &str,
    routes: &'a [TlsPassthroughRoute],
) -> Option<&'a TlsPassthroughRoute> {
    let prefix = sni_host.split('.').next().unwrap_or("");
    routes.iter().find(|r| r.host_prefix == prefix)
}

/// Pure decision helper: given a peeked ClientHello buffer, return the matching
/// passthrough route (if any).  This is the testable core of `handle_connection`.
fn resolve_passthrough_route<'a>(
    buf: &[u8],
    routes: &'a [TlsPassthroughRoute],
) -> Option<&'a TlsPassthroughRoute> {
    sni::parse_client_hello_sni(buf).and_then(|sni| find_passthrough_route(sni, routes))
}

async fn handle_connection(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    routes: &[TlsPassthroughRoute],
    pingora_addr: &str,
) -> Result<(), std::io::Error> {
    // Peek at the ClientHello without consuming the bytes.
    let mut buf = [0u8; PEEK_BUF_SIZE];
    let n = socket.peek(&mut buf).await?;

    if let Some(route) = resolve_passthrough_route(&buf[..n], routes) {
        let sni_host = sni::parse_client_hello_sni(&buf[..n]).unwrap_or("");
        tracing::info!(
            %peer_addr,
            sni = %sni_host,
            backend = %route.backend,
            "tls_passthrough: routing to passthrough backend"
        );
        let mut upstream = TcpStream::connect(&route.backend).await?;
        copy_bidirectional(&mut socket, &mut upstream).await?;
        return Ok(());
    }

    // No passthrough match — forward to Pingora's internal TLS listener.
    let mut pingora = TcpStream::connect(pingora_addr).await?;
    copy_bidirectional(&mut socket, &mut pingora).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn find_matching_route() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "127.0.0.1:1234".to_string(),
        }];
        // Simulate what handle_connection does
        let sni = "build.sunbeam.pt";
        let prefix = sni.split('.').next().unwrap();
        assert!(routes.iter().any(|r| r.host_prefix == prefix));

        let sni = "docs.sunbeam.pt";
        let prefix = sni.split('.').next().unwrap();
        assert!(!routes.iter().any(|r| r.host_prefix == prefix));
    }

    #[test]
    fn test_find_passthrough_route_match() {
        let routes = vec![
            TlsPassthroughRoute {
                host_prefix: "build".to_string(),
                backend: "10.0.0.1:22".to_string(),
            },
            TlsPassthroughRoute {
                host_prefix: "git".to_string(),
                backend: "10.0.0.2:22".to_string(),
            },
        ];

        let matched = find_passthrough_route("build.sunbeam.pt", &routes);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().backend, "10.0.0.1:22");
    }

    #[test]
    fn test_find_passthrough_route_no_match() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];

        assert!(find_passthrough_route("docs.sunbeam.pt", &routes).is_none());
    }

    #[test]
    fn test_find_passthrough_route_empty_sni() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];

        let matched = find_passthrough_route("", &routes);
        assert!(matched.is_some());
    }

    #[test]
    fn test_find_passthrough_route_first_match_wins() {
        let routes = vec![
            TlsPassthroughRoute {
                host_prefix: "build".to_string(),
                backend: "10.0.0.1:22".to_string(),
            },
            TlsPassthroughRoute {
                host_prefix: "build".to_string(),
                backend: "10.0.0.2:22".to_string(),
            },
        ];

        let matched = find_passthrough_route("build.sunbeam.pt", &routes);
        assert_eq!(matched.unwrap().backend, "10.0.0.1:22");
    }

    #[test]
    fn test_find_passthrough_route_no_dot_in_sni() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];

        let matched = find_passthrough_route("build", &routes);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().backend, "10.0.0.1:22");
    }

    #[test]
    fn test_find_passthrough_route_empty_routes() {
        assert!(find_passthrough_route("build.sunbeam.pt", &[]).is_none());
    }

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // Random
        ch.push(0x00); // Session ID length
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // Compression

        let mut exts = Vec::new();
        let name_bytes = sni.as_bytes();
        let name_len = name_bytes.len() as u16;
        let entry_len = 1 + 2 + name_len;
        let sni_data_len = 2 + entry_len;
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        exts.extend_from_slice(&((entry_len) as u16).to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(name_bytes);

        let ext_len = exts.len() as u16;
        ch.extend_from_slice(&ext_len.to_be_bytes());
        ch.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let ch_len = ch.len() as u32;
        hs.push((ch_len >> 16) as u8);
        hs.push((ch_len >> 8) as u8);
        hs.push(ch_len as u8);
        hs.extend_from_slice(&ch);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        let hs_len = hs.len() as u16;
        record.extend_from_slice(&hs_len.to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn test_resolve_passthrough_route_match() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];
        let buf = build_client_hello("build.sunbeam.pt");
        let matched = resolve_passthrough_route(&buf, &routes);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().backend, "10.0.0.1:22");
    }

    #[test]
    fn test_resolve_passthrough_route_no_match() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];
        let buf = build_client_hello("docs.sunbeam.pt");
        assert!(resolve_passthrough_route(&buf, &routes).is_none());
    }

    #[test]
    fn test_resolve_passthrough_route_no_sni() {
        let routes = vec![TlsPassthroughRoute {
            host_prefix: "build".to_string(),
            backend: "10.0.0.1:22".to_string(),
        }];
        assert!(resolve_passthrough_route(b"not tls", &routes).is_none());
    }

    #[tokio::test]
    async fn test_run_returns_on_bind_failure() {
        // An invalid address with a non-numeric port forces bind() to fail,
        // covering the early-return error path in run().
        let routes: Vec<TlsPassthroughRoute> = Vec::new();
        run("127.0.0.1:not-a-port", &routes, "127.0.0.1:18889").await;
    }

    #[tokio::test]
    async fn test_handle_connection_forwards_to_pingora() {
        // Proxy listener.
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        // Pingora backend listener.
        let pingora_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pingora_addr = pingora_listener.local_addr().unwrap().to_string();

        // Connect a client to the proxy side and send data *before* the proxy
        // accepts, so handle_connection's initial peek sees bytes instead of
        // blocking on an empty socket.
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"hello pingora").await.unwrap();
        client.shutdown().await.unwrap();

        // Accept on the proxy side and run handle_connection.
        let (proxy_socket, peer_addr) = proxy_listener.accept().await.unwrap();
        let routes: Vec<TlsPassthroughRoute> = Vec::new();
        let handle = tokio::spawn(async move {
            handle_connection(proxy_socket, peer_addr, &routes, &pingora_addr)
                .await
                .unwrap();
        });

        // Accept the forwarded connection on the Pingora side and verify data.
        let (mut pingora_side, _) = pingora_listener.accept().await.unwrap();
        let mut buf = Vec::new();
        pingora_side.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello pingora");

        // Close the Pingora side so copy_bidirectional can terminate.
        drop(pingora_side);

        // Wait for handle_connection to finish.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
