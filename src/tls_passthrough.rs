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
pub async fn run(
    listen_addr: &str,
    routes: &[TlsPassthroughRoute],
    pingora_internal_addr: &str,
) {
    let port = listen_addr
        .rsplit(':')
        .next()
        .unwrap_or("443");
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
                    if let Err(e) = handle_connection(socket, peer_addr, &routes, &pingora_addr).await {
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

async fn handle_connection(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    routes: &[TlsPassthroughRoute],
    pingora_addr: &str,
) -> Result<(), std::io::Error> {
    // Peek at the ClientHello without consuming the bytes.
    let mut buf = [0u8; PEEK_BUF_SIZE];
    let n = socket.peek(&mut buf).await?;

    if let Some(sni_host) = sni::parse_client_hello_sni(&buf[..n]) {
        let prefix = sni_host.split('.').next().unwrap_or("");

        if let Some(route) = routes.iter().find(|r| r.host_prefix == prefix) {
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
    }

    // No passthrough match — forward to Pingora's internal TLS listener.
    let mut pingora = TcpStream::connect(pingora_addr).await?;
    copy_bidirectional(&mut socket, &mut pingora).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_matching_route() {
        let routes = vec![
            TlsPassthroughRoute {
                host_prefix: "build".to_string(),
                backend: "127.0.0.1:1234".to_string(),
            },
        ];
        // Simulate what handle_connection does
        let sni = "build.sunbeam.pt";
        let prefix = sni.split('.').next().unwrap();
        assert!(routes.iter().any(|r| r.host_prefix == prefix));

        let sni = "docs.sunbeam.pt";
        let prefix = sni.split('.').next().unwrap();
        assert!(!routes.iter().any(|r| r.host_prefix == prefix));
    }
}
