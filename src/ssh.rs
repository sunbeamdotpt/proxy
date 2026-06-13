// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::dual_stack::DualStackTcpListener;

/// Listens on `listen` and proxies every TCP connection to `backend`.
/// Runs forever; intended to be spawned on a dedicated OS thread + Tokio runtime,
/// matching the pattern used for the cert/ingress watcher.
/// Normalize a listen specifier into the IPv6 and IPv4 bind addresses used by
/// the TCP proxy.
fn normalize_listen_addrs(listen: &str) -> (String, String) {
    let ipv6_addr = if listen.starts_with('[') {
        listen.to_string()
    } else {
        format!("[::]:{}", listen.split(':').next_back().unwrap_or("22"))
    };

    let ipv4_addr = if listen.contains(':') {
        // Extract port from the original address
        let port = listen.split(':').next_back().unwrap_or("22");
        format!("0.0.0.0:{}", port)
    } else {
        "0.0.0.0:22".to_string()
    };

    (ipv6_addr, ipv4_addr)
}

pub async fn run_tcp_proxy(listen: &str, backend: &str) {
    let (ipv6_addr, ipv4_addr) = normalize_listen_addrs(listen);

    let listener = match DualStackTcpListener::bind(&ipv6_addr, &ipv4_addr).await {
        Ok(l) => {
            tracing::info!(%listen, %backend, "SSH TCP proxy listening (dual-stack)");
            l
        }
        Err(e) => {
            tracing::error!(error = %e, %listen, "SSH TCP proxy: bind failed");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut socket, peer_addr)) => {
                let backend = backend.to_string();
                tokio::spawn(async move {
                    match TcpStream::connect(&backend).await {
                        Ok(mut upstream) => {
                            if let Err(e) = copy_bidirectional(&mut socket, &mut upstream).await {
                                tracing::debug!(error = %e, %peer_addr, "ssh: session ended");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, %peer_addr, %backend, "ssh: upstream connect failed");
                        }
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "ssh: accept failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_plain_port() {
        let (v6, v4) = normalize_listen_addrs("2222");
        assert_eq!(v6, "[::]:2222");
        // A bare port is treated as an IPv6 listen address; IPv4 falls back to 22.
        assert_eq!(v4, "0.0.0.0:22");
    }

    #[test]
    fn normalize_ipv4_with_port() {
        let (v6, v4) = normalize_listen_addrs("0.0.0.0:2222");
        assert_eq!(v6, "[::]:2222");
        assert_eq!(v4, "0.0.0.0:2222");
    }

    #[test]
    fn normalize_ipv6_literal() {
        let (v6, v4) = normalize_listen_addrs("[::1]:2222");
        assert_eq!(v6, "[::1]:2222");
        assert_eq!(v4, "0.0.0.0:2222");
    }

    #[test]
    fn normalize_empty_defaults_to_22() {
        let (v6, v4) = normalize_listen_addrs("");
        assert_eq!(v6, "[::]:");
        assert_eq!(v4, "0.0.0.0:22");
    }
}
