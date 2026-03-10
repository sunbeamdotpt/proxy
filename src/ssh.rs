use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::dual_stack::DualStackTcpListener;

/// Listens on `listen` and proxies every TCP connection to `backend`.
/// Runs forever; intended to be spawned on a dedicated OS thread + Tokio runtime,
/// matching the pattern used for the cert/ingress watcher.
pub async fn run_tcp_proxy(listen: &str, backend: &str) {
    // Parse the listen address to determine if it's IPv6 or IPv4
    let ipv6_addr = if listen.starts_with('[') {
        listen.to_string()
    } else {
        format!("[::]:{}", listen.split(':').last().unwrap_or("22"))
    };
    
    let ipv4_addr = if listen.contains(':') {
        // Extract port from the original address
        let port = listen.split(':').last().unwrap_or("22");
        format!("0.0.0.0:{}", port)
    } else {
        "0.0.0.0:22".to_string()
    };

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
