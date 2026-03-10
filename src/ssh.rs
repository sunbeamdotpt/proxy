use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

/// Listens on `listen` and proxies every TCP connection to `backend`.
/// Runs forever; intended to be spawned on a dedicated OS thread + Tokio runtime,
/// matching the pattern used for the cert/ingress watcher.
pub async fn run_tcp_proxy(listen: &str, backend: &str) {
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => {
            tracing::info!(%listen, %backend, "SSH TCP proxy listening");
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
