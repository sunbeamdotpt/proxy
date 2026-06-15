// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 socket manager.
//!
//! Owns the public TCP/UDP listeners, runs on a dedicated OS thread + Tokio
//! runtime, and dispatches accepted connections and UDP packets to a router.

use crate::ir::compile::{CompiledL4Config, CompiledListener};
use crate::ir::Protocol;
use crate::l4::context::L4Context;
use crate::l4::udp::DualStackUdpSocket;
use crate::l4::{L4Router, SharedState};
use crate::tls::TlsRegistry;
use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

/// Handle to an L4 socket manager running on its own thread.
#[derive(Clone, Debug)]
pub struct L4SocketManagerHandle {
    tx: mpsc::Sender<Arc<CompiledL4Config>>,
}

impl L4SocketManagerHandle {
    /// Apply a new compiled L4 configuration.
    ///
    /// The manager diffs the new config against the active listeners, starting
    /// new binds and stopping removed ones.
    pub fn apply(&self, config: Arc<CompiledL4Config>) {
        let _ = self.tx.send(config);
    }
}

/// Spawn an L4 socket manager on a dedicated OS thread.
pub fn spawn<R: L4Router>(registry: Arc<TlsRegistry>, router: Arc<R>) -> L4SocketManagerHandle {
    let config = Arc::new(ArcSwap::from_pointee(CompiledL4Config::default()));
    spawn_with_config(registry, router, config)
}

/// Spawn an L4 socket manager sharing the given atomic L4 config.
///
/// The manager stores incoming configs into `config`, so routers and other
/// consumers that hold a clone of the same `ArcSwap` see updates immediately.
pub fn spawn_with_config<R: L4Router>(
    registry: Arc<TlsRegistry>,
    router: Arc<R>,
    config: Arc<ArcSwap<CompiledL4Config>>,
) -> L4SocketManagerHandle {
    let (tx, rx) = mpsc::channel::<Arc<CompiledL4Config>>();

    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "l4 manager: failed to create tokio runtime");
                return;
            }
        };

        let shared = Arc::new(SharedState { config, registry });

        runtime.block_on(run_manager(rx, router, shared));
    });

    L4SocketManagerHandle { tx }
}

struct ListenerHandle {
    config: CompiledListener,
    shutdown: watch::Sender<()>,
    task: JoinHandle<()>,
}

async fn run_manager<R: L4Router>(
    rx: mpsc::Receiver<Arc<CompiledL4Config>>,
    router: Arc<R>,
    shared: Arc<SharedState>,
) {
    let mut active: HashMap<Arc<str>, ListenerHandle> = HashMap::new();
    let mut current: Arc<CompiledL4Config> = Arc::new(CompiledL4Config::default());

    while let Ok(config) = rx.recv() {
        // Drain pending updates; only the latest snapshot matters.
        let mut latest = config;
        while let Ok(c) = rx.try_recv() {
            latest = c;
        }

        if *current == *latest {
            continue;
        }
        current = latest;
        shared.config.store(Arc::clone(&current));
        tracing::info!(
            listeners = current.listeners.len(),
            http_routes = current.http_routes.len(),
            https_routes = current.https_routes.len(),
            "l4 manager: applied compiled config"
        );

        let desired_map: HashMap<Arc<str>, &CompiledListener> = current
            .listeners
            .iter()
            .map(|l| (Arc::clone(&l.id), l))
            .collect();

        // Stop listeners whose id disappeared or whose configuration changed.
        // Waiting for the task to exit ensures the socket is released before a
        // replacement binds the same address.
        let mut removed_tasks = Vec::new();
        let mut kept_handles = Vec::new();
        for (id, handle) in active.drain() {
            let keep = desired_map
                .get(&id)
                .map(|l| {
                    l.bind_addr == handle.config.bind_addr && l.protocol == handle.config.protocol
                })
                .unwrap_or(false);
            if keep {
                kept_handles.push((id, handle));
                continue;
            }
            let _ = handle.shutdown.send(());
            removed_tasks.push((id, handle.task));
        }
        for (id, handle) in kept_handles {
            active.insert(id, handle);
        }
        for (id, task) in removed_tasks {
            if timeout(Duration::from_secs(5), task).await.is_err() {
                tracing::warn!(listener_id = %id, "l4 manager: listener task did not stop in time");
            }
        }

        // Start listeners that are not yet active (or were restarted above).
        for listener in &current.listeners {
            if active.contains_key(&listener.id) {
                continue;
            }
            let (shutdown_tx, shutdown_rx) = watch::channel(());
            let config = listener.clone();
            let task = spawn_listener_task(
                config.clone(),
                Arc::clone(&router),
                Arc::clone(&shared),
                shutdown_rx,
            );
            active.insert(
                Arc::clone(&listener.id),
                ListenerHandle {
                    config,
                    shutdown: shutdown_tx,
                    task,
                },
            );
        }
    }
}

fn spawn_listener_task<R: L4Router>(
    listener: CompiledListener,
    router: Arc<R>,
    _shared: Arc<SharedState>,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        match listener.protocol {
            Protocol::Tcp | Protocol::Tls | Protocol::Https => {
                let tcp = match TcpListener::bind(listener.bind_addr.as_ref()).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            listener_id = %listener.id,
                            error = %e,
                            "l4 manager: tcp bind failed"
                        );
                        return;
                    }
                };

                loop {
                    let accept = tcp.accept();
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        res = accept => {
                            match res {
                                Ok((stream, _peer)) => {
                                    let ctx = match L4Context::from_tcp_stream(
                                        Arc::clone(&listener.id),
                                        listener.protocol,
                                        &stream,
                                    ) {
                                        Ok(ctx) => ctx,
                                        Err(e) => {
                                            tracing::debug!(error = %e, "l4 manager: tcp context failed");
                                            continue;
                                        }
                                    };
                                    let router = Arc::clone(&router);
                                    tokio::spawn(async move {
                                        router.handle_tcp(ctx, stream).await;
                                    });
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "l4 manager: accept failed");
                                }
                            }
                        }
                    }
                }
            }
            Protocol::Udp => {
                let udp = match DualStackUdpSocket::bind(listener.bind_addr.as_ref()).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            listener_id = %listener.id,
                            error = %e,
                            "l4 manager: udp bind failed"
                        );
                        return;
                    }
                };

                let local_addr = match udp.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(
                            listener_id = %listener.id,
                            error = %e,
                            "l4 manager: udp local_addr failed"
                        );
                        return;
                    }
                };

                let socket = Arc::new(udp);
                let mut buf = vec![0u8; 65535];
                loop {
                    let recv = socket.recv_from(&mut buf);
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        res = recv => {
                            match res {
                                Ok((len, peer)) => {
                                    let packet = bytes::Bytes::copy_from_slice(&buf[..len]);
                                    let ctx = L4Context::from_udp(
                                        Arc::clone(&listener.id),
                                        local_addr,
                                        peer,
                                        listener.protocol,
                                    );
                                    let router = Arc::clone(&router);
                                    let socket = Arc::clone(&socket);
                                    tokio::spawn(async move {
                                        router.handle_udp(ctx, packet, peer, socket).await;
                                    });
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "l4 manager: udp recv failed");
                                }
                            }
                        }
                    }
                }
            }
            Protocol::Http => {
                // Plain HTTP listeners are bound here and relayed to the internal
                // Pingora plaintext address. This lets Gateway API HTTP listeners
                // use arbitrary ports without conflicting with Pingora's static
                // listen configuration.
                let tcp = match TcpListener::bind(listener.bind_addr.as_ref()).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            listener_id = %listener.id,
                            error = %e,
                            "l4 manager: http bind failed"
                        );
                        return;
                    }
                };

                loop {
                    let accept = tcp.accept();
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        res = accept => {
                            match res {
                                Ok((stream, _peer)) => {
                                    let ctx = match L4Context::from_tcp_stream(
                                        Arc::clone(&listener.id),
                                        listener.protocol,
                                        &stream,
                                    ) {
                                        Ok(ctx) => ctx,
                                        Err(e) => {
                                            tracing::debug!(error = %e, "l4 manager: http context failed");
                                            continue;
                                        }
                                    };
                                    let router = Arc::clone(&router);
                                    tokio::spawn(async move {
                                        router.handle_tcp(ctx, stream).await;
                                    });
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "l4 manager: http accept failed");
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Listener id diff: `(added, removed, unchanged)`.
pub type ListenerDiff<'a> = (Vec<&'a Arc<str>>, Vec<&'a Arc<str>>, Vec<&'a Arc<str>>);

/// Compute listener id diff for tests and diagnostics.
pub fn compute_diff<'a>(
    current: &HashSet<&'a Arc<str>>,
    desired: &HashSet<&'a Arc<str>>,
) -> ListenerDiff<'a> {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();

    for id in desired {
        if current.contains(id) {
            unchanged.push(*id);
        } else {
            added.push(*id);
        }
    }
    for id in current {
        if !desired.contains(id) {
            removed.push(*id);
        }
    }

    (added, removed, unchanged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::compile::CompiledListener;
    use crate::ir::Protocol;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpStream, UdpSocket};

    fn reserve_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn reserve_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    }

    fn tcp_listener(id: &str, port: u16) -> CompiledListener {
        CompiledListener {
            id: id.into(),
            bind_addr: format!("127.0.0.1:{}", port).into(),
            protocol: Protocol::Tcp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        }
    }

    fn udp_listener(id: &str, port: u16) -> CompiledListener {
        CompiledListener {
            id: id.into(),
            bind_addr: format!("127.0.0.1:{}", port).into(),
            protocol: Protocol::Udp,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        }
    }

    #[test]
    fn diff_adds_removes_and_unchanged() {
        let a: Arc<str> = "a".into();
        let b: Arc<str> = "b".into();
        let c: Arc<str> = "c".into();

        let current: HashSet<&Arc<str>> = [&a, &b].into_iter().collect();
        let desired: HashSet<&Arc<str>> = [&b, &c].into_iter().collect();

        let (added, removed, unchanged) = compute_diff(&current, &desired);
        assert_eq!(added, vec![&c]);
        assert_eq!(removed, vec![&a]);
        assert_eq!(unchanged, vec![&b]);
    }

    #[test]
    fn diff_empty_is_all_added() {
        let a: Arc<str> = "a".into();
        let desired: HashSet<&Arc<str>> = [&a].into_iter().collect();
        let (added, removed, unchanged) = compute_diff(&HashSet::new(), &desired);
        assert_eq!(added, vec![&a]);
        assert!(removed.is_empty());
        assert!(unchanged.is_empty());
    }

    #[tokio::test]
    async fn manager_binds_tcp_and_udp_listeners() {
        let tcp_port = reserve_tcp_port();
        let udp_port = reserve_udp_port();

        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        let config = Arc::new(CompiledL4Config {
            listeners: vec![
                tcp_listener("tcp-l", tcp_port),
                udp_listener("udp-l", udp_port),
            ],
            ..Default::default()
        });
        mgr.apply(config);

        // Wait for binds.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // TCP connect.
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();

        // UDP send.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(b"hello", format!("127.0.0.1:{}", udp_port))
            .await
            .unwrap();
    }

    fn http_listener(id: &str, port: u16) -> CompiledListener {
        CompiledListener {
            id: id.into(),
            bind_addr: format!("127.0.0.1:{}", port).into(),
            protocol: Protocol::Http,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        }
    }

    #[tokio::test]
    async fn apply_removes_listener() {
        let tcp_port = reserve_tcp_port();

        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        mgr.apply(Arc::new(CompiledL4Config {
            listeners: vec![tcp_listener("tcp-l", tcp_port)],
            ..Default::default()
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_ok());

        mgr.apply(Arc::new(CompiledL4Config::default()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn apply_keeps_listener_when_bind_and_protocol_unchanged() {
        let tcp_port = reserve_tcp_port();

        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        mgr.apply(Arc::new(CompiledL4Config {
            listeners: vec![tcp_listener("tcp-l", tcp_port)],
            ..Default::default()
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_ok());

        // Apply a new config with the same listener id/bind/protocol but a
        // different per-listener setting. The existing socket should be kept.
        mgr.apply(Arc::new(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "tcp-l".into(),
                bind_addr: format!("127.0.0.1:{}", tcp_port).into(),
                protocol: Protocol::Tcp,
                tls: None,
                redirect_http_to_https: true,
                frontend_validation: None,
            }],
            ..Default::default()
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_ok());

        // Removing the listener should still release the socket.
        mgr.apply(Arc::new(CompiledL4Config::default()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn http_and_https_listeners_are_bound() {
        let http_port = reserve_tcp_port();
        let https_port = reserve_tcp_port();

        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        mgr.apply(Arc::new(CompiledL4Config {
            listeners: vec![
                http_listener("http-l", http_port),
                CompiledListener {
                    id: "https-l".into(),
                    bind_addr: format!("127.0.0.1:{}", https_port).into(),
                    protocol: Protocol::Https,
                    tls: None,
                    redirect_http_to_https: false,
                    frontend_validation: None,
                },
            ],
            ..Default::default()
        }));

        // Wait briefly to ensure the manager binds both sockets.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Plain HTTP listeners are now bound by the L4 manager and relayed to
        // the internal Pingora plaintext service.
        assert!(TcpStream::connect(format!("127.0.0.1:{}", http_port))
            .await
            .is_ok());
        // HTTPS listeners are bound by the L4 manager for TLS termination.
        assert!(TcpStream::connect(format!("127.0.0.1:{}", https_port))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn invalid_bind_addresses_are_handled_gracefully() {
        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        mgr.apply(Arc::new(CompiledL4Config {
            listeners: vec![
                CompiledListener {
                    id: "bad-tcp".into(),
                    bind_addr: "not-an-address:0".into(),
                    protocol: Protocol::Tcp,
                    tls: None,
                    redirect_http_to_https: false,
                    frontend_validation: None,
                },
                CompiledListener {
                    id: "bad-udp".into(),
                    bind_addr: "also-not-an-address:0".into(),
                    protocol: Protocol::Udp,
                    tls: None,
                    redirect_http_to_https: false,
                    frontend_validation: None,
                },
            ],
            ..Default::default()
        }));

        // Manager should survive invalid bind addresses.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn applying_identical_config_is_noop() {
        let tcp_port = reserve_tcp_port();

        let registry = Arc::new(TlsRegistry::new());
        let router = Arc::new(crate::l4::NoOpRouter);
        let mgr = spawn(registry, router);

        let config = Arc::new(CompiledL4Config {
            listeners: vec![tcp_listener("tcp-l", tcp_port)],
            ..Default::default()
        });
        mgr.apply(Arc::clone(&config));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_ok());

        // Applying the exact same snapshot should short-circuit and leave the
        // listener bound.
        mgr.apply(config);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .is_ok());
    }
}
