// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 router implementation.
//!
//! Matches TCP/UDP/TLS passthrough routes from the compiled L4 configuration and
//! relays traffic to weighted backends.

use crate::ir::compile::{
    CompiledL4Config, CompiledL4Route, CompiledListener, ir_hostname_matches,
    ir_listener_specificity_score,
};
use crate::ir::{L4Action, L4Match, Protocol, WeightedBackend};
use crate::l4::L4Router;
use crate::l4::context::L4Context;
use crate::l4::udp::DualStackUdpSocket;
use crate::tls::TlsRegistry;
use async_trait::async_trait;
use bytes::Bytes;
use rand::distr::Distribution;
use rand::distr::weighted::WeightedIndex;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

/// Maximum bytes to peek from a TCP stream for SNI extraction: the largest
/// possible TLS record (16384) plus its 5-byte header. TLS 1.3 ClientHellos
/// with post-quantum key shares exceed smaller buffers.
const PEEK_BUF_SIZE: usize = 16389;

/// Overall timeout for waiting on a fragmented ClientHello.
const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Default timeout for UDP relay responses.
const UDP_RELAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Router that executes compiled L4 routes.
#[derive(Clone, Debug)]
pub struct Router {
    config: Arc<arc_swap::ArcSwap<CompiledL4Config>>,
    registry: Arc<TlsRegistry>,
    sni_context: Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<str>>>>,
    http_context: Arc<std::sync::Mutex<HashMap<SocketAddr, crate::l4::context::HttpRelayContext>>>,
}

impl Router {
    /// Create a router backed by the given atomic L4 config, TLS registry, and
    /// SNI propagation context.
    pub fn new(
        config: Arc<arc_swap::ArcSwap<CompiledL4Config>>,
        registry: Arc<TlsRegistry>,
        sni_context: Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<str>>>>,
    ) -> Self {
        Self {
            config,
            registry,
            sni_context,
            http_context: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Create a router with an explicit HTTP relay context map. Used by tests
    /// and by the binary to share the same map with the HTTP proxy.
    pub fn new_with_http_context(
        config: Arc<arc_swap::ArcSwap<CompiledL4Config>>,
        registry: Arc<TlsRegistry>,
        sni_context: Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<str>>>>,
        http_context: Arc<
            std::sync::Mutex<HashMap<SocketAddr, crate::l4::context::HttpRelayContext>>,
        >,
    ) -> Self {
        Self {
            config,
            registry,
            sni_context,
            http_context,
        }
    }

    /// Resolve the current compiled configuration.
    fn config(&self) -> arc_swap::Guard<Arc<CompiledL4Config>> {
        self.config.load()
    }
}

/// Peek the ClientHello, waiting until the full first TLS record has arrived.
///
/// A single `peek()` can return a fragmented hello (slow or lossy clients),
/// which used to fail SNI extraction and drop the connection. Peek does not
/// consume, so each retry sees every byte received so far.
async fn peek_client_hello_sni(stream: &TcpStream) -> Option<Arc<str>> {
    timeout(SNI_PEEK_TIMEOUT, async {
        let mut buf = [0u8; PEEK_BUF_SIZE];
        loop {
            let n = stream.peek(&mut buf).await.ok()?;
            let data = &buf[..n];
            match data.first() {
                // Orderly shutdown before any bytes.
                None => return None,
                Some(&0x16) => {}
                // Not a TLS handshake — fail fast instead of waiting.
                Some(_) => return None,
            }
            if let Some(total) = crate::sni::record_total_len(data)
                && n >= total.min(PEEK_BUF_SIZE)
            {
                return crate::sni::parse_client_hello_sni(data).map(Arc::from);
            }
            // Incomplete record — wait for more bytes and peek again.
            if stream.readable().await.is_err() {
                return None;
            }
        }
    })
    .await
    .ok()
    .flatten()
}

#[async_trait]
impl L4Router for Router {
    async fn handle_tcp(&self, ctx: L4Context, stream: TcpStream) {
        let config = self.config();
        let routes = routes_for_protocol(&config, ctx.protocol);

        // For TLS-terminated HTTPS and raw TLS listeners, peek the ClientHello
        // to extract SNI unless it was already provided (e.g. by a terminating
        // listener). HTTPS listeners use the SNI hostname to choose the correct
        // terminating route before the TLS handshake is completed.
        let sni: Option<Arc<str>> = if let Some(sni) = ctx.sni.clone() {
            Some(sni)
        } else if matches!(ctx.protocol, Protocol::Tls | Protocol::Https) {
            peek_client_hello_sni(&stream).await
        } else {
            None
        };

        let route = if matches!(ctx.protocol, Protocol::Tls | Protocol::Https) {
            find_tls_route(routes, &ctx, sni.as_deref())
        } else {
            find_route(routes, &ctx, sni.as_deref())
        };
        let Some(route) = route else {
            tracing::info!(
                listener_id = %ctx.listener_id,
                protocol = ?ctx.protocol,
                local_addr = %ctx.local_addr,
                "l4 router: no matching route"
            );
            return;
        };
        tracing::info!(
            listener_id = %ctx.listener_id,
            protocol = ?ctx.protocol,
            action = ?route.action,
            "l4 router: matched route"
        );

        match &route.action {
            L4Action::TcpRelay(backends) | L4Action::TlsPassthrough(backends) => {
                relay_tcp(&ctx, stream, backends).await;
            }
            L4Action::TlsTerminate(backends) => {
                if let Err(e) = tls_terminate(&ctx, stream, backends, &self.registry, &config).await
                {
                    tracing::debug!(
                        listener_id = %ctx.listener_id,
                        error = %e,
                        "l4 router: tls termination failed"
                    );
                }
            }
            L4Action::UdpRelay(_) => {
                tracing::debug!(listener_id = %ctx.listener_id, "l4 router: udp action on tcp stream");
            }
            L4Action::TerminateAndHttp(target) => {
                if let Err(e) = terminate_and_http(
                    &ctx,
                    stream,
                    target,
                    &self.registry,
                    &self.sni_context,
                    &self.http_context,
                    &config,
                )
                .await
                {
                    tracing::debug!(
                        listener_id = %ctx.listener_id,
                        error = %e,
                        "l4 router: https termination failed"
                    );
                }
            }
            L4Action::HttpRelay(target) => {
                if let Err(e) = http_relay(&ctx, stream, target, &self.http_context).await {
                    tracing::debug!(
                        listener_id = %ctx.listener_id,
                        error = %e,
                        "l4 router: http relay failed"
                    );
                }
            }
        }
    }

    async fn handle_udp(
        &self,
        ctx: L4Context,
        packet: Bytes,
        peer: SocketAddr,
        socket: Arc<DualStackUdpSocket>,
    ) {
        let config = self.config();
        let routes = routes_for_protocol(&config, ctx.protocol);
        let route = find_route(routes, &ctx, None);
        let Some(route) = route else {
            tracing::debug!(
                listener_id = %ctx.listener_id,
                "l4 router: no matching udp route"
            );
            return;
        };

        let L4Action::UdpRelay(backends) = &route.action else {
            tracing::debug!(
                listener_id = %ctx.listener_id,
                action = ?route.action,
                "l4 router: non-udp action on udp packet"
            );
            return;
        };

        relay_udp(&ctx, packet, peer, socket, backends).await;
    }
}

/// Return the route slice that applies to the given protocol.
fn routes_for_protocol(config: &CompiledL4Config, protocol: Protocol) -> &[CompiledL4Route] {
    match protocol {
        Protocol::Tcp => &config.tcp_routes,
        Protocol::Udp => &config.udp_routes,
        Protocol::Tls => &config.tls_routes,
        Protocol::Https => &config.https_routes,
        Protocol::Http => &config.http_routes,
    }
}

/// Find the first matching route for the connection/packet context.
fn find_route<'a>(
    routes: &'a [CompiledL4Route],
    ctx: &L4Context,
    sni: Option<&str>,
) -> Option<&'a CompiledL4Route> {
    routes
        .iter()
        .find(|r| r.listener_id.as_ref() == ctx.listener_id.as_ref() && match_route(&r.match_, sni))
}

/// Find the best TLS route for an SNI-aware listener.
///
/// When multiple TLS listeners share a socket (e.g. several Gateway API TLS
/// listeners on port 443), the SNI hostname is matched against each route's
/// listener hostname, and the most specific matching listener is chosen. Routes
/// attached to less specific listeners are not considered for that connection,
/// which preserves listener isolation.
fn find_tls_route<'a>(
    routes: &'a [CompiledL4Route],
    ctx: &L4Context,
    sni: Option<&str>,
) -> Option<&'a CompiledL4Route> {
    let sni = sni?;
    let mut candidates: Vec<(&CompiledL4Route, i32)> = routes
        .iter()
        .filter(|r| r.listener_id.as_ref() == ctx.listener_id.as_ref())
        .filter_map(|r| {
            if ir_hostname_matches(sni, &r.listener_hostname) {
                Some((r, ir_listener_specificity_score(&r.listener_hostname)))
            } else {
                None
            }
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let best_score = candidates
        .iter()
        .map(|(_, score)| *score)
        .max()
        .unwrap_or(0);
    candidates.retain(|(_, score)| *score == best_score);
    candidates
        .iter()
        .find(|(r, _)| match_route(&r.match_, Some(sni)))
        .map(|(r, _)| *r)
}

/// Evaluate an L4 match against an optional SNI hostname.
fn match_route(match_: &L4Match, sni: Option<&str>) -> bool {
    match match_ {
        L4Match::Any => true,
        L4Match::Sni(hostname) => sni.is_some_and(|h| ir_hostname_matches(h, hostname)),
    }
}

/// Pick a backend using weighted random selection.
fn pick_backend(backends: &[WeightedBackend]) -> Option<&WeightedBackend> {
    if backends.is_empty() {
        return None;
    }
    if backends.len() == 1 {
        return backends.first();
    }
    let weights: Vec<u64> = backends.iter().map(|b| b.weight as u64).collect();
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return backends.first();
    }
    let dist = WeightedIndex::new(weights).ok()?;
    let mut rng = rand::rng();
    Some(&backends[dist.sample(&mut rng)])
}

/// Resolve a backend address string to a `SocketAddr`.
fn resolve_backend_addr(addr: &str) -> io::Result<SocketAddr> {
    SocketAddr::from_str(addr).or_else(|_| addr.to_socket_addrs()?.next().ok_or_else(invalid_addr))
}

fn invalid_addr() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "backend address could not be resolved",
    )
}

/// Relay a TCP stream to a selected backend.
async fn relay_tcp(ctx: &L4Context, mut stream: TcpStream, backends: &[WeightedBackend]) {
    let Some(backend) = pick_backend(backends) else {
        tracing::debug!(listener_id = %ctx.listener_id, "l4 router: no backend available");
        return;
    };
    let addr = match resolve_backend_addr(backend.backend.as_ref()) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(error = %e, backend = %backend.backend, "l4 router: backend resolve failed");
            return;
        }
    };

    let mut upstream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, %addr, "l4 router: backend connect failed");
            return;
        }
    };

    match copy_bidirectional(&mut stream, &mut upstream).await {
        Ok((down, up)) => {
            tracing::debug!(down, up, %addr, "l4 router: tcp relay completed");
        }
        Err(e) => {
            tracing::debug!(error = %e, %addr, "l4 router: tcp relay error");
        }
    }
}

/// Relay a plain HTTP TCP stream to the internal Pingora plaintext address.
async fn http_relay(
    ctx: &L4Context,
    mut stream: TcpStream,
    target: &str,
    http_context: &Arc<std::sync::Mutex<HashMap<SocketAddr, crate::l4::context::HttpRelayContext>>>,
) -> io::Result<()> {
    let addr = resolve_backend_addr(target)?;
    tracing::info!(%addr, "l4 router: http_relay connecting");
    let mut upstream = TcpStream::connect(addr).await?;

    // Tell the internal HTTP proxy which public listener this connection
    // arrived on, keyed by the source address it will see as the downstream
    // peer.
    if let Ok(local_addr) = upstream.local_addr() {
        http_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                local_addr,
                crate::l4::context::HttpRelayContext {
                    listener_id: Arc::clone(&ctx.listener_id),
                    listener_port: ctx.local_addr.port(),
                    secure: false,
                    client_addr: ctx.remote_addr,
                },
            );
    }

    match copy_bidirectional(&mut stream, &mut upstream).await {
        Ok((down, up)) => {
            tracing::debug!(down, up, %addr, "l4 router: http relay completed");
        }
        Err(e) => {
            tracing::debug!(error = %e, %addr, "l4 router: http relay error");
        }
    }

    if let Ok(local_addr) = upstream.local_addr() {
        http_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&local_addr);
    }

    Ok(())
}

/// Relay a UDP packet to a selected backend and send the response back.
async fn relay_udp(
    ctx: &L4Context,
    packet: Bytes,
    peer: SocketAddr,
    inbound: Arc<DualStackUdpSocket>,
    backends: &[WeightedBackend],
) {
    let Some(backend) = pick_backend(backends) else {
        tracing::debug!(listener_id = %ctx.listener_id, "l4 router: no udp backend available");
        return;
    };
    let addr = match resolve_backend_addr(backend.backend.as_ref()) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(error = %e, backend = %backend.backend, "l4 router: udp backend resolve failed");
            return;
        }
    };

    let outbound = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "l4 router: udp bind failed");
            return;
        }
    };

    if let Err(e) = outbound.send_to(&packet, addr).await {
        tracing::debug!(error = %e, %addr, "l4 router: udp send failed");
        return;
    }

    let mut buf = vec![0u8; 65535];
    match timeout(UDP_RELAY_TIMEOUT, outbound.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let response = Bytes::copy_from_slice(&buf[..len]);
            if let Err(e) = inbound.send_to(&response, peer).await {
                tracing::debug!(error = %e, %peer, "l4 router: udp response failed");
            }
        }
        Ok(Err(e)) => {
            tracing::debug!(error = %e, %addr, "l4 router: udp recv failed");
        }
        Err(_) => {
            tracing::debug!(%addr, "l4 router: udp relay timed out");
        }
    }
}

/// Accept TLS using the registry and forward the decrypted stream to a
/// plaintext HTTP upstream.
fn find_listener<'a>(
    config: &'a CompiledL4Config,
    listener_id: &str,
) -> Option<&'a CompiledListener> {
    config
        .listeners
        .iter()
        .find(|l| l.id.as_ref() == listener_id)
}

async fn terminate_and_http(
    ctx: &L4Context,
    stream: TcpStream,
    target: &Arc<str>,
    registry: &Arc<TlsRegistry>,
    sni_context: &Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<str>>>>,
    http_context: &Arc<std::sync::Mutex<HashMap<SocketAddr, crate::l4::context::HttpRelayContext>>>,
    l4_config: &CompiledL4Config,
) -> io::Result<()> {
    if registry.is_empty() {
        return Err(io::Error::other("tls registry has no certificates"));
    }
    let listener = find_listener(l4_config, ctx.listener_id.as_ref())
        .ok_or_else(|| io::Error::other("listener not found for terminate_and_http"))?;
    let server_config = match &listener.frontend_validation {
        Some(v) => registry
            .server_config_with_client_auth(v.ca_bundle_pem.as_ref(), v.allow_insecure_fallback),
        None => registry.server_config(),
    }
    .map_err(|e| io::Error::other(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let mut tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "l4 router: tls accept failed");
            return Err(io::Error::other(e.to_string()));
        }
    };

    // Propagate the SNI hostname to the HTTP proxy so it can detect misdirected
    // requests. The mapping is keyed by the upstream-side socket address that
    // Pingora will see as the downstream peer.
    let sni = tls_stream
        .get_ref()
        .1
        .server_name()
        .map(|name| Arc::from(name.to_string()) as Arc<str>);

    let addr = resolve_backend_addr(target.as_ref())?;
    let mut upstream = TcpStream::connect(addr).await?;
    if let Ok(local_addr) = upstream.local_addr() {
        if let Some(sni) = sni.clone() {
            sni_context
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(local_addr, sni);
        }
        http_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                local_addr,
                crate::l4::context::HttpRelayContext {
                    listener_id: Arc::clone(&ctx.listener_id),
                    listener_port: ctx.local_addr.port(),
                    secure: true,
                    client_addr: ctx.remote_addr,
                },
            );
    }

    match copy_bidirectional(&mut tls_stream, &mut upstream).await {
        Ok((down, up)) => {
            tracing::debug!(listener_id = %ctx.listener_id, down, up, %addr, "l4 router: https termination completed");
        }
        Err(e) => {
            tracing::debug!(error = %e, %addr, "l4 router: https termination relay error");
        }
    }

    if let Ok(local_addr) = upstream.local_addr() {
        sni_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&local_addr);
        http_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&local_addr);
    }
    Ok(())
}

/// Accept TLS using the registry and forward the decrypted stream to a
/// selected plaintext TCP backend.
async fn tls_terminate(
    ctx: &L4Context,
    stream: TcpStream,
    backends: &[WeightedBackend],
    registry: &Arc<TlsRegistry>,
    l4_config: &CompiledL4Config,
) -> io::Result<()> {
    if registry.is_empty() {
        return Err(io::Error::other("tls registry has no certificates"));
    }
    let listener = find_listener(l4_config, ctx.listener_id.as_ref())
        .ok_or_else(|| io::Error::other("listener not found for tls_terminate"))?;
    let server_config = match &listener.frontend_validation {
        Some(v) => registry
            .server_config_with_client_auth(v.ca_bundle_pem.as_ref(), v.allow_insecure_fallback),
        None => registry.server_config(),
    }
    .map_err(|e| io::Error::other(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let mut tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "l4 router: tls accept failed");
            return Err(io::Error::other(e.to_string()));
        }
    };

    let Some(backend) = pick_backend(backends) else {
        return Err(io::Error::other("no tls terminate backend available"));
    };
    let addr = resolve_backend_addr(backend.backend.as_ref())?;
    let mut upstream = TcpStream::connect(addr).await?;
    match copy_bidirectional(&mut tls_stream, &mut upstream).await {
        Ok((down, up)) => {
            tracing::debug!(listener_id = %ctx.listener_id, down, up, %addr, "l4 router: tls terminate completed");
        }
        Err(e) => {
            tracing::debug!(error = %e, %addr, "l4 router: tls terminate relay error");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::compile::{CompiledListener, CompiledTlsConfig};
    use crate::ir::{HostnameMatch, L4Action, L4Match};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn route(action: L4Action) -> CompiledL4Route {
        CompiledL4Route {
            listener_id: "l1".into(),
            listener_hostname: HostnameMatch::Any,
            match_: L4Match::Any,
            action,
            priority: 0,
        }
    }

    fn sni_route(hostname: HostnameMatch, action: L4Action) -> CompiledL4Route {
        CompiledL4Route {
            listener_id: "l1".into(),
            listener_hostname: hostname.clone(),
            match_: L4Match::Sni(hostname),
            action,
            priority: 0,
        }
    }

    fn backend(addr: &str) -> WeightedBackend {
        WeightedBackend {
            backend: addr.into(),
            weight: 1,
            request_filters: Vec::new(),
            protocol: crate::ir::BackendProtocol::Http,
            tls: None,
        }
    }

    fn config_with_route(action: L4Action) -> Arc<arc_swap::ArcSwap<CompiledL4Config>> {
        config_with_routes(vec![route(action)])
    }

    fn registry() -> Arc<TlsRegistry> {
        Arc::new(TlsRegistry::new())
    }

    fn sni_context() -> Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<str>>>> {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    fn config_with_routes(
        routes: Vec<CompiledL4Route>,
    ) -> Arc<arc_swap::ArcSwap<CompiledL4Config>> {
        Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            tcp_routes: routes.clone(),
            udp_routes: routes.clone(),
            tls_routes: routes.clone(),
            https_routes: routes.clone(),
            http_routes: routes,
            ..Default::default()
        }))
    }

    /// Create a connected pair of TCP streams via a temporary listener.
    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn peek_sni_extracts_from_single_segment_hello() {
        let (mut client, server) = connected_pair().await;
        client
            .write_all(&crate::sni::build_client_hello(Some("one.example.com")))
            .await
            .unwrap();
        let sni = peek_client_hello_sni(&server).await;
        assert_eq!(sni.as_deref(), Some("one.example.com"));
    }

    #[tokio::test]
    async fn peek_sni_waits_for_fragmented_client_hello() {
        let (mut client, server) = connected_pair().await;
        let hello = crate::sni::build_client_hello(Some("frag.example.com"));
        let split = hello.len() / 2;
        let first = hello[..split].to_vec();
        let second = hello[split..].to_vec();
        let writer = tokio::spawn(async move {
            client.write_all(&first).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(&second).await.unwrap();
        });
        let sni = peek_client_hello_sni(&server).await;
        assert_eq!(sni.as_deref(), Some("frag.example.com"));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn peek_sni_handles_hello_larger_than_old_buffer() {
        // TLS 1.3 / post-quantum ClientHellos exceed the old 1536-byte buffer.
        let (mut client, server) = connected_pair().await;
        let hello = crate::sni::build_client_hello_padded(Some("pq.example.com"), 4096);
        assert!(hello.len() > 1536);
        client.write_all(&hello).await.unwrap();
        let sni = peek_client_hello_sni(&server).await;
        assert_eq!(sni.as_deref(), Some("pq.example.com"));
    }

    #[tokio::test]
    async fn peek_sni_fails_fast_on_non_tls_data() {
        let (mut client, server) = connected_pair().await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(peek_client_hello_sni(&server).await.is_none());
    }

    #[test]
    fn routes_for_protocol_selects_correct_slice() {
        let config = CompiledL4Config {
            tcp_routes: vec![route(L4Action::TcpRelay(vec![]))],
            udp_routes: vec![route(L4Action::UdpRelay(vec![]))],
            tls_routes: vec![route(L4Action::TlsPassthrough(vec![]))],
            https_routes: vec![route(L4Action::TerminateAndHttp("127.0.0.1:443".into()))],
            http_routes: vec![route(L4Action::HttpRelay("127.0.0.1:80".into()))],
            ..Default::default()
        };
        assert_eq!(routes_for_protocol(&config, Protocol::Tcp).len(), 1);
        assert_eq!(routes_for_protocol(&config, Protocol::Udp).len(), 1);
        assert_eq!(routes_for_protocol(&config, Protocol::Tls).len(), 1);
        assert_eq!(routes_for_protocol(&config, Protocol::Https).len(), 1);
        assert_eq!(routes_for_protocol(&config, Protocol::Http).len(), 1);
    }

    #[test]
    fn find_route_matches_listener_id_and_any() {
        let routes = vec![route(L4Action::TcpRelay(vec![]))];
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tcp,
        );
        assert!(find_route(&routes, &ctx, None).is_some());

        let ctx_mismatch = L4Context::from_udp(
            "l2".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tcp,
        );
        assert!(find_route(&routes, &ctx_mismatch, None).is_none());
    }

    #[test]
    fn find_route_matches_sni() {
        let routes = vec![sni_route(
            HostnameMatch::Exact("test.example.com".into()),
            L4Action::TlsPassthrough(vec![]),
        )];
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tls,
        );
        assert!(find_route(&routes, &ctx, Some("test.example.com")).is_some());
        assert!(find_route(&routes, &ctx, Some("other.example.com")).is_none());
        assert!(find_route(&routes, &ctx, None).is_none());
    }

    #[test]
    fn pick_backend_returns_none_when_empty() {
        assert!(pick_backend(&[]).is_none());
    }

    #[test]
    fn pick_backend_returns_single_backend() {
        let b = vec![backend("127.0.0.1:8080")];
        assert_eq!(pick_backend(&b).unwrap().backend.as_ref(), "127.0.0.1:8080");
    }

    #[test]
    fn resolve_backend_addr_parses_socket_addr() {
        assert_eq!(
            resolve_backend_addr("127.0.0.1:8080").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8080))
        );
    }

    #[test]
    fn resolve_backend_addr_returns_error_for_invalid_input() {
        assert!(resolve_backend_addr("not a valid address").is_err());
    }

    #[test]
    fn pick_backend_with_zero_total_weight_falls_back_to_first() {
        let b = vec![
            WeightedBackend {
                backend: "first".into(),
                weight: 0,
                request_filters: Vec::new(),
                protocol: crate::ir::BackendProtocol::Http,
                tls: None,
            },
            WeightedBackend {
                backend: "second".into(),
                weight: 0,
                request_filters: Vec::new(),
                protocol: crate::ir::BackendProtocol::Http,
                tls: None,
            },
        ];
        assert_eq!(pick_backend(&b).unwrap().backend.as_ref(), "first");
    }

    #[test]
    fn find_listener_selects_by_id() {
        let config = CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(find_listener(&config, "l1").is_some());
        assert!(find_listener(&config, "l2").is_none());
    }

    #[tokio::test]
    async fn handle_tcp_logs_when_no_route_matches() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            tcp_routes: vec![CompiledL4Route {
                listener_id: "other".into(),
                listener_hostname: HostnameMatch::Any,
                match_: L4Match::Any,
                action: L4Action::TcpRelay(vec![]),
                priority: 0,
            }],
            ..Default::default()
        }));
        let (mut client, inbound) = connected_pair().await;
        let router = Router::new(config, registry(), sni_context());
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tcp,
        );
        let task = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });
        // Writing should not panic; the connection is closed without a backend.
        let _ = client.write_all(b"hello").await;
        let _ = task.await;
    }

    #[tokio::test]
    async fn handle_udp_logs_when_no_route_matches() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config::default()));
        let router = Router::new(config, registry(), sni_context());
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Udp,
        );
        let socket = Arc::new(
            crate::l4::udp::DualStackUdpSocket::bind("127.0.0.1:0")
                .await
                .unwrap(),
        );
        router
            .handle_udp(
                ctx,
                bytes::Bytes::from_static(b"ping"),
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                socket,
            )
            .await;
    }

    #[tokio::test]
    async fn handle_udp_logs_non_udp_action() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            udp_routes: vec![CompiledL4Route {
                listener_id: "l1".into(),
                listener_hostname: HostnameMatch::Any,
                match_: L4Match::Any,
                action: L4Action::TcpRelay(vec![]),
                priority: 0,
            }],
            ..Default::default()
        }));
        let router = Router::new(config, registry(), sni_context());
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Udp,
        );
        let socket = Arc::new(
            crate::l4::udp::DualStackUdpSocket::bind("127.0.0.1:0")
                .await
                .unwrap(),
        );
        router
            .handle_udp(
                ctx,
                bytes::Bytes::from_static(b"ping"),
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                socket,
            )
            .await;
    }

    #[test]
    fn router_new_with_http_context() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config::default()));
        let registry = registry();
        let sni = sni_context();
        let http: Arc<std::sync::Mutex<HashMap<SocketAddr, crate::l4::context::HttpRelayContext>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let router = Router::new_with_http_context(config, registry, sni, Arc::clone(&http));
        let _ = router.http_context.lock().unwrap().len();
    }

    #[test]
    fn pick_backend_weighted_distribution() {
        let b = vec![
            backend("a"),
            WeightedBackend {
                backend: "b".into(),
                weight: 1,
                request_filters: Vec::new(),
                protocol: crate::ir::BackendProtocol::Http,
                tls: None,
            },
        ];
        let mut seen_a = false;
        let mut seen_b = false;
        for _ in 0..50 {
            let picked = pick_backend(&b).unwrap().backend.as_ref();
            if picked == "a" {
                seen_a = true;
            } else if picked == "b" {
                seen_b = true;
            }
        }
        assert!(seen_a);
        assert!(seen_b);
    }

    #[tokio::test]
    async fn handle_tcp_terminate_and_http_empty_registry() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            https_routes: vec![CompiledL4Route {
                listener_id: "l1".into(),
                listener_hostname: HostnameMatch::Any,
                match_: L4Match::Any,
                action: L4Action::TerminateAndHttp("127.0.0.1:8080".into()),
                priority: 0,
            }],
            ..Default::default()
        }));
        let (mut client, inbound) = connected_pair().await;
        let router = Router::new(config, registry(), sni_context());
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Https,
        );
        let task = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });
        let _ = client.write_all(b"not tls").await;
        let _ = client.shutdown().await;
        let _ = task.await;
    }

    #[tokio::test]
    async fn tcp_relay_forwards_data_to_backend() {
        // Backend echoes data and then closes.
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut socket, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.shutdown().await.ok();
        });

        let (mut client, inbound) = connected_pair().await;
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tcp,
        );
        let router = Router::new(
            config_with_route(L4Action::TcpRelay(vec![backend(&backend_addr.to_string())])),
            registry(),
            sni_context(),
        );

        let relay = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });

        client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        drop(client);
        let _ = tokio::join!(backend_task, relay);
    }

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session id len
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression

        let mut exts = Vec::new();
        if let Some(hostname) = sni {
            let name_bytes = hostname.as_bytes();
            let name_len = name_bytes.len() as u16;
            let entry_len = 1 + 2 + name_len;
            let sni_data_len = 2 + entry_len;
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
            exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&name_len.to_be_bytes());
            exts.extend_from_slice(name_bytes);
        }
        exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // dummy extension
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let ch_len = ch.len() as u32;
        hs.push((ch_len >> 16) as u8);
        hs.push((ch_len >> 8) as u8);
        hs.push(ch_len as u8);
        hs.extend_from_slice(&ch);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[tokio::test]
    async fn tls_passthrough_peeks_sni_and_relays() {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut socket, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.shutdown().await.ok();
            n
        });

        let (mut client, inbound) = connected_pair().await;
        let client_hello = build_client_hello(Some("test.example.com"));

        let routes = vec![CompiledL4Route {
            listener_id: "l1".into(),
            listener_hostname: HostnameMatch::Exact("test.example.com".into()),
            match_: L4Match::Sni(HostnameMatch::Exact("test.example.com".into())),
            action: L4Action::TlsPassthrough(vec![backend(&backend_addr.to_string())]),
            priority: 0,
        }];
        let router = Router::new(config_with_routes(routes), registry(), sni_context());
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Tls,
        );

        let relay = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });

        client.write_all(&client_hello).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &client_hello);

        drop(client);
        let received_len = backend_task.await.unwrap();
        assert_eq!(received_len, client_hello.len());
        relay.await.ok();
    }

    #[tokio::test]
    async fn udp_relay_forwards_packet_and_returns_response() {
        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = peer_socket.local_addr().unwrap();

        let inbound_socket = Arc::new(DualStackUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inbound_addr = inbound_socket.local_addr().unwrap();

        // Backend UDP echo server.
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_socket.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let (_len, sender) = backend_socket.recv_from(&mut buf).await.unwrap();
            backend_socket.send_to(b"pong", sender).await.unwrap();
        });

        let router = Router::new(
            config_with_route(L4Action::UdpRelay(vec![backend(&backend_addr.to_string())])),
            registry(),
            sni_context(),
        );
        let ctx = L4Context::from_udp("l1".into(), inbound_addr, peer, Protocol::Udp);

        let relay = tokio::spawn(async move {
            router
                .handle_udp(ctx, Bytes::from_static(b"ping"), peer, inbound_socket)
                .await;
        });

        // The router should relay the backend echo back to the peer address.
        let mut buf = vec![0u8; 64];
        let (len, from) = timeout(Duration::from_secs(5), peer_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"pong");
        assert_eq!(from, inbound_addr);

        backend_task.await.unwrap();
        relay.await.unwrap();
    }

    #[test]
    fn router_new_stores_config() {
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config::default()));
        let router = Router::new(Arc::clone(&config), registry(), sni_context());
        assert!(router.config().tcp_routes.is_empty());
        assert!(config.load().tcp_routes.is_empty());
    }

    #[tokio::test]
    async fn http_relay_forwards_request_and_response() {
        // Minimal upstream that reads an HTTP request and returns a response.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut socket, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            socket.shutdown().await.ok();
        });

        let (mut client, inbound) = connected_pair().await;
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Http,
        );
        let router = Router::new(
            config_with_route(L4Action::HttpRelay(
                upstream_addr.to_string().as_str().into(),
            )),
            registry(),
            sni_context(),
        );

        let relay = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert!(n > 0);
        assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("200 OK"));

        drop(client);
        let _ = tokio::join!(upstream_task, relay);
    }

    #[test]
    fn match_route_any_is_true() {
        assert!(match_route(&L4Match::Any, None));
        assert!(match_route(&L4Match::Any, Some("anything")));
    }

    #[tokio::test]
    async fn terminate_and_http_fails_when_registry_has_no_cert() {
        let registry = Arc::new(TlsRegistry::new());
        let (client, inbound) = connected_pair().await;
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Https,
        );
        drop(client);
        let sni_ctx = sni_context();
        let l4_config = CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = terminate_and_http(
            &ctx,
            inbound,
            &Arc::from("127.0.0.1:1"),
            &registry,
            &sni_ctx,
            &Arc::new(std::sync::Mutex::new(HashMap::new())),
            &l4_config,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn terminate_and_http_relays_to_plaintext_backend() {
        const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUXdh+Kh3k6v8yH9DP4xrSLFpEdVIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYxMzEyNTQxOVoXDTI3MDYx
MzEyNTQxOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAxiakZm33D6e5fJhSrGl5nrB+Q5v4aoWaYO31l6Wys2Hh
H2y2MAffWAcYn6PteE9gb6UUhxxHbtXu9jIb1I7WrO+qFXyalSNl6yYYYIYo7+2L
bKap6LkbaIz8Jsegrjtmb6RW2TyXqX5DtwWMpU6ePnCSm6cHj3Pqs/VesCtpuh1c
D/MoeWRGYuB+nfKkZ6/dmFs46jlRsjnSrNFslTgIkt6Fbed7Xn5E4wAz6gILxHB6
pktWIC+86uR9kEJ5G63/QPjymg1PSVaezn6LSkgeKg9SLPGurWTbrsqkwEwa8t0K
QQAiaHli0//Go+cIDJCvKogTxFYmD1e3+3q9x/SvCwIDAQABo4GGMIGDMB0GA1Ud
DgQWBBQYwTWRTd7tJXu6Je3yXF1LEpXRSTAfBgNVHSMEGDAWgBQYwTWRTd7tJXu6
Je3yXF1LEpXRSTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEB
ADnLr9hpXoWU5WeDqZgMxBCwv9eXZFCeDI9WEY8NP9bihyYNTFeg2smmwmUisVfM
TngOwXc0lkdnw0yjEY9BkreiW7SXYw4LRXKSLTzvYOElvR0eEh2fuFLJ01Coul/d
AIG4IFYUm81n+39M9x58rzuVpHybJhVyQynQG4pvQ/gvoMS1T52r+1XvcjpFopc3
8siM5UYpfvrmjVa4ehWZJUt0C+Yc0VEh5QrqkawI7mVBu+UDbD/dZpJqnZYxj2dP
QSMofIl2UfWQZruEXjdykcygVc45VzAd56l9H1H3mOocpgoGZHHflIPzbdyUwDte
1JLEQApDV4RilthGCExnnxk=
-----END CERTIFICATE-----
"#;
        const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGJqRmbfcPp7l8
mFKsaXmesH5Dm/hqhZpg7fWXpbKzYeEfbLYwB99YBxifo+14T2BvpRSHHEdu1e72
MhvUjtas76oVfJqVI2XrJhhghijv7YtspqnouRtojPwmx6CuO2ZvpFbZPJepfkO3
BYylTp4+cJKbpwePc+qz9V6wK2m6HVwP8yh5ZEZi4H6d8qRnr92YWzjqOVGyOdKs
0WyVOAiS3oVt53tefkTjADPqAgvEcHqmS1YgL7zq5H2QQnkbrf9A+PKaDU9JVp7O
fotKSB4qD1Is8a6tZNuuyqTATBry3QpBACJoeWLT/8aj5wgMkK8qiBPEViYPV7f7
er3H9K8LAgMBAAECggEAG9kydx2IANtBu7vCDW6FeUK00YEKLhkOKVvy4u1Baunx
Xx6YPF00NoWeIFGZqQmpiVyvazho5wWKIBp1bto5sZ8SoxJwEfsiR8+C0uNdaDBV
IrVfC9DNg/7MhrwSXmpawItdlApqsOzd93Wq3qYTTL3lh5q3T/dVSmrMdACl9fy1
PACZGMIhQpo//cu+4RlUA8OrpWk+hPkNep+JoO7hdTfBxxqzLMAg1xgP6yEpAad4
8wXq39btwhMf29fxoEQqYOZkEyEvtkXb3EYCnkgVMfEHJ9yEjkgM/o6RbLm9fCeS
PYH1ZmlMk0RDX9EOEYNrtTLUdIjmmQmEP+2NOlvLAQKBgQD+cpSzXg3MKUrhon1Q
JAWAA90GYHOfkyluOBiFeZjedo4PnNPWWcVij7P3LJ7sPGTV4JcYvlEHbKcnLR2r
DEhyfJ7V6piZ4UDKG6OnKXkGsFfazUbMZLhuZNFegjnxpaX6L65U9vp1Z5uzVr1B
Q6K+BJNSEkJOb3lg/ZJlTo8teQKBgQDHXCHWFpQpKF2oLDKRbKV63On62KUfkUpI
olAhpa//KDafDrEUbngsPdpY0MafFSafvLF7VRJcc2Tct0WijDJo5t5+synrc+/4
zvet50sRHocvh5as6n23XtmNhosiBcYnMwALeA3j4jat8bpdBc/tf9OUk3dxSgmz
FD2ovtDTowKBgQCb2PiFaG1RCFWqIAlbJcUMpNEjD76iFdQBg3BZiKH+WGUo4OjL
WI7SkKwtD/KDRXaJnZdOe3tL7dvv3e1XEB3rqbLr2VYAonw5jnZNc9SCKU6WYLcl
h+eDDlNC7Maq4MfplnzT47aCZKR0UwN2TwQGGO1XDoH4YsTYiFe7n0OJGQKBgC3F
qoMkBfp5KR++nhGjl07hP9t3OFpKGnsYwTsodoMn8XqNffzJ7E+EGAjCTogh7A9K
3JkLjD6rw+GlNpi+hahuMXF3o01K/jLrGhTUgPi6QKGaCO9Em36piVukI3e5Saig
XgdEFjRXMOS5FmfbOMU3zxVS0l6xeA6kvA9tWDbvAoGADGdEQYBm1xaoQlb2F6TY
4u2jkAABAQOebNnVYT9UqOdYpz03rC4xQbJuRqTBH6RtfcVEFUYDqDg86DXhczSP
823w6ZqslkWPA9UKvtGQL0fCVUNlQbMJNSKGpkJ5T+6Saip6+C9r0RAvNYlACJ54
7UDrRhNwO+cf9/tDJh2nD8Y=
-----END PRIVATE KEY-----
"#;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut socket, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.shutdown().await.ok();
        });

        let cert_key =
            crate::tls::certified_key_from_pem(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes())
                .unwrap();
        let mut store = crate::tls::CertStore::default();
        store.default = Some(cert_key);
        let registry = Arc::new(TlsRegistry::new());
        registry.apply(store);

        let (client, inbound) = connected_pair().await;
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Https,
        );
        let router = Router::new(
            config_with_route(L4Action::TerminateAndHttp(Arc::from(
                backend_addr.to_string().as_str(),
            ))),
            registry,
            sni_context(),
        );

        let relay = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });

        let mut root_store = rustls::RootCertStore::empty();
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(TEST_CERT_PEM.as_bytes()))
                .collect::<Result<_, _>>()
                .unwrap();
        for cert in certs {
            root_store.add(cert).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls_client = connector.connect(server_name, client).await.unwrap();
        tls_client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tls_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        drop(tls_client);
        let _ = tokio::join!(backend_task, relay);
    }

    #[tokio::test]
    async fn terminate_and_http_matches_listener_hostname_by_sni() {
        const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUXdh+Kh3k6v8yH9DP4xrSLFpEdVIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYxMzEyNTQxOVoXDTI3MDYx
MzEyNTQxOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAxiakZm33D6e5fJhSrGl5nrB+Q5v4aoWaYO31l6Wys2Hh
H2y2MAffWAcYn6PteE9gb6UUhxxHbtXu9jIb1I7WrO+qFXyalSNl6yYYYIYo7+2L
bKap6LkbaIz8Jsegrjtmb6RW2TyXqX5DtwWMpU6ePnCSm6cHj3Pqs/VesCtpuh1c
D/MoeWRGYuB+nfKkZ6/dmFs46jlRsjnSrNFslTgIkt6Fbed7Xn5E4wAz6gILxHB6
pktWIC+86uR9kEJ5G63/QPjymg1PSVaezn6LSkgeKg9SLPGurWTbrsqkwEwa8t0K
QQAiaHli0//Go+cIDJCvKogTxFYmD1e3+3q9x/SvCwIDAQABo4GGMIGDMB0GA1Ud
DgQWBBQYwTWRTd7tJXu6Je3yXF1LEpXRSTAfBgNVHSMEGDAWgBQYwTWRTd7tJXu6
Je3yXF1LEpXRSTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEB
ADnLr9hpXoWU5WeDqZgMxBCwv9eXZFCeDI9WEY8NP9bihyYNTFeg2smmwmUisVfM
TngOwXc0lkdnw0yjEY9BkreiW7SXYw4LRXKSLTzvYOElvR0eEh2fuFLJ01Coul/d
AIG4IFYUm81n+39M9x58rzuVpHybJhVyQynQG4pvQ/gvoMS1T52r+1XvcjpFopc3
8siM5UYpfvrmjVa4ehWZJUt0C+Yc0VEh5QrqkawI7mVBu+UDbD/dZpJqnZYxj2dP
QSMofIl2UfWQZruEXjdykcygVc45VzAd56l9H1H3mOocpgoGZHHflIPzbdyUwDte
1JLEQApDV4RilthGCExnnxk=
-----END CERTIFICATE-----
"#;
        const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGJqRmbfcPp7l8
mFKsaXmesH5Dm/hqhZpg7fWXpbKzYeEfbLYwB99YBxifo+14T2BvpRSHHEdu1e72
MhvUjtas76oVfJqVI2XrJhhghijv7YtspqnouRtojPwmx6CuO2ZvpFbZPJepfkO3
BYylTp4+cJKbpwePc+qz9V6wK2m6HVwP8yh5ZEZi4H6d8qRnr92YWzjqOVGyOdKs
0WyVOAiS3oVt53tefkTjADPqAgvEcHqmS1YgL7zq5H2QQnkbrf9A+PKaDU9JVp7O
fotKSB4qD1Is8a6tZNuuyqTATBry3QpBACJoeWLT/8aj5wgMkK8qiBPEViYPV7f7
er3H9K8LAgMBAAECggEAG9kydx2IANtBu7vCDW6FeUK00YEKLhkOKVvy4u1Baunx
Xx6YPF00NoWeIFGZqQmpiVyvazho5wWKIBp1bto5sZ8SoxJwEfsiR8+C0uNdaDBV
IrVfC9DNg/7MhrwSXmpawItdlApqsOzd93Wq3qYTTL3lh5q3T/dVSmrMdACl9fy1
PACZGMIhQpo//cu+4RlUA8OrpWk+hPkNep+JoO7hdTfBxxqzLMAg1xgP6yEpAad4
8wXq39btwhMf29fxoEQqYOZkEyEvtkXb3EYCnkgVMfEHJ9yEjkgM/o6RbLm9fCeS
PYH1ZmlMk0RDX9EOEYNrtTLUdIjmmQmEP+2NOlvLAQKBgQD+cpSzXg3MKUrhon1Q
JAWAA90GYHOfkyluOBiFeZjedo4PnNPWWcVij7P3LJ7sPGTV4JcYvlEHbKcnLR2r
DEhyfJ7V6piZ4UDKG6OnKXkGsFfazUbMZLhuZNFegjnxpaX6L65U9vp1Z5uzVr1B
Q6K+BJNSEkJOb3lg/ZJlTo8teQKBgQDHXCHWFpQpKF2oLDKRbKV63On62KUfkUpI
olAhpa//KDafDrEUbngsPdpY0MafFSafvLF7VRJcc2Tct0WijDJo5t5+synrc+/4
zvet50sRHocvh5as6n23XtmNhosiBcYnMwALeA3j4jat8bpdBc/tf9OUk3dxSgmz
FD2ovtDTowKBgQCb2PiFaG1RCFWqIAlbJcUMpNEjD76iFdQBg3BZiKH+WGUo4OjL
WI7SkKwtD/KDRXaJnZdOe3tL7dvv3e1XEB3rqbLr2VYAonw5jnZNc9SCKU6WYLcl
h+eDDlNC7Maq4MfplnzT47aCZKR0UwN2TwQGGO1XDoH4YsTYiFe7n0OJGQKBgC3F
qoMkBfp5KR++nhGjl07hP9t3OFpKGnsYwTsodoMn8XqNffzJ7E+EGAjCTogh7A9K
3JkLjD6rw+GlNpi+hahuMXF3o01K/jLrGhTUgPi6QKGaCO9Em36piVukI3e5Saig
XgdEFjRXMOS5FmfbOMU3zxVS0l6xeA6kvA9tWDbvAoGADGdEQYBm1xaoQlb2F6TY
4u2jkAABAQOebNnVYT9UqOdYpz03rC4xQbJuRqTBH6RtfcVEFUYDqDg86DXhczSP
823w6ZqslkWPA9UKvtGQL0fCVUNlQbMJNSKGpkJ5T+6Saip6+C9r0RAvNYlACJ54
7UDrRhNwO+cf9/tDJh2nD8Y=
-----END PRIVATE KEY-----
"#;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut socket, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.shutdown().await.ok();
        });

        let cert_key =
            crate::tls::certified_key_from_pem(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes())
                .unwrap();
        let mut store = crate::tls::CertStore::default();
        store.default = Some(cert_key);
        let registry = Arc::new(TlsRegistry::new());
        registry.apply(store);

        let (client, inbound) = connected_pair().await;
        let ctx = L4Context::from_udp(
            "l1".into(),
            SocketAddr::from(([127, 0, 0, 1], 8443)),
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Protocol::Https,
        );

        let hostname = HostnameMatch::Exact(Arc::from("localhost"));
        let config = Arc::new(arc_swap::ArcSwap::from_pointee(CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "l1".into(),
                bind_addr: "127.0.0.1:8443".into(),
                protocol: Protocol::Https,
                ..Default::default()
            }],
            https_routes: vec![CompiledL4Route {
                listener_id: "l1".into(),
                listener_hostname: hostname.clone(),
                match_: L4Match::Sni(hostname),
                action: L4Action::TerminateAndHttp(Arc::from(backend_addr.to_string().as_str())),
                priority: 0,
            }],
            ..Default::default()
        }));

        let router = Router::new(config, registry, sni_context());

        let relay = tokio::spawn(async move {
            router.handle_tcp(ctx, inbound).await;
        });

        let mut root_store = rustls::RootCertStore::empty();
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(TEST_CERT_PEM.as_bytes()))
                .collect::<Result<_, _>>()
                .unwrap();
        for cert in certs {
            root_store.add(cert).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls_client = connector.connect(server_name, client).await.unwrap();
        tls_client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tls_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        drop(tls_client);
        let _ = tokio::join!(backend_task, relay);
    }

    #[test]
    fn compiled_listener_and_tls_config_coverage() {
        // Exercise the debug/clone derives used by the router.
        let listener = CompiledListener {
            id: "l1".into(),
            bind_addr: "127.0.0.1:8080".into(),
            protocol: Protocol::Tcp,
            tls: Some(CompiledTlsConfig::Registry {
                cert_id: "cert1".into(),
            }),
            redirect_http_to_https: false,
            frontend_validation: None,
        };
        let _ = listener.clone();
        let tls = CompiledTlsConfig::Files {
            cert_path: "/tmp/cert.pem".into(),
            key_path: "/tmp/key.pem".into(),
        };
        let _ = tls.clone();
        let _ = format!("{:?}", listener);
    }
}
