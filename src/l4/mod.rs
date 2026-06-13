// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 socket manager and routing abstractions.

use crate::ir::compile::CompiledL4Config;
use crate::tls::TlsRegistry;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::sync::Arc;

pub mod context;
pub mod manager;
pub mod router;
pub mod udp;

/// Router that handles accepted L4 connections and UDP packets.
#[async_trait]
pub trait L4Router: Send + Sync + 'static {
    /// Handle an accepted TCP connection.
    async fn handle_tcp(&self, ctx: context::L4Context, stream: tokio::net::TcpStream);

    /// Handle a single UDP packet.
    async fn handle_udp(
        &self,
        ctx: context::L4Context,
        packet: bytes::Bytes,
        peer: std::net::SocketAddr,
        socket: Arc<udp::DualStackUdpSocket>,
    );
}

/// A no-op router used for binding/accept tests.
#[derive(Debug, Default)]
pub struct NoOpRouter;

#[async_trait]
impl L4Router for NoOpRouter {
    async fn handle_tcp(&self, _ctx: context::L4Context, _stream: tokio::net::TcpStream) {}

    async fn handle_udp(
        &self,
        _ctx: context::L4Context,
        _packet: bytes::Bytes,
        _peer: std::net::SocketAddr,
        _socket: Arc<udp::DualStackUdpSocket>,
    ) {
    }
}

/// Shared state consumed by listener tasks.
pub struct SharedState {
    /// Current compiled L4 configuration.
    pub config: Arc<ArcSwap<CompiledL4Config>>,
    /// TLS certificate registry.
    pub registry: Arc<TlsRegistry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_router_handles_tcp_and_udp() {
        let router = NoOpRouter;
        let ctx = context::L4Context::from_udp(
            "l1".into(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 80)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
            crate::ir::Protocol::Udp,
        );
        let socket = Arc::new(udp::DualStackUdpSocket::bind("127.0.0.1:0").await.unwrap());
        router
            .handle_udp(
                ctx,
                bytes::Bytes::new(),
                std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
                socket,
            )
            .await;
    }

    #[test]
    fn shared_state_fields_are_accessible() {
        let state = SharedState {
            config: Arc::new(ArcSwap::from_pointee(CompiledL4Config::default())),
            registry: Arc::new(TlsRegistry::new()),
        };
        assert!(state.config.load().listeners.is_empty());
    }
}
