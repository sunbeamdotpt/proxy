// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 connection/packet context passed to the router.

use crate::ir::Protocol;
use std::net::SocketAddr;
use std::sync::Arc;

/// Per-connection (TCP) or per-packet (UDP) context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L4Context {
    /// Listener this connection/packet arrived on.
    pub listener_id: Arc<str>,
    /// Local address the packet/connection arrived on.
    pub local_addr: SocketAddr,
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Transport protocol.
    pub protocol: Protocol,
    /// SNI hostname, if already peeked (TLSRoute / HTTPS termination).
    pub sni: Option<Arc<str>>,
}

/// Context propagated from the L4 HTTP relay to the internal HTTP proxy so that
/// the proxy can recover the public listener that accepted the connection.
#[derive(Clone, Debug)]
pub struct HttpRelayContext {
    /// Compiled listener identifier the connection arrived on.
    pub listener_id: Arc<str>,
    /// Public listener port (e.g. 80 or 8080).
    pub listener_port: u16,
}

impl L4Context {
    /// Build a context for an accepted TCP stream.
    pub fn from_tcp_stream(
        listener_id: Arc<str>,
        protocol: Protocol,
        stream: &tokio::net::TcpStream,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener_id,
            local_addr: stream.local_addr()?,
            remote_addr: stream.peer_addr()?,
            protocol,
            sni: None,
        })
    }

    /// Build a context for a UDP packet.
    pub fn from_udp(
        listener_id: Arc<str>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol: Protocol,
    ) -> Self {
        Self {
            listener_id,
            local_addr,
            remote_addr,
            protocol,
            sni: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_from_udp() {
        let local = SocketAddr::from(([127, 0, 0, 1], 80));
        let remote = SocketAddr::from(([127, 0, 0, 1], 12345));
        let ctx = L4Context::from_udp("l1".into(), local, remote, Protocol::Udp);
        assert_eq!(ctx.listener_id.as_ref(), "l1");
        assert_eq!(ctx.local_addr, local);
        assert_eq!(ctx.remote_addr, remote);
        assert_eq!(ctx.protocol, Protocol::Udp);
        assert!(ctx.sni.is_none());
    }
}
