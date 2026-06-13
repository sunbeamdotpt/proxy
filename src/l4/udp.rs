// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dual-stack UDP socket wrapper.

use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// A UDP socket that binds to a single address.
///
/// On dual-stack hosts binding to `[::]:port` will accept both IPv4 and IPv6
/// traffic. For IPv4-specific binds a standard IPv4 socket is used.
#[derive(Debug)]
pub struct DualStackUdpSocket {
    inner: UdpSocket,
}

impl DualStackUdpSocket {
    /// Bind a UDP socket to `addr`.
    pub async fn bind(addr: &str) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { inner: socket })
    }

    /// Receive a datagram into `buf`, returning the length and sender address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    /// Send a datagram to `target`.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    /// Local socket address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_ipv4_send_recv_roundtrip() {
        let a = DualStackUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = DualStackUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        b.send_to(b"hello", a_addr).await.unwrap();

        let mut buf = [0u8; 16];
        let (len, peer) =
            tokio::time::timeout(std::time::Duration::from_secs(5), a.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();

        assert_eq!(&buf[..len], b"hello");
        assert_eq!(peer, b_addr);
    }

    #[tokio::test]
    async fn bind_ipv6_localhost_succeeds() {
        let socket = DualStackUdpSocket::bind("[::1]:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        assert!(addr.is_ipv6());
    }

    #[tokio::test]
    async fn bind_bad_address_fails() {
        assert!(DualStackUdpSocket::bind("not-an-address").await.is_err());
    }
}
