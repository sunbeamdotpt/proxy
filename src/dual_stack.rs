//! Dual-stack TCP listener implementation inspired by `tokio_dual_stack`.
//!
//! This module provides a `DualStackTcpListener` that can listen on both IPv4 and IPv6
//! addresses simultaneously, ensuring fair distribution of connections between both stacks.

use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::net::{TcpListener, TcpStream};

pin_project_lite::pin_project! {
    /// Future returned by [`DualStackTcpListener::accept`].
    struct AcceptFut<
        F: std::future::Future<Output = Result<(TcpStream, SocketAddr)>>,
        F2: std::future::Future<Output = Result<(TcpStream, SocketAddr)>>,
    > {
        #[pin]
        fut_1: F,
        #[pin]
        fut_2: F2,
    }
}

impl<
    F: std::future::Future<Output = Result<(TcpStream, SocketAddr)>>,
    F2: std::future::Future<Output = Result<(TcpStream, SocketAddr)>>,
> std::future::Future for AcceptFut<F, F2>
{
    type Output = Result<(TcpStream, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.fut_1.poll(cx) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => this.fut_2.poll(cx),
        }
    }
}

/// Dual-stack TCP listener that can handle both IPv4 and IPv6 connections.
#[derive(Debug)]
pub struct DualStackTcpListener {
    /// IPv6 TCP listener.
    ip6: TcpListener,
    /// IPv4 TCP listener.
    ip4: TcpListener,
    /// Alternates between IPv6 and IPv4 to ensure fair distribution of connections.
    ip6_first: AtomicBool,
}

impl DualStackTcpListener {
    /// Creates a new dual-stack listener by binding to both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    /// * `ipv6_addr` - The IPv6 address to bind to (e.g., "[::]:80").
    /// * `ipv4_addr` - The IPv4 address to bind to (e.g., "0.0.0.0:80").
    ///
    /// # Returns
    /// A `Result` containing the dual-stack listener if successful.
    pub async fn bind(ipv6_addr: &str, ipv4_addr: &str) -> Result<Self> {
        let ip6 = TcpListener::bind(ipv6_addr).await?;
        let ip4 = TcpListener::bind(ipv4_addr).await?;
        
        Ok(Self {
            ip6,
            ip4,
            ip6_first: AtomicBool::new(true),
        })
    }

    /// Accepts a new incoming connection from either the IPv4 or IPv6 listener.
    ///
    /// This method alternates between the IPv6 and IPv4 listeners to ensure
    /// fair distribution of connections.
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        if self.ip6_first.swap(false, Ordering::Relaxed) {
            AcceptFut {
                fut_1: self.ip6.accept(),
                fut_2: self.ip4.accept(),
            }
            .await
        } else {
            self.ip6_first.store(true, Ordering::Relaxed);
            AcceptFut {
                fut_1: self.ip4.accept(),
                fut_2: self.ip6.accept(),
            }
            .await
        }
    }

    /// Returns the local addresses of the IPv6 and IPv4 listeners.
    pub fn local_addr(&self) -> Result<(SocketAddrV6, SocketAddrV4)> {
        let ip6_addr = self.ip6.local_addr()?;
        let ip4_addr = self.ip4.local_addr()?;
        
        match (ip6_addr, ip4_addr) {
            (SocketAddr::V6(ip6), SocketAddr::V4(ip4)) => Ok((ip6, ip4)),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Unexpected address types for dual-stack listener",
            )),
        }
    }
}

/// Extension trait to add dual-stack binding capability to configuration structs.
pub trait DualStackBind {
    /// Binds to both IPv4 and IPv6 addresses for dual-stack support.
    ///
    /// # Arguments
    /// * `ipv6_addr` - The IPv6 address to bind to.
    /// * `ipv4_addr` - The IPv4 address to bind to.
    ///
    /// # Returns
    /// A `Result` containing the dual-stack listener if successful.
    fn bind_dual_stack(
        ipv6_addr: &str,
        ipv4_addr: &str,
    ) -> impl std::future::Future<Output = Result<DualStackTcpListener>> + Send;
}

impl DualStackBind for str {
    fn bind_dual_stack(
        ipv6_addr: &str,
        ipv4_addr: &str,
    ) -> impl std::future::Future<Output = Result<DualStackTcpListener>> + Send {
        DualStackTcpListener::bind(ipv6_addr, ipv4_addr)
    }
}