// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test for dual-stack TCP listener functionality.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_dual_stack_listener_creation() {
    // This test verifies that the dual-stack listener can be created
    // and that it properly binds to both IPv4 and IPv6 addresses.

    let listener = sunbeam_proxy::dual_stack::DualStackTcpListener::bind(
        "[::]:0",    // IPv6 wildcard on a random port
        "0.0.0.0:0", // IPv4 wildcard on a random port
    )
    .await
    .expect("Failed to create dual-stack listener");

    let (ipv6_addr, ipv4_addr) = listener
        .local_addr()
        .expect("Failed to get local addresses");

    // Verify that we got valid addresses
    assert!(ipv6_addr.port() > 0, "IPv6 port should be valid");
    assert!(ipv4_addr.port() > 0, "IPv4 port should be valid");

    println!(
        "Dual-stack listener created successfully: IPv6={}, IPv4={}",
        ipv6_addr, ipv4_addr
    );
}

#[tokio::test]
async fn test_dual_stack_listener_with_connection() {
    // This test verifies that the dual-stack listener can accept connections
    // and communicate with clients. We use a timeout to prevent hanging.

    let listener = sunbeam_proxy::dual_stack::DualStackTcpListener::bind(
        "[::]:0",    // IPv6 wildcard on a random port
        "0.0.0.0:0", // IPv4 wildcard on a random port
    )
    .await
    .expect("Failed to create dual-stack listener");

    let (_, ipv4_addr) = listener
        .local_addr()
        .expect("Failed to get local addresses");

    // Create a channel to signal when the server has received the message
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Spawn a task to accept the connection
    let server_task = tokio::spawn(async move {
        let (mut socket, peer_addr) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("Accept timed out")
            .expect("Failed to accept connection");

        let mut buf = [0u8; 1024];
        let n = timeout(Duration::from_secs(1), socket.read(&mut buf))
            .await
            .expect("Read timed out")
            .expect("Failed to read from socket");

        let request = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(request, "test");

        timeout(Duration::from_secs(1), socket.write_all(b"response"))
            .await
            .expect("Write timed out")
            .expect("Failed to write response");

        // Drop the socket to close the connection
        drop(socket);

        tx.send(peer_addr).expect("Failed to send peer address");
    });

    // Give the server a moment to start listening
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect to the IPv4 address
    let ipv4_socket_addr = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 1),
        ipv4_addr.port(),
    ));

    let client_task = tokio::spawn(async move {
        let mut client = timeout(Duration::from_secs(2), TcpStream::connect(ipv4_socket_addr))
            .await
            .expect("Connect timed out")
            .expect("Failed to connect to IPv4 address");

        // Send a test message
        timeout(Duration::from_secs(1), client.write_all(b"test"))
            .await
            .expect("Write timed out")
            .expect("Failed to write to socket");

        // Read the response
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("Read timed out")
            .expect("Failed to read response");

        assert_eq!(response, b"response");

        // Close the client connection
        client.shutdown().await.expect("Failed to shutdown client");
    });

    // Wait for both tasks to complete with a timeout
    timeout(Duration::from_secs(5), async {
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    })
    .await
    .expect("Test timed out");

    // Verify the server received the connection
    let peer_addr = rx.await.expect("Failed to receive peer address");
    println!("Successfully accepted connection from: {}", peer_addr);
}
