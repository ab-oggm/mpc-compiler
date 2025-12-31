use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// Minimal handshake: client sends its party_id as 8 bytes LE.
/// Server logs incoming connections and replies "OK".
pub async fn serve_p2p(bind_addr: &str) -> Result<()> {
    let addr: SocketAddr = bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("p2p listener bound on {}", addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            match handle_incoming(&mut socket, peer_addr).await {
                Ok(_) => {}
                Err(e) => warn!("p2p incoming error from {}: {}", peer_addr, e),
            }
        });
    }
}

async fn handle_incoming(socket: &mut TcpStream, peer_addr: SocketAddr) -> Result<()> {
    let mut buf = [0u8; 8];
    socket.read_exact(&mut buf).await?;
    let remote_party_id = u64::from_le_bytes(buf);
    info!("p2p incoming: connected from party_id={} ({})", remote_party_id, peer_addr);

    socket.write_all(b"OK").await?;
    Ok(())
}

/// Attempt a TCP connection to `addr` and send `my_party_id` as handshake.
/// Returns Ok(()) on success.
pub async fn connect_and_handshake(addr: &str, my_party_id: u64, timeout_ms: u64) -> Result<()> {
    let fut = TcpStream::connect(addr);
    let mut stream = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut)
        .await
        .map_err(|_| anyhow!("connect timeout"))??;

    // Send my party_id
    stream.write_all(&my_party_id.to_le_bytes()).await?;

    // Read response
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if &resp != b"OK" {
        return Err(anyhow!("bad handshake response"));
    }
    Ok(())
}
