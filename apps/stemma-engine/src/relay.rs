//! Relaying redirected TCP connections through a SOCKS5 proxy.

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::time::Duration;

use stemma_core::config::ProxyGroup;
use stemma_core::platform::Counter;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::socks5::{self, Credentials, Socks5Error};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub credentials: Option<Credentials>,
}

impl From<&ProxyGroup> for ProxyEndpoint {
    fn from(group: &ProxyGroup) -> Self {
        Self {
            host: group.host.clone(),
            port: group.port,
            credentials: (!group.username.is_empty()).then(|| Credentials {
                username: group.username.clone(),
                password: group.password.clone(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("cannot reach proxy {0}: {1}")]
    Connect(String, std::io::Error),
    #[error("proxy {0} did not answer in time")]
    Timeout(String),
    #[error(transparent)]
    Socks5(#[from] Socks5Error),
}

#[derive(Default)]
pub struct RelayCounters {
    pub started: AtomicU64,
    pub failed: AtomicU64,
    pub active: AtomicI64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

impl RelayCounters {
    pub fn snapshot(&self) -> Vec<Counter> {
        vec![
            Counter {
                name: "relay.started",
                value: self.started.load(Relaxed),
            },
            Counter {
                name: "relay.failed",
                value: self.failed.load(Relaxed),
            },
            Counter {
                name: "relay.active",
                value: self.active.load(Relaxed).max(0) as u64,
            },
            Counter {
                name: "relay.bytes_up",
                value: self.bytes_up.load(Relaxed),
            },
            Counter {
                name: "relay.bytes_down",
                value: self.bytes_down.load(Relaxed),
            },
        ]
    }
}

/// Connects to `proxy`, asks it for `target` and copies data both ways until
/// either side closes. Returns the bytes sent to and received from `target`.
pub async fn relay(
    mut client: TcpStream,
    proxy: &ProxyEndpoint,
    target: SocketAddr,
) -> Result<(u64, u64), RelayError> {
    let name = format!("{}:{}", proxy.host, proxy.port);
    let mut upstream = match timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((proxy.host.as_str(), proxy.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(RelayError::Connect(name, err)),
        Err(_) => return Err(RelayError::Timeout(name)),
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    timeout(
        HANDSHAKE_TIMEOUT,
        socks5::connect(&mut upstream, target, proxy.credentials.as_ref()),
    )
    .await
    .map_err(|_| RelayError::Timeout(name))??;
    // Errors after the tunnel is up are ordinary disconnects.
    Ok(
        copy_bidirectional_with_sizes(&mut client, &mut upstream, BUFFER_SIZE, BUFFER_SIZE)
            .await
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A SOCKS5 server that accepts one CONNECT and echoes the tunnel.
    async fn echo_proxy() -> (u16, tokio::task::JoinHandle<SocketAddr>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            let target = SocketAddr::from((
                [request[4], request[5], request[6], request[7]],
                u16::from_be_bytes([request[8], request[9]]),
            ));
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
            target
        });
        (port, server)
    }

    #[tokio::test]
    async fn relays_both_directions_through_the_proxy() {
        let (proxy_port, server) = echo_proxy().await;
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (redirected, _) = local.accept().await.unwrap();
        let proxy = ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: proxy_port,
            credentials: None,
        };
        let target: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let relay = tokio::spawn(async move { relay(redirected, &proxy, target).await });

        app.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        app.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        app.shutdown().await.unwrap();

        assert_eq!(relay.await.unwrap().unwrap(), (5, 5));
        assert_eq!(server.await.unwrap(), target);
    }

    #[tokio::test]
    async fn unreachable_proxy_is_an_error() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = unused.local_addr().unwrap().port();
        drop(unused);
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (redirected, _) = local.accept().await.unwrap();
        let proxy = ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port,
            credentials: None,
        };
        let result = relay(redirected, &proxy, "203.0.113.10:443".parse().unwrap()).await;
        assert!(matches!(result, Err(RelayError::Connect(..))), "{result:?}");
    }
}
