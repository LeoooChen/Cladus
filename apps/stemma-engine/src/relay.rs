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

/// SOCKS5 reachability/authentication only, without contacting a website.
pub async fn check_proxy(proxy: &ProxyEndpoint) -> Result<(), String> {
    timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
            .await
            .map_err(|err| format!("cannot reach SOCKS5 proxy: {err}"))?;
        socks5::negotiate(&mut stream, proxy.credentials.as_ref())
            .await
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|_| "SOCKS5 proxy check timed out".to_owned())?
}

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

/// Time to receive HTTP response headers through the proxy, including SOCKS5
/// connection and TLS. The proxy resolves the target name (socks5h), so local
/// DNS poisoning cannot turn a successful local handshake into a false result.
pub async fn probe(proxy: &ProxyEndpoint, url: &str) -> Result<Duration, String> {
    probe_with_timeout(proxy, url, Duration::from_secs(20)).await
}

async fn probe_with_timeout(
    proxy: &ProxyEndpoint,
    url: &str,
    limit: Duration,
) -> Result<Duration, String> {
    let target = reqwest::Url::parse(url).map_err(|err| format!("invalid test URL: {err}"))?;
    if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
        return Err("test URL must use http:// or https://".to_owned());
    }
    let mut endpoint = reqwest::Url::parse("socks5h://localhost").expect("built-in URL");
    endpoint
        .set_host(Some(&proxy.host))
        .map_err(|err| format!("invalid proxy host: {err}"))?;
    endpoint
        .set_port(Some(proxy.port))
        .map_err(|_| "invalid proxy port")?;
    let mut transport = reqwest::Proxy::all(endpoint).map_err(|err| err.to_string())?;
    if let Some(credentials) = &proxy.credentials {
        transport = transport.basic_auth(&credentials.username, &credentials.password);
    }
    // A fresh client prevents cached connections from hiding connection/TLS time.
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(transport)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(limit)
        .build()
        .map_err(|err| format!("cannot create website probe: {err}"))?;
    let started = std::time::Instant::now();
    timeout(limit, async {
        client
            .get(target)
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|err| format!("website probe failed: {err}"))?;
        Ok(started.elapsed())
    })
    .await
    .map_err(|_| "website response timed out".to_owned())?
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn health_check_negotiates_without_a_website_and_rejects_auth_failure() {
        for accepted in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = ProxyEndpoint {
                host: "127.0.0.1".into(),
                port: listener.local_addr().unwrap().port(),
                credentials: None,
            };
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream
                    .write_all(&[5, if accepted { 0 } else { 255 }])
                    .await
                    .unwrap();
                let mut byte = [0];
                assert_eq!(
                    stream.read(&mut byte).await.unwrap(),
                    0,
                    "health check must not open a website tunnel"
                );
            });
            assert_eq!(check_proxy(&proxy).await.is_ok(), accepted);
            server.await.unwrap();
        }
    }

    async fn website_proxy(
        delay: Duration,
        status: u16,
        close_after_handshake: bool,
    ) -> (ProxyEndpoint, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0; greeting[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(
                header,
                [5, 1, 0, 3],
                "target DNS must be resolved by the proxy"
            );
            let len = stream.read_u8().await.unwrap();
            let mut domain = vec![0; len as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"probe.invalid");
            let _port = stream.read_u16().await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            if close_after_handshake {
                return;
            }
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
            tokio::time::sleep(delay).await;
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (
            ProxyEndpoint {
                host: "127.0.0.1".into(),
                port,
                credentials: None,
            },
            server,
        )
    }

    #[tokio::test]
    async fn probe_waits_for_http_headers_and_uses_remote_dns() {
        let delay = Duration::from_millis(120);
        let (proxy, server) = website_proxy(delay, 204, false).await;
        let elapsed = probe(&proxy, "http://probe.invalid/health").await.unwrap();
        assert!(
            elapsed >= delay,
            "a SOCKS5 handshake is not website latency"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_rejects_http_error_and_failed_tls_after_successful_socks() {
        let (proxy, server) = website_proxy(Duration::ZERO, 502, false).await;
        assert!(
            probe(&proxy, "http://probe.invalid/health")
                .await
                .unwrap_err()
                .contains("502")
        );
        server.await.unwrap();
        let (proxy, server) = website_proxy(Duration::ZERO, 200, true).await;
        assert!(probe(&proxy, "https://probe.invalid/health").await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_timeout_covers_response_wait_and_can_be_cancelled() {
        let (proxy, server) = website_proxy(Duration::from_secs(5), 200, false).await;
        let result = probe_with_timeout(
            &proxy,
            "http://probe.invalid/health",
            Duration::from_millis(100),
        )
        .await;
        assert!(
            result.is_err(),
            "a nonresponding website must not produce a latency"
        );
        server.abort();
        let (proxy, server) = website_proxy(Duration::from_secs(5), 200, false).await;
        let task = tokio::spawn(async move { probe(&proxy, "http://probe.invalid/health").await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        task.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        server.abort();
    }

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
