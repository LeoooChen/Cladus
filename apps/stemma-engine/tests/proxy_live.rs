//! Opt-in real SOCKS5/HTTPS acceptance; no system settings are changed.
//! Set STEMMA_TEST_PROXY (IP:port) and STEMMA_TEST_URL, then run this ignored test.
use stemma_engine::relay::{ProxyEndpoint, check_proxy, probe};

#[tokio::test]
#[ignore = "requires an explicitly configured live SOCKS5 endpoint and website"]
async fn real_proxy_authentication_and_website_response() {
    let address: std::net::SocketAddr = std::env::var("STEMMA_TEST_PROXY")
        .expect("set STEMMA_TEST_PROXY to IP:port")
        .parse()
        .unwrap();
    let url = std::env::var("STEMMA_TEST_URL").expect("set STEMMA_TEST_URL");
    let proxy = ProxyEndpoint {
        host: address.ip().to_string(),
        port: address.port(),
        credentials: None,
    };
    check_proxy(&proxy).await.expect("SOCKS5 authentication");
    let elapsed = probe(&proxy, &url)
        .await
        .expect("HTTP(S) response through SOCKS5");
    println!(
        "SOCKS5 reachable; website response (including TLS): {} ms",
        elapsed.as_millis()
    );
}
