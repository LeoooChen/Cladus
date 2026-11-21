use super::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Debug, PartialEq, Eq)]
enum SeenTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

struct MockSocks {
    endpoint: ProxyEndpoint,
    targets: Arc<Mutex<Vec<SeenTarget>>>,
    payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn mock_socks(refuse_domain_atyp: bool, server_speaks_first: bool) -> MockSocks {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = ProxyEndpoint {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        credentials: None,
    };
    let targets = Arc::new(Mutex::new(Vec::new()));
    let payloads = Arc::new(Mutex::new(Vec::new()));
    let (seen, sent) = (targets.clone(), payloads.clone());
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (seen, sent) = (seen.clone(), sent.clone());
            tasks.spawn(async move {
                let mut hdr = [0u8; 4];
                stream.read_exact(&mut hdr[..3]).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                stream.read_exact(&mut hdr).await.unwrap();
                let target = match hdr[3] {
                    1 => {
                        let mut ip = [0u8; 4];
                        stream.read_exact(&mut ip).await.unwrap();
                        let port = stream.read_u16().await.unwrap();
                        SeenTarget::Ip(SocketAddr::from((ip, port)))
                    }
                    4 => {
                        let mut ip = [0u8; 16];
                        stream.read_exact(&mut ip).await.unwrap();
                        let port = stream.read_u16().await.unwrap();
                        SeenTarget::Ip(SocketAddr::from((ip, port)))
                    }
                    3 => {
                        let len = stream.read_u8().await.unwrap() as usize;
                        let mut host = vec![0u8; len];
                        stream.read_exact(&mut host).await.unwrap();
                        let port = stream.read_u16().await.unwrap();
                        SeenTarget::Domain(String::from_utf8(host).unwrap(), port)
                    }
                    other => panic!("unexpected ATYP {other}"),
                };
                seen.lock().unwrap().push(target.clone());
                if matches!(target, SeenTarget::Domain(..)) && refuse_domain_atyp {
                    // RFC 1928 reply 0x08: Address type not supported.
                    stream
                        .write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    return;
                }
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                if server_speaks_first {
                    stream.write_all(b"SSH-2.0-test\r\n").await.unwrap();
                }
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                sent.lock().unwrap().push(data);
                if !server_speaks_first {
                    stream.write_all(b"ok").await.unwrap();
                }
            });
        }
    });
    MockSocks {
        endpoint,
        targets,
        payloads,
        task,
    }
}

#[tokio::test]
async fn sni_routes_both_ipv4_and_ipv6_by_domain_ignoring_poisoned_ip() {
    for target_str in ["198.51.100.1:443", "[2001:db8::99]:443"] {
        let hello = crate::tls_hello::tests::hello("api.example.com", &[]);
        let proxy = mock_socks(false, false).await;
        let counters = Arc::new(RelayCounters::default());
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
        let target: SocketAddr = target_str.parse().unwrap();
        let task = tokio::spawn(async move {
            relay_with_sni(client, &endpoint, target, true, None, &counts).await
        });

        let mut payload = hello.clone();
        payload.extend_from_slice(b"app-data");
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"ok");
        assert_eq!(task.await.unwrap().unwrap(), (payload.len() as u64, 2));
        assert_eq!(counters.sni_routed.load(Relaxed), 1);
        assert_eq!(
            *proxy.targets.lock().unwrap(),
            [SeenTarget::Domain("api.example.com".into(), 443)]
        );
        assert_eq!(*proxy.payloads.lock().unwrap(), [payload]);
    }
}

#[tokio::test]
async fn legacy_proxy_refusing_domain_atyp_falls_back_to_ip() {
    let hello = crate::tls_hello::tests::hello("api.example.com", &[]);
    let proxy = mock_socks(true, false).await;
    let counters = Arc::new(RelayCounters::default());
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
    let target: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let task = tokio::spawn(async move {
        relay_with_sni(client, &endpoint, target, true, None, &counts).await
    });

    app.write_all(&hello).await.unwrap();
    app.shutdown().await.unwrap();
    let mut reply = Vec::new();
    app.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"ok");
    task.await.unwrap().unwrap();
    assert_eq!(counters.sni_routed.load(Relaxed), 0);
    assert_eq!(counters.sni_fallback_to_ip.load(Relaxed), 1);
    assert_eq!(
        *proxy.targets.lock().unwrap(),
        [
            SeenTarget::Domain("api.example.com".into(), 443),
            SeenTarget::Ip(target),
        ]
    );
    assert_eq!(*proxy.payloads.lock().unwrap(), [hello]);
}

#[tokio::test]
async fn grease_ech_client_hello_is_still_routed_by_sni() {
    let hello = crate::tls_hello::tests::hello("api.example.com", &[0xfe, 0x0d, 0, 0]);
    let proxy = mock_socks(false, false).await;
    let counters = Arc::new(RelayCounters::default());
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
    let target: SocketAddr = "[2001:db8::99]:443".parse().unwrap();
    let task = tokio::spawn(async move {
        relay_with_sni(client, &endpoint, target, true, None, &counts).await
    });

    app.write_all(&hello).await.unwrap();
    app.shutdown().await.unwrap();
    let mut reply = Vec::new();
    app.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"ok");
    task.await.unwrap().unwrap();
    assert_eq!(counters.sni_routed.load(Relaxed), 1);
    assert_eq!(
        *proxy.targets.lock().unwrap(),
        [SeenTarget::Domain("api.example.com".into(), 443)]
    );
    assert_eq!(*proxy.payloads.lock().unwrap(), [hello]);
}

#[tokio::test]
async fn local_names_non_tls_and_disabled_policy_keep_ip_routing() {
    let cases: Vec<(Vec<u8>, bool)> = vec![
        (crate::tls_hello::tests::hello("service.local", &[]), true),
        (b"GET / HTTP/1.1\r\n\r\n".to_vec(), true),
        (
            crate::tls_hello::tests::hello("api.example.com", &[]),
            false,
        ),
    ];
    for (data, sni_allowed) in cases {
        let proxy = mock_socks(false, false).await;
        let counters = Arc::new(RelayCounters::default());
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
        let target: SocketAddr = "203.0.113.20:443".parse().unwrap();
        let task = tokio::spawn(async move {
            relay_with_sni(client, &endpoint, target, sni_allowed, None, &counts).await
        });

        app.write_all(&data).await.unwrap();
        app.shutdown().await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"ok");
        task.await.unwrap().unwrap();
        assert_eq!(counters.sni_routed.load(Relaxed), 0);
        assert_eq!(*proxy.targets.lock().unwrap(), [SeenTarget::Ip(target)]);
        assert_eq!(*proxy.payloads.lock().unwrap(), [data]);
    }
}

#[tokio::test]
async fn non_443_server_speaks_first_does_not_wait_for_client_bytes() {
    let proxy = mock_socks(false, true).await;
    let counters = Arc::new(RelayCounters::default());
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
    let target: SocketAddr = "203.0.113.30:22".parse().unwrap();
    let task = tokio::spawn(async move {
        relay_with_sni(client, &endpoint, target, true, None, &counts).await
    });

    // Server banner arrives immediately (< 500ms, well below the 1s hello timeout).
    let mut banner = [0u8; 14];
    timeout(Duration::from_millis(500), app.read_exact(&mut banner))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&banner, b"SSH-2.0-test\r\n");
    app.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(*proxy.targets.lock().unwrap(), [SeenTarget::Ip(target)]);
}
