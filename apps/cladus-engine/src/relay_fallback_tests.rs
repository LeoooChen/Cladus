use super::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const HOST: &str = "service.example";
const V6: &str = "[2001:db8::10]:443";
const V4: &str = "203.0.113.10:443";
const POST: &[u8] = b"POST /v1/responses HTTP/1.1\r\n\r\nunique-request";
type RecordedPayloads = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

struct Proxy {
    endpoint: ProxyEndpoint,
    targets: Arc<Mutex<Vec<SocketAddr>>>,
    payloads: RecordedPayloads,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn an_unresponsive_handshake_times_out_and_releases_the_socket() {
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = local.accept().await.unwrap();
    let task = tokio::spawn(async move { first_response(upstream, b"hello").await });
    let mut hello = [0; 5];
    peer.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    let result = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(RelayError::Timeout(_))));
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn proxy(
    hello_len: usize,
    ipv6_works: bool,
    reset_after_post: bool,
    dns_matches: bool,
) -> Proxy {
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
                let mut header = [0u8; 4];
                stream.read_exact(&mut header[..3]).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                stream.read_exact(&mut header).await.unwrap();
                let ip = if header[3] == 4 {
                    let mut ip = [0; 16];
                    stream.read_exact(&mut ip).await.unwrap();
                    std::net::IpAddr::from(ip)
                } else {
                    assert_eq!(header[3], 1);
                    let mut ip = [0; 4];
                    stream.read_exact(&mut ip).await.unwrap();
                    std::net::IpAddr::from(ip)
                };
                let port = stream.read_u16().await.unwrap();
                let target = SocketAddr::new(ip, port);
                seen.lock().unwrap().push(target);
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                if port == 53 {
                    let len = stream.read_u16().await.unwrap();
                    let mut q = vec![0; len as usize];
                    stream.read_exact(&mut q).await.unwrap();
                    let kind = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
                    let mut answer = q;
                    answer[2] = 0x81;
                    answer[3] = 0x80;
                    answer[7] = 1;
                    answer.extend([0xc0, 12]);
                    answer.extend(kind.to_be_bytes());
                    answer.extend([0, 1, 0, 0, 0, 30]);
                    if kind == 1 {
                        answer.extend([0, 4, 203, 0, 113, 10]);
                    } else {
                        let ip: std::net::Ipv6Addr = if dns_matches {
                            "2001:db8::10"
                        } else {
                            "2001:db8::99"
                        }
                        .parse()
                        .unwrap();
                        answer.extend([0, 16]);
                        answer.extend(ip.octets());
                    }
                    stream
                        .write_all(&(answer.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    stream.write_all(&answer).await.unwrap();
                    return;
                }
                let mut initial = vec![0; hello_len];
                stream.read_exact(&mut initial).await.unwrap();
                if ip.is_ipv6() && !ipv6_works {
                    sent.lock().unwrap().push((target, initial));
                    return; // SOCKS success followed by EOF: the observed failure
                }
                stream.write_all(b"S").await.unwrap();
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                initial.extend(data);
                sent.lock().unwrap().push((target, initial));
                if reset_after_post {
                    socket2::SockRef::from(&stream)
                        .set_linger(Some(Duration::ZERO))
                        .unwrap();
                } else {
                    stream.write_all(b"reply").await.unwrap();
                }
            });
        }
    });
    Proxy {
        endpoint,
        targets,
        payloads,
        task,
    }
}

#[tokio::test]
async fn ipv6_eof_falls_back_without_replaying_the_post() {
    let hello = crate::tls_hello::tests::hello(HOST, &[]);
    let proxy = proxy(hello.len(), false, false, true).await;
    let counters = Arc::new(RelayCounters::default());
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
    let task = tokio::spawn(async move {
        relay_with_fallback(
            client,
            &endpoint,
            V6.parse().unwrap(),
            Ipv6Fallback {
                resolver: "192.0.2.53:53".parse().unwrap(),
                allows: &|_| true,
                counters: &counts,
            },
        )
        .await
    });
    app.write_all(&hello).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), app.read_u8())
            .await
            .unwrap()
            .unwrap(),
        b'S'
    );
    app.write_all(POST).await.unwrap();
    app.shutdown().await.unwrap();
    let mut response = Vec::new();
    app.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"reply");
    assert_eq!(
        task.await.unwrap().unwrap(),
        ((hello.len() + POST.len()) as u64, 6)
    );
    assert_eq!(counters.ipv4_fallback_selected.load(Relaxed), 1);
    let payloads = proxy.payloads.lock().unwrap();
    assert_eq!(payloads.iter().find(|(t, _)| t.is_ipv6()).unwrap().1, hello);
    assert_eq!(
        payloads.iter().filter(|(_, p)| p.ends_with(POST)).count(),
        1
    );
    assert!(proxy.targets.lock().unwrap().contains(&V4.parse().unwrap()));
}

#[tokio::test]
async fn healthy_ipv6_and_midstream_resets_never_retry_or_query_dns() {
    for reset in [false, true] {
        let hello = crate::tls_hello::tests::hello(HOST, &[]);
        let proxy = proxy(hello.len(), true, reset, true).await;
        let counters = Arc::new(RelayCounters::default());
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        let (endpoint, counts) = (proxy.endpoint.clone(), counters.clone());
        let task = tokio::spawn(async move {
            relay_with_fallback(
                client,
                &endpoint,
                V6.parse().unwrap(),
                Ipv6Fallback {
                    resolver: "192.0.2.53:53".parse().unwrap(),
                    allows: &|_| true,
                    counters: &counts,
                },
            )
            .await
        });
        app.write_all(&hello).await.unwrap();
        assert_eq!(app.read_u8().await.unwrap(), b'S');
        app.write_all(POST).await.unwrap();
        app.shutdown().await.unwrap();
        let mut response = Vec::new();
        let _ = app.read_to_end(&mut response).await;
        let result = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        if reset {
            assert!(matches!(result, Err(RelayError::Transfer(_))), "{result:?}");
        } else {
            assert_eq!(result.unwrap(), ((hello.len() + POST.len()) as u64, 6));
        }
        assert_eq!(counters.ipv4_fallback_attempted.load(Relaxed), 0);
        assert_eq!(*proxy.targets.lock().unwrap(), [V6.parse().unwrap()]);
    }
}

#[tokio::test]
async fn destination_policy_and_dns_identity_cannot_be_bypassed() {
    for (allowed, matched) in [(false, true), (true, false)] {
        let hello = crate::tls_hello::tests::hello(HOST, &[]);
        let proxy = proxy(hello.len(), false, false, matched).await;
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        app.write_all(&hello).await.unwrap();
        let counts = RelayCounters::default();
        let result = relay_with_fallback(
            client,
            &proxy.endpoint,
            V6.parse().unwrap(),
            Ipv6Fallback {
                resolver: "192.0.2.53:53".parse().unwrap(),
                allows: &move |_| allowed,
                counters: &counts,
            },
        )
        .await;
        assert!(
            matches!(result, Err(RelayError::Fallback { .. })),
            "{result:?}"
        );
        assert_eq!(counts.ipv4_fallback_failed.load(Relaxed), 1);
        assert!(!proxy.targets.lock().unwrap().contains(&V4.parse().unwrap()));
    }
}

#[tokio::test]
async fn early_data_is_passed_once_without_fallback() {
    let hello = crate::tls_hello::tests::hello(HOST, &[0, 42, 0, 0]);
    let proxy = proxy(hello.len(), false, false, true).await;
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    app.write_all(&hello).await.unwrap();
    app.shutdown().await.unwrap();
    let counts = RelayCounters::default();
    let _ = timeout(
        Duration::from_secs(5),
        relay_with_fallback(
            client,
            &proxy.endpoint,
            V6.parse().unwrap(),
            Ipv6Fallback {
                resolver: "192.0.2.53:53".parse().unwrap(),
                allows: &|_| true,
                counters: &counts,
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(*proxy.targets.lock().unwrap(), [V6.parse().unwrap()]);
    assert_eq!(counts.ipv4_fallback_attempted.load(Relaxed), 0);
}
