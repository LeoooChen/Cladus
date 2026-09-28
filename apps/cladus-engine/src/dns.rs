//! Local DNS forwarder.
//!
//! Listens on UDP and TCP, sends every query to the upstream resolver over
//! one pipelined TCP connection through the SOCKS5 proxy, and matches
//! answers by rewritten transaction IDs, so clients that happen to use the
//! same ID never see each other's answers. When the proxy path fails, queries
//! go directly to the system's original servers unless strict mode is on.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cladus_core::platform::Counter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::relay::ProxyEndpoint;
use crate::socks5;

const HEADER: usize = 12;
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(2);
/// Consecutive proxy-path failures before falling back for a while.
const FAILURE_LIMIT: u32 = 3;
const UNHEALTHY_FOR: Duration = Duration::from_secs(30);
const MAX_PENDING: usize = 4096;
const MAX_TCP_CLIENTS: usize = 128;

#[derive(Clone, Debug)]
pub struct DnsSettings {
    pub upstream: SocketAddr,
    pub proxy: Option<Arc<ProxyEndpoint>>,
    pub strict: bool,
    /// The system's original servers, used when the proxy path fails.
    pub fallback: Vec<IpAddr>,
}

#[derive(Default)]
pub struct DnsCounters {
    pub queries: AtomicU64,
    pub proxied: AtomicU64,
    pub fallback: AtomicU64,
    pub failed: AtomicU64,
    pub fallback_active: AtomicU64,
}

impl DnsCounters {
    pub fn snapshot(&self) -> Vec<Counter> {
        let c = |name, value: &AtomicU64| Counter {
            name,
            value: value.load(Relaxed),
        };
        vec![
            c("dns.queries", &self.queries),
            c("dns.proxied", &self.proxied),
            c("dns.fallback", &self.fallback),
            c("dns.failed", &self.failed),
            c("dns.fallback_active", &self.fallback_active),
        ]
    }
}

struct Shared {
    settings: RwLock<DnsSettings>,
    counters: Arc<DnsCounters>,
    upstream: mpsc::Sender<Query>,
    changed: tokio::sync::Notify,
}

struct Query {
    message: Vec<u8>,
    reply: oneshot::Sender<Option<Vec<u8>>>,
}

/// Runs until dropped.
pub struct DnsForwarder {
    shared: Arc<Shared>,
    tasks: JoinSet<()>,
}

impl DnsForwarder {
    /// Listens on UDP and TCP at every address. Only the first is required.
    pub fn start(
        runtime: &Handle,
        listen: &[SocketAddr],
        settings: DnsSettings,
        counters: Arc<DnsCounters>,
    ) -> io::Result<Self> {
        let _guard = runtime.enter();
        let (tx, rx) = mpsc::channel(1024);
        let shared = Arc::new(Shared {
            settings: RwLock::new(settings),
            counters,
            upstream: tx,
            changed: tokio::sync::Notify::new(),
        });
        let mut tasks = JoinSet::new();
        let mut sockets = Vec::new();
        for addr in listen {
            let bound = (|| {
                let udp = std::net::UdpSocket::bind(addr)?;
                udp.set_nonblocking(true)?;
                let tcp = std::net::TcpListener::bind(addr)?;
                tcp.set_nonblocking(true)?;
                Ok::<_, io::Error>((UdpSocket::from_std(udp)?, TcpListener::from_std(tcp)?))
            })();
            match bound {
                Ok(pair) => sockets.push(pair),
                // IPv6 may be disabled. Its DNS still points here and fails
                // fast, so the resolver uses the IPv4 forwarder.
                Err(err) if addr.is_ipv6() && !sockets.is_empty() => {
                    warn!(%addr, "DNS forwarder cannot listen: {err}");
                }
                Err(err) => return Err(err),
            }
        }
        tasks.spawn_on(upstream_task(Arc::clone(&shared), rx), runtime);
        for (udp, tcp) in sockets {
            info!(addr = %udp.local_addr()?, "DNS forwarder listening");
            tasks.spawn_on(serve_udp(Arc::clone(&shared), Arc::new(udp)), runtime);
            tasks.spawn_on(serve_tcp(Arc::clone(&shared), tcp), runtime);
        }
        Ok(Self { shared, tasks })
    }

    pub fn update(&self, settings: DnsSettings) {
        *self.shared.settings.write().unwrap() = settings;
        self.shared.changed.notify_one();
    }

    pub fn fallback(&self) -> Vec<IpAddr> {
        self.shared.settings.read().unwrap().fallback.clone()
    }

    pub fn set_fallback(&self, servers: Vec<IpAddr>) {
        self.shared.settings.write().unwrap().fallback = servers;
    }
}

impl Drop for DnsForwarder {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

async fn serve_udp(shared: Arc<Shared>, socket: Arc<UdpSocket>) {
    let mut buffer = vec![0u8; 4096];
    let mut requests = JoinSet::new();
    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buffer) => received,
            Some(_) = requests.join_next(), if !requests.is_empty() => continue,
        };
        let (len, client) = match received {
            Ok(received) => received,
            // Windows reports ICMP port-unreachable for earlier sends this way.
            Err(err) if err.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(err) => {
                warn!(%err, "DNS UDP listener failed");
                return;
            }
        };
        if requests.len() >= MAX_PENDING {
            shared.counters.failed.fetch_add(1, Relaxed);
            continue;
        }
        let query = buffer[..len].to_vec();
        let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
        requests.spawn(async move {
            let Some(answer) = resolve(&shared, query.clone(), false).await else {
                return;
            };
            let answer = truncate_for_udp(&query, answer);
            let _ = socket.send_to(&answer, client).await;
        });
    }
}

async fn serve_tcp(shared: Arc<Shared>, listener: TcpListener) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CLIENTS));
    let mut clients = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            Some(_) = clients.join_next(), if !clients.is_empty() => continue,
        };
        let Ok((mut stream, _)) = accepted else {
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };
        let shared = Arc::clone(&shared);
        clients.spawn(async move {
            let _permit = permit;
            loop {
                let Ok(Ok(query)) = timeout(Duration::from_secs(10), read_frame(&mut stream)).await
                else {
                    return;
                };
                let Some(answer) = resolve(&shared, query, true).await else {
                    return;
                };
                if !matches!(
                    timeout(Duration::from_secs(10), write_frame(&mut stream, &answer)).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
            }
        });
    }
}

/// `None` only for input that is not a DNS query at all.
async fn resolve(shared: &Shared, query: Vec<u8>, tcp: bool) -> Option<Vec<u8>> {
    if query.len() < HEADER || query[2] & 0x80 != 0 {
        return None;
    }
    shared.counters.queries.fetch_add(1, Relaxed);
    let (tx, rx) = oneshot::channel();
    let proxied = shared
        .upstream
        .try_send(Query {
            message: query.clone(),
            reply: tx,
        })
        .is_ok();
    if proxied && let Ok(Ok(Some(answer))) = timeout(QUERY_TIMEOUT, rx).await {
        shared.counters.proxied.fetch_add(1, Relaxed);
        return Some(answer);
    }
    let (strict, fallback) = {
        let settings = shared.settings.read().unwrap();
        (settings.strict, settings.fallback.clone())
    };
    if !strict {
        for server in fallback {
            if let Ok(Ok(answer)) = timeout(
                FALLBACK_TIMEOUT,
                direct(&query, SocketAddr::new(server, 53), tcp),
            )
            .await
            {
                shared.counters.fallback.fetch_add(1, Relaxed);
                return Some(answer);
            }
        }
    }
    shared.counters.failed.fetch_add(1, Relaxed);
    Some(servfail(&query))
}

async fn direct(query: &[u8], server: SocketAddr, tcp: bool) -> io::Result<Vec<u8>> {
    if tcp {
        let mut stream = TcpStream::connect(server).await?;
        write_frame(&mut stream, query).await?;
        return read_frame(&mut stream).await;
    }
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(server).await?;
    socket.send(query).await?;
    let mut buffer = vec![0u8; 4096];
    loop {
        let len = socket.recv(&mut buffer).await?;
        if len >= HEADER && buffer[..2] == query[..2] {
            return Ok(buffer[..len].to_vec());
        }
    }
}

struct Pending {
    id: u16,
    message: Vec<u8>,
    reply: oneshot::Sender<Option<Vec<u8>>>,
    deadline: Instant,
}

struct Upstream {
    writer: tokio::net::tcp::OwnedWriteHalf,
    answers: mpsc::Receiver<Vec<u8>>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Owns the upstream connection and every in-flight query.
async fn upstream_task(shared: Arc<Shared>, mut queries: mpsc::Receiver<Query>) {
    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut next_id: u16 = rand_seed();
    let mut connection: Option<Upstream> = None;
    let mut failures = 0u32;
    let mut unhealthy_until: Option<Instant> = None;
    loop {
        let next_deadline = pending.values().map(|p| p.deadline).min();
        tokio::select! {
            // Apply updates before queued queries; drain answers and deadlines
            // before more sends so sustained input cannot starve either.
            biased;
            () = shared.changed.notified() => {
                connection = None;
                fail_all(&mut pending);
                unhealthy_until = None;
                failures = 0;
                shared.counters.fallback_active.store(0, Relaxed);
            }
            answer = async { connection.as_mut().expect("guarded").answers.recv().await }, if connection.is_some() => {
                match answer {
                    Some(mut answer) => {
                        let id = u16::from_be_bytes([answer[0], answer[1]]);
                        if let Some(p) = pending.remove(&id) {
                            failures = 0;
                            answer[..2].copy_from_slice(&p.id.to_be_bytes());
                            let _ = p.reply.send(Some(answer));
                        }
                    }
                    None => {
                        // The resolver closed an idle connection; queries sent
                        // on it go out again on the next one.
                        debug!("DNS upstream connection closed");
                        connection = None;
                        let settings = shared.settings.read().unwrap().clone();
                        if !pending.is_empty() {
                            match open(&settings).await {
                                Ok(mut opened) => {
                                    for p in pending.values() {
                                        if !matches!(timeout(QUERY_TIMEOUT, write_frame(&mut opened.writer, &p.message)).await, Ok(Ok(()))) {
                                            break;
                                        }
                                    }
                                    connection = Some(opened);
                                }
                                Err(_) => fail_all(&mut pending),
                            }
                        }
                    }
                }
            }
            () = async { sleep_until(next_deadline.expect("guarded")).await }, if next_deadline.is_some() => {
                let now = Instant::now();
                let expired: Vec<u16> = pending.iter().filter(|(_, p)| p.deadline <= now).map(|(id, _)| *id).collect();
                for id in expired {
                    if let Some(p) = pending.remove(&id) {
                        let _ = p.reply.send(None);
                    }
                    failures += 1;
                }
                if failures >= FAILURE_LIMIT {
                    warn!("DNS through the proxy keeps timing out; using the original servers for a while");
                    failures = 0;
                    connection = None;
                    fail_all(&mut pending);
                    unhealthy_until = Some(now + UNHEALTHY_FOR);
                    shared.counters.fallback_active.store(1, Relaxed);
                }
            }
            query = queries.recv() => {
                let Some(query) = query else { return };
                let now = Instant::now();
                if unhealthy_until.is_some_and(|until| now < until) || pending.len() >= MAX_PENDING {
                    let _ = query.reply.send(None);
                    continue;
                }
                if unhealthy_until.take().is_some() {
                    shared.counters.fallback_active.store(0, Relaxed);
                }
                if connection.is_none() {
                    let settings = shared.settings.read().unwrap().clone();
                    match open(&settings).await {
                        Ok(opened) => connection = Some(opened),
                        Err(err) => {
                            warn!(upstream = %settings.upstream, "DNS proxy path failed: {err}");
                            let _ = query.reply.send(None);
                            unhealthy_until = Some(Instant::now() + UNHEALTHY_FOR);
                            shared.counters.fallback_active.store(1, Relaxed);
                            continue;
                        }
                    }
                }
                while pending.contains_key(&next_id) {
                    next_id = next_id.wrapping_add(1);
                }
                let id = next_id;
                next_id = next_id.wrapping_add(1);
                let mut message = query.message;
                let original = u16::from_be_bytes([message[0], message[1]]);
                message[..2].copy_from_slice(&id.to_be_bytes());
                let writer = &mut connection.as_mut().expect("connected above").writer;
                if !matches!(timeout(QUERY_TIMEOUT, write_frame(writer, &message)).await, Ok(Ok(()))) {
                    connection = None;
                    let _ = query.reply.send(None);
                    continue;
                }
                pending.insert(id, Pending { id: original, message, reply: query.reply, deadline: now + QUERY_TIMEOUT });
            }
        }
    }
}

fn fail_all(pending: &mut HashMap<u16, Pending>) {
    for (_, p) in pending.drain() {
        let _ = p.reply.send(None);
    }
}

async fn open(settings: &DnsSettings) -> io::Result<Upstream> {
    let proxy = settings
        .proxy
        .as_ref()
        .ok_or_else(|| io::Error::other("no such proxy group"))?;
    let stream = timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
        socks5::connect(&mut stream, settings.upstream, proxy.credentials.as_ref())
            .await
            .map_err(io::Error::other)?;
        Ok::<_, io::Error>(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy did not answer in time"))??;
    let (mut reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel(256);
    let task = tokio::spawn(async move {
        while let Ok(answer) = read_frame(&mut reader).await {
            if answer.len() < HEADER || tx.send(answer).await.is_err() {
                return;
            }
        }
    });
    Ok(Upstream {
        writer,
        answers: rx,
        reader: task,
    })
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u16().await? as usize;
    let mut message = vec![0u8; len];
    reader.read_exact(&mut message).await?;
    Ok(message)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, message: &[u8]) -> io::Result<()> {
    let len =
        u16::try_from(message.len()).map_err(|_| io::Error::other("DNS message too large"))?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    writer.write_all(&frame).await
}

fn rand_seed() -> u16 {
    use std::hash::{BuildHasher, RandomState};
    RandomState::new().hash_one(std::time::SystemTime::now()) as u16
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let end = question_end(query).unwrap_or(HEADER);
    let mut answer = query[..end].to_vec();
    answer[2] = 0x80 | (query[2] & 0x79); // QR, keep opcode and RD
    answer[3] = 0x80 | 2; // RA, SERVFAIL
    answer[4..6].copy_from_slice(if end > HEADER { &query[4..6] } else { &[0, 0] });
    answer[6..12].fill(0);
    answer
}

/// Answers that do not fit the client's UDP limit are replaced by a
/// truncated answer, which makes the client retry over TCP.
fn truncate_for_udp(query: &[u8], answer: Vec<u8>) -> Vec<u8> {
    let limit = udp_limit(query);
    if answer.len() <= limit {
        return answer;
    }
    let end = question_end(&answer).unwrap_or(HEADER);
    let mut short = answer[..end].to_vec();
    short[2] |= 0x02; // TC
    short[6..12].fill(0);
    short
}

/// 512 bytes, or the EDNS payload size the client advertised.
fn udp_limit(query: &[u8]) -> usize {
    let count = |i: usize| u16::from_be_bytes([query[i], query[i + 1]]) as usize;
    let Some(mut at) = question_end(query) else {
        return 512;
    };
    let records = count(6) + count(8) + count(10);
    for _ in 0..records {
        let Some(name_end) = skip_name(query, at) else {
            return 512;
        };
        if name_end + 10 > query.len() {
            return 512;
        }
        let rtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let class = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]) as usize;
        if rtype == 41 {
            return class.clamp(512, 4096);
        }
        let rdlen = u16::from_be_bytes([query[name_end + 8], query[name_end + 9]]) as usize;
        at = name_end + 10 + rdlen;
    }
    512
}

fn question_end(message: &[u8]) -> Option<usize> {
    if message.len() < HEADER {
        return None;
    }
    let mut at = HEADER;
    for _ in 0..u16::from_be_bytes([message[4], message[5]]) {
        at = skip_name(message, at)? + 4;
        if at > message.len() {
            return None;
        }
    }
    Some(at)
}

fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)? as usize;
        match len {
            0 => return Some(at + 1),
            l if l & 0xC0 == 0xC0 => return (at + 2 <= message.len()).then_some(at + 2),
            l => at += 1 + l,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tagged_proxy(tag: &'static [u8]) -> Arc<ProxyEndpoint> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 10];
                    stream.read_exact(&mut head[..3]).await.unwrap();
                    stream.write_all(&[5, 0]).await.unwrap();
                    stream.read_exact(&mut head).await.unwrap();
                    stream
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    while let Ok(query) = read_frame(&mut stream).await {
                        if write_frame(&mut stream, &answer_for(&query, tag))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        Arc::new(ProxyEndpoint {
            host: "127.0.0.1".into(),
            port,
            credentials: None,
        })
    }

    #[tokio::test]
    async fn reconfiguration_reconnects_and_drop_releases_tcp_clients() {
        let mut settings = DnsSettings {
            upstream: "192.0.2.53:53".parse().unwrap(),
            proxy: Some(tagged_proxy(b"first").await),
            strict: true,
            fallback: vec![],
        };
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let forwarder = DnsForwarder::start(
            &Handle::current(),
            &[listen],
            settings.clone(),
            Arc::default(),
        )
        .unwrap();
        let first = resolve(&forwarder.shared, query(1, None), true)
            .await
            .unwrap();
        assert!(first.ends_with(b"first"));
        let proxies = [settings.proxy.clone(), Some(tagged_proxy(b"second").await)];
        for i in 0..20 {
            settings.proxy = proxies[i % 2].clone();
            forwarder.update(settings.clone());
            // Queue immediately: reconfiguration and the request are both ready.
            let answer = resolve(&forwarder.shared, query(i as u16 + 2, None), true)
                .await
                .unwrap();
            let expected: &[u8] = if i % 2 == 0 { b"first" } else { b"second" };
            assert!(
                answer.ends_with(expected),
                "stale DNS upstream after update {i}"
            );
        }
        let mut client = TcpStream::connect(listen).await.unwrap();
        write_frame(&mut client, &query(3, None)).await.unwrap();
        assert!(read_frame(&mut client).await.unwrap().ends_with(b"second"));
        drop(forwarder);
        let closed = timeout(Duration::from_secs(1), client.read(&mut [0u8; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)));
        timeout(Duration::from_secs(1), async {
            loop {
                if std::net::UdpSocket::bind(listen).is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    /// Query for `example.com A`, with an optional EDNS OPT record.
    fn query(id: u16, edns: Option<u16>) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        if let Some(size) = edns {
            q.extend_from_slice(&[0, 0, 41]);
            q.extend_from_slice(&size.to_be_bytes());
            q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        q
    }

    /// Answers `query` with a response carrying `tag` in its additional data.
    fn answer_for(query: &[u8], tag: &[u8]) -> Vec<u8> {
        let mut a = query[..question_end(query).unwrap()].to_vec();
        a[2] |= 0x80;
        a[10..12].fill(0);
        a.extend_from_slice(tag);
        a
    }

    #[test]
    fn edns_size_and_truncation() {
        assert_eq!(udp_limit(&query(1, None)), 512);
        assert_eq!(udp_limit(&query(1, Some(1232))), 1232);
        let q = query(7, None);
        let big = answer_for(&q, &[0u8; 600]);
        let short = truncate_for_udp(&q, big);
        assert_eq!(short.len(), q.len());
        assert_ne!(short[2] & 0x02, 0);
        let fail = servfail(&q);
        assert_eq!((fail[0..2].to_vec(), fail[3] & 0x0f), (vec![0, 7], 2));
    }

    /// A SOCKS5 server that tunnels to a pipelined DNS-over-TCP resolver
    /// which answers queries in reverse order, tagging each with its question id.
    async fn proxy_with_resolver() -> Arc<ProxyEndpoint> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 10];
                    s.read_exact(&mut buf[..3]).await.unwrap();
                    s.write_all(&[5, 0]).await.unwrap();
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    let a = read_frame(&mut s).await.unwrap();
                    let b = read_frame(&mut s).await.unwrap();
                    for q in [b, a] {
                        write_frame(&mut s, &answer_for(&q, &q[..2])).await.unwrap();
                    }
                });
            }
        });
        Arc::new(ProxyEndpoint {
            host: "127.0.0.1".into(),
            port,
            credentials: None,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clients_with_the_same_id_get_their_own_answers() {
        let counters = Arc::new(DnsCounters::default());
        let settings = DnsSettings {
            upstream: "192.0.2.53:53".parse().unwrap(),
            proxy: Some(proxy_with_resolver().await),
            strict: true,
            fallback: vec![],
        };
        let listen: SocketAddr = {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = probe.local_addr().unwrap();
            let tcp = std::net::TcpListener::bind(addr);
            drop(probe);
            if tcp.is_err() {
                return;
            }
            addr
        };
        let forwarder =
            DnsForwarder::start(&Handle::current(), &[listen], settings, counters.clone()).unwrap();
        let ask = |edns| async move {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.send_to(&query(0x4242, edns), listen).await.unwrap();
            let mut buf = [0u8; 512];
            let n = timeout(Duration::from_secs(5), s.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            buf[..n].to_vec()
        };
        let (a, b) = tokio::join!(ask(None), ask(Some(1232)));
        for answer in [&a, &b] {
            assert_eq!(answer[..2], [0x42, 0x42]);
            assert_ne!(answer[2] & 0x80, 0);
        }
        // Each answer carries the rewritten id the resolver saw; they differ.
        assert_ne!(a[a.len() - 2..], b[b.len() - 2..]);
        assert_eq!(counters.proxied.load(Relaxed), 2);
        drop(forwarder);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_proxy_falls_back_to_the_original_server() {
        let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
                resolver
                    .send_to(&answer_for(&buf[..n], b"direct"), from)
                    .await
                    .unwrap();
            }
        });
        let counters = Arc::new(DnsCounters::default());
        let (tx, rx) = mpsc::channel(8);
        let shared = Arc::new(Shared {
            settings: RwLock::new(DnsSettings {
                upstream: "192.0.2.53:53".parse().unwrap(),
                // Nothing listens on port 1.
                proxy: Some(Arc::new(ProxyEndpoint {
                    host: "127.0.0.1".into(),
                    port: 1,
                    credentials: None,
                })),
                strict: false,
                fallback: vec![],
            }),
            counters: counters.clone(),
            upstream: tx,
            changed: tokio::sync::Notify::new(),
        });
        tokio::spawn(upstream_task(Arc::clone(&shared), rx));
        // `direct` always uses port 53; test it separately against the resolver.
        let answer = direct(&query(9, None), resolver_addr, false).await.unwrap();
        assert!(answer.ends_with(b"direct"));
        let failed = resolve(&shared, query(9, None), false).await.unwrap();
        assert_eq!(failed[3] & 0x0f, 2, "no fallback servers means SERVFAIL");
        assert_eq!(counters.fallback_active.load(Relaxed), 1);
    }
}
