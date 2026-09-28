//! Relaying UDP datagrams of proxied sockets through SOCKS5 UDP ASSOCIATE.
//!
//! Each application socket gets its own association, so replies can only
//! ever reach the socket that asked. A reply's source is taken from the
//! relay's datagram header, so an unconnected socket that talks to several
//! peers sees each reply come from the right one.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cladus_core::model::GroupId;
use cladus_core::platform::{Counter, RedirectedUdp, UdpInjector};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until, timeout};
use tracing::{debug, warn};

use crate::relay::ProxyEndpoint;
use crate::socks5;

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// An association without traffic in either direction is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// After a failed setup, datagrams of that socket are dropped for this long.
const RETRY_AFTER: Duration = Duration::from_secs(5);
const QUEUE: usize = 32;
const MAX_SESSIONS: usize = 1024;

type Key = (SocketAddr, GroupId, u64);

enum Entry {
    Active {
        id: u64,
        tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    },
    Failed {
        until: Instant,
    },
}

#[derive(Default)]
pub struct UdpCounters {
    pub associations: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
}

impl UdpCounters {
    pub fn snapshot(&self) -> Vec<Counter> {
        vec![
            Counter {
                name: "udp.associations",
                value: self.associations.load(Relaxed),
            },
            Counter {
                name: "udp.associations_failed",
                value: self.failed.load(Relaxed),
            },
            Counter {
                name: "udp.relay_dropped",
                value: self.dropped.load(Relaxed),
            },
        ]
    }
}

pub struct UdpRelay {
    runtime: Handle,
    injector: Arc<dyn UdpInjector>,
    sessions: Mutex<HashMap<Key, Entry>>,
    next_id: AtomicU64,
    counters: Arc<UdpCounters>,
}

impl UdpRelay {
    pub fn new(
        runtime: Handle,
        injector: Arc<dyn UdpInjector>,
        counters: Arc<UdpCounters>,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            injector,
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            counters,
        })
    }

    /// Forwards one datagram. Called on a backend thread; never blocks.
    pub fn send(self: &Arc<Self>, datagram: RedirectedUdp, proxy: Option<Arc<ProxyEndpoint>>) {
        let key = (datagram.app, datagram.group, datagram.generation);
        let message = (datagram.dst, datagram.payload);
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|(app, _, generation), entry| {
            !matches!(entry, Entry::Failed { until } if *until <= now)
                && (*app != key.0 || *generation >= key.2)
        });
        if sessions
            .keys()
            .any(|(app, _, generation)| *app == key.0 && *generation > key.2)
        {
            self.counters.dropped.fetch_add(1, Relaxed);
            return;
        }
        match sessions.get(&key) {
            Some(Entry::Active { tx, .. }) => match tx.try_send(message) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.counters.dropped.fetch_add(1, Relaxed);
                    return;
                }
                // The association ended; start a new one below.
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    return self.open(&mut sessions, key, returned, proxy);
                }
            },
            Some(Entry::Failed { until }) if Instant::now() < *until => {
                self.counters.dropped.fetch_add(1, Relaxed);
                return;
            }
            _ => {}
        }
        self.open(&mut sessions, key, message, proxy);
    }

    fn open(
        self: &Arc<Self>,
        sessions: &mut HashMap<Key, Entry>,
        key: Key,
        first: (SocketAddr, Vec<u8>),
        proxy: Option<Arc<ProxyEndpoint>>,
    ) {
        if !sessions.contains_key(&key) && sessions.len() >= MAX_SESSIONS {
            self.counters.dropped.fetch_add(1, Relaxed);
            return;
        }
        let Some(proxy) = proxy else {
            warn!(group = %key.1, "no such proxy group; dropping UDP traffic");
            self.counters.dropped.fetch_add(1, Relaxed);
            return;
        };
        let (tx, rx) = mpsc::channel(QUEUE);
        tx.try_send(first).expect("new channel has room");
        let id = self.next_id.fetch_add(1, Relaxed);
        sessions.insert(key, Entry::Active { id, tx });
        self.counters.associations.fetch_add(1, Relaxed);
        let relay = Arc::clone(self);
        self.runtime.spawn(async move {
            let result = relay.run(key.0, key.2, &proxy, rx).await;
            let mut sessions = relay.sessions.lock().unwrap();
            let current = matches!(sessions.get(&key), Some(Entry::Active { id: current, .. }) if *current == id);
            match result {
                Ok(()) => {
                    debug!(app = %key.0, "UDP association closed");
                    if current {
                        sessions.remove(&key);
                    }
                }
                Err(err) => {
                    relay.counters.failed.fetch_add(1, Relaxed);
                    warn!(app = %key.0, proxy = %format!("{}:{}", proxy.host, proxy.port), "UDP association failed: {err}");
                    if current {
                        sessions.insert(
                            key,
                            Entry::Failed {
                                until: Instant::now() + RETRY_AFTER,
                            },
                        );
                    }
                }
            }
        });
    }

    async fn run(
        &self,
        app: SocketAddr,
        generation: u64,
        proxy: &ProxyEndpoint,
        mut rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<()> {
        let setup = async {
            let mut control = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
            let bound = socks5::associate(&mut control, proxy.credentials.as_ref())
                .await
                .map_err(io::Error::other)?;
            let bound = match bound {
                socks5::BoundAddress::Ip(addr) => addr,
                socks5::BoundAddress::Domain(host, port) => lookup_host((host.as_str(), port))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        io::Error::other("SOCKS5 UDP relay name resolved to no addresses")
                    })?,
            };
            if bound.port() == 0 {
                return Err(io::Error::other("SOCKS5 UDP relay has no port"));
            }
            // An unspecified address means "where you reached me".
            let relay = if bound.ip().is_unspecified() {
                SocketAddr::new(control.peer_addr()?.ip().to_canonical(), bound.port())
            } else {
                SocketAddr::new(bound.ip().to_canonical(), bound.port())
            };
            let local = if relay.is_ipv4() {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            };
            let socket = UdpSocket::bind(local).await?;
            Ok::<_, io::Error>((control, relay, socket))
        };
        let (mut control, relay, socket) = timeout(SETUP_TIMEOUT, setup)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP setup timed out"))??;
        debug!(%app, %relay, "UDP association established");

        let mut buffer = vec![0u8; 65_536];
        let mut probe = [0u8; 1];
        let mut deadline = Instant::now() + IDLE_TIMEOUT;
        loop {
            tokio::select! {
                message = rx.recv() => {
                    let Some((dst, payload)) = message else { return Ok(()) };
                    let encoded = socks5::encode_udp(dst, &payload);
                    // SOCKS5 framing must fit inside one UDP datagram.
                    if encoded.len() > 65_507 {
                        self.counters.dropped.fetch_add(1, Relaxed);
                        continue;
                    }
                    socket.send_to(&encoded, relay).await?;
                    deadline = Instant::now() + IDLE_TIMEOUT;
                }
                received = socket.recv_from(&mut buffer) => {
                    let (len, from) = match received {
                        Ok(received) => received,
                        // Windows reports ICMP port-unreachable this way.
                        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => continue,
                        Err(err) => return Err(err),
                    };
                    // Only the relay may speak for the remote side.
                    if SocketAddr::new(from.ip().to_canonical(), from.port()) != relay {
                        continue;
                    }
                    if let Some((source, payload)) = socks5::decode_udp(&buffer[..len]) {
                        self.injector.inject(app, generation, source, payload);
                        deadline = Instant::now() + IDLE_TIMEOUT;
                    }
                }
                // The association lives as long as the control connection.
                _ = control.read(&mut probe) => return Ok(()),
                () = sleep_until(deadline) => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Default)]
    struct Recorder(StdMutex<Vec<(SocketAddr, SocketAddr, Vec<u8>)>>);

    impl UdpInjector for Recorder {
        fn inject(&self, app: SocketAddr, _: u64, from: SocketAddr, payload: &[u8]) -> bool {
            self.0.lock().unwrap().push((app, from, payload.to_vec()));
            true
        }
    }

    /// A SOCKS5 server whose UDP relay answers every datagram with
    /// "echo:<payload>" from a source address chosen per destination.
    async fn socks5_udp_echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut control, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 10];
                    control.read_exact(&mut buf[..3]).await.unwrap();
                    control.write_all(&[5, 0]).await.unwrap();
                    control.read_exact(&mut buf).await.unwrap();
                    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let relay_port = relay.local_addr().unwrap().port().to_be_bytes();
                    control
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, relay_port[0], relay_port[1]])
                        .await
                        .unwrap();
                    let mut datagram = vec![0u8; 2048];
                    loop {
                        tokio::select! {
                            received = relay.recv_from(&mut datagram) => {
                                let (len, client) = received.unwrap();
                                let (dst, payload) = socks5::decode_udp(&datagram[..len]).unwrap();
                                let reply = [b"echo:".as_slice(), payload].concat();
                                relay.send_to(&socks5::encode_udp(dst, &reply), client).await.unwrap();
                            }
                            n = control.read(&mut buf) => if n.unwrap_or(0) == 0 { return },
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn datagrams_go_through_the_relay_and_replies_come_back() {
        let proxy = Arc::new(ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: socks5_udp_echo().await,
            credentials: None,
        });
        let recorder = Arc::new(Recorder::default());
        let relay = UdpRelay::new(Handle::current(), recorder.clone(), Arc::default());
        let app: SocketAddr = "192.168.1.5:50000".parse().unwrap();
        let (dns, other): (SocketAddr, SocketAddr) = (
            "8.8.8.8:53".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        );
        for (dst, payload) in [(dns, b"a"), (other, b"b")] {
            relay.send(
                RedirectedUdp {
                    app,
                    generation: 0,
                    dst,
                    group: GroupId(0),
                    payload: payload.to_vec(),
                },
                Some(Arc::clone(&proxy)),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while recorder.0.lock().unwrap().len() < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut got = recorder.0.lock().unwrap().clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                (app, dns, b"echo:a".to_vec()),
                (app, other, b"echo:b".to_vec()),
            ]
        );
        assert_eq!(relay.counters.associations.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn generations_do_not_share_an_association() {
        let proxy = Arc::new(ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: socks5_udp_echo().await,
            credentials: None,
        });
        let recorder = Arc::new(Recorder::default());
        let relay = UdpRelay::new(Handle::current(), recorder.clone(), Arc::default());
        let mut datagram = RedirectedUdp {
            app: "192.168.1.5:50000".parse().unwrap(),
            generation: 1,
            dst: "8.8.8.8:53".parse().unwrap(),
            group: GroupId(0),
            payload: vec![1],
        };
        relay.send(datagram.clone(), Some(Arc::clone(&proxy)));
        datagram.generation = 2;
        relay.send(datagram.clone(), Some(Arc::clone(&proxy)));
        assert_eq!(relay.counters.associations.load(Relaxed), 2);
        assert_eq!(relay.sessions.lock().unwrap().len(), 1);
        datagram.generation = 1;
        relay.send(datagram, Some(proxy));
        assert_eq!(relay.counters.associations.load(Relaxed), 2);
        assert_eq!(relay.counters.dropped.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn oversized_datagram_does_not_destroy_the_association() {
        let proxy = Arc::new(ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: socks5_udp_echo().await,
            credentials: None,
        });
        let recorder = Arc::new(Recorder::default());
        let relay = UdpRelay::new(Handle::current(), recorder.clone(), Arc::default());
        let mut datagram = RedirectedUdp {
            app: "192.168.1.5:50000".parse().unwrap(),
            generation: 0,
            dst: "8.8.8.8:53".parse().unwrap(),
            group: GroupId(0),
            payload: vec![1; 65_507],
        };
        relay.send(datagram.clone(), Some(Arc::clone(&proxy)));
        datagram.payload = b"valid".to_vec();
        relay.send(datagram, Some(proxy));
        timeout(Duration::from_secs(5), async {
            while recorder.0.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(relay.counters.associations.load(Relaxed), 1);
        assert_eq!(relay.counters.dropped.load(Relaxed), 1);
        assert_eq!(relay.counters.failed.load(Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_setup_drops_datagrams_for_a_while() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = unused.local_addr().unwrap().port();
        drop(unused);
        let proxy = Arc::new(ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port,
            credentials: None,
        });
        let relay = UdpRelay::new(
            Handle::current(),
            Arc::new(Recorder::default()),
            Arc::default(),
        );
        let datagram = RedirectedUdp {
            app: "192.168.1.5:50000".parse().unwrap(),
            generation: 0,
            dst: "8.8.8.8:53".parse().unwrap(),
            group: GroupId(0),
            payload: vec![1],
        };
        relay.send(datagram.clone(), Some(Arc::clone(&proxy)));
        let deadline = Instant::now() + Duration::from_secs(5);
        while relay.counters.failed.load(Relaxed) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(relay.counters.failed.load(Relaxed), 1);
        relay.send(datagram, Some(proxy));
        assert_eq!(relay.counters.associations.load(Relaxed), 1);
        assert_eq!(relay.counters.dropped.load(Relaxed), 1);
    }
}
