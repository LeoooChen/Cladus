//! SOCKS5 client (RFC 1928, username/password auth per RFC 1929).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a SOCKS5 server (version byte {0})")]
    Version(u8),
    #[error("the SOCKS5 server accepts none of the offered authentication methods")]
    NoAcceptableMethod,
    #[error("SOCKS5 authentication failed")]
    AuthFailed,
    #[error("the SOCKS5 server refused the request: {0}")]
    Refused(&'static str),
    #[error("malformed SOCKS5 reply")]
    Malformed,
    #[error("SOCKS5 username and password must each contain 1 to 255 bytes")]
    InvalidCredentials,
}

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

/// Asks the server behind `stream` to connect to `target`. On success the
/// stream carries the tunneled connection.
pub async fn connect<S>(
    stream: &mut S,
    target: SocketAddr,
    credentials: Option<&Credentials>,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream, credentials).await?;
    request(stream, CMD_CONNECT, target).await?;
    Ok(())
}

/// Asks the server behind `stream` for a UDP relay. Returns the address the
/// server reported for it (possibly unspecified, meaning "the server's own
/// address"). The association lasts as long as `stream` stays open.
pub async fn associate<S>(
    stream: &mut S,
    credentials: Option<&Credentials>,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream, credentials).await?;
    // Our datagrams may leave from any local address, so none is announced.
    request(
        stream,
        CMD_UDP_ASSOCIATE,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    )
    .await
}

async fn negotiate<S>(stream: &mut S, credentials: Option<&Credentials>) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(credentials) = credentials
        && (!(1..=255).contains(&credentials.username.len())
            || !(1..=255).contains(&credentials.password.len()))
    {
        return Err(Socks5Error::InvalidCredentials);
    }
    let greeting: &[u8] = match credentials {
        Some(_) => &[VERSION, 2, NO_AUTH, USER_PASS],
        None => &[VERSION, 1, NO_AUTH],
    };
    stream.write_all(greeting).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != VERSION {
        return Err(Socks5Error::Version(choice[0]));
    }
    match (choice[1], credentials) {
        (NO_AUTH, _) => Ok(()),
        (USER_PASS, Some(credentials)) => authenticate(stream, credentials).await,
        _ => Err(Socks5Error::NoAcceptableMethod),
    }
}

/// Sends a request and returns the bound address from the reply.
async fn request<S>(
    stream: &mut S,
    command: u8,
    address: SocketAddr,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = vec![VERSION, command, 0];
    push_address(&mut request, address);
    stream.write_all(&request).await?;

    // VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Socks5Error::Version(head[0]));
    }
    if head[2] != 0 {
        return Err(Socks5Error::Malformed);
    }
    if head[1] != 0 {
        return Err(Socks5Error::Refused(reply_text(head[1])));
    }
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::from(octets)
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            IpAddr::from(octets)
        }
        3 => {
            let len = stream.read_u8().await?;
            if len == 0 {
                return Err(Socks5Error::Malformed);
            }
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8(name).map_err(|_| Socks5Error::Malformed)?;
            let port = stream.read_u16().await?;
            return Ok(BoundAddress::Domain(name, port));
        }
        _ => return Err(Socks5Error::Malformed),
    };
    let port = stream.read_u16().await?;
    Ok(BoundAddress::Ip(SocketAddr::new(ip, port)))
}

async fn authenticate<S>(stream: &mut S, credentials: &Credentials) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (user, pass) = (
        credentials.username.as_bytes(),
        credentials.password.as_bytes(),
    );
    let mut message = vec![1, user.len() as u8];
    message.extend(user);
    message.push(pass.len() as u8);
    message.extend(pass);
    stream.write_all(&message).await?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    if status == [1, 0] {
        Ok(())
    } else {
        Err(Socks5Error::AuthFailed)
    }
}

fn push_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip().to_canonical() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend(ip.octets());
        }
    }
    out.extend(address.port().to_be_bytes());
}

/// Wraps a datagram for the UDP relay: RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA.
pub fn encode_udp(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(22 + payload.len());
    datagram.extend([0, 0, 0]);
    push_address(&mut datagram, dst);
    datagram.extend(payload);
    datagram
}

/// Unwraps a datagram from the UDP relay into its source and payload.
/// Fragments and host-name sources are not supported.
pub fn decode_udp(datagram: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (header, rest) = datagram.split_at_checked(4)?;
    if header[..3] != [0, 0, 0] {
        return None; // fragmented
    }
    let (ip, rest): (IpAddr, _) = match header[3] {
        1 => {
            let (octets, rest) = rest.split_first_chunk::<4>()?;
            (Ipv4Addr::from(*octets).into(), rest)
        }
        4 => {
            let (octets, rest) = rest.split_first_chunk::<16>()?;
            (Ipv6Addr::from(*octets).into(), rest)
        }
        _ => return None,
    };
    let (port, payload) = rest.split_first_chunk::<2>()?;
    Some((SocketAddr::new(ip, u16::from_be_bytes(*port)), payload))
}

fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    async fn expect(server: &mut DuplexStream, bytes: &[u8]) {
        let mut buf = vec![0u8; bytes.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, bytes);
    }

    fn target() -> SocketAddr {
        "203.0.113.10:443".parse().unwrap()
    }

    #[tokio::test]
    async fn connect_without_authentication() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            expect(&mut server, &[5, 1, 0, 1, 203, 0, 113, 10, 0x01, 0xBB]).await;
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        result.unwrap();
    }

    #[tokio::test]
    async fn connect_with_username_and_password() {
        let (mut client, mut server) = duplex(256);
        let credentials = Credentials {
            username: "u".to_owned(),
            password: "pw".to_owned(),
        };
        let script = async {
            expect(&mut server, &[5, 2, 0, 2]).await;
            server.write_all(&[5, 2]).await.unwrap();
            expect(&mut server, &[1, 1, b'u', 2, b'p', b'w']).await;
            server.write_all(&[1, 0]).await.unwrap();
            expect(&mut server, &[5, 1, 0, 1, 203, 0, 113, 10, 0x01, 0xBB]).await;
            // A domain-name BND.ADDR, as some servers send.
            server
                .write_all(&[5, 0, 0, 3, 4, b'p', b'r', b'o', b'x', 0, 80])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), Some(&credentials)), script);
        result.unwrap();
    }

    #[tokio::test]
    async fn ipv6_target_and_bound_address() {
        let (mut client, mut server) = duplex(256);
        let target: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = vec![5, 1, 0, 4];
            request.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            request.extend([0, 80]);
            expect(&mut server, &request).await;
            let mut reply = vec![5, 0, 0, 4];
            reply.extend([0u8; 18]);
            server.write_all(&reply).await.unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target, None), script);
        result.unwrap();
    }

    #[tokio::test]
    async fn udp_associate_returns_the_relay_address() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            expect(&mut server, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(associate(&mut client, None), script);
        assert_eq!(
            result.unwrap(),
            BoundAddress::Ip("127.0.0.1:8080".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn udp_associate_preserves_a_domain_bound_address() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            expect(&mut server, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            server
                .write_all(&[5, 0, 0, 3, 5, b'r', b'e', b'l', b'a', b'y', 0, 53])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(associate(&mut client, None), script);
        assert_eq!(
            result.unwrap(),
            BoundAddress::Domain("relay".to_owned(), 53)
        );
    }

    #[tokio::test]
    async fn malformed_reserved_byte_is_rejected() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            expect(&mut server, &[5, 1, 0, 1, 203, 0, 113, 10, 1, 187]).await;
            server
                .write_all(&[5, 0, 1, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        assert!(matches!(result, Err(Socks5Error::Malformed)));
    }

    #[tokio::test]
    async fn invalid_credentials_are_rejected_before_sending() {
        for (username, password) in [
            ("".to_owned(), "p".to_owned()),
            ("u".repeat(256), "p".to_owned()),
            ("u".to_owned(), "".to_owned()),
        ] {
            let (mut client, _server) = duplex(256);
            let credentials = Credentials { username, password };
            assert!(matches!(
                connect(&mut client, target(), Some(&credentials)).await,
                Err(Socks5Error::InvalidCredentials)
            ));
        }
    }

    #[test]
    fn udp_datagram_round_trip() {
        for dst in ["8.8.8.8:53", "[2001:db8::1]:443"] {
            let dst: SocketAddr = dst.parse().unwrap();
            let datagram = encode_udp(dst, b"query");
            assert_eq!(decode_udp(&datagram), Some((dst, &b"query"[..])));
        }
        // An IPv4-mapped destination is sent as IPv4.
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:53".parse().unwrap();
        assert_eq!(encode_udp(mapped, b"")[3], 1);
        assert_eq!(
            decode_udp(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]),
            None,
            "fragment"
        );
        assert_eq!(decode_udp(&[0, 0, 0, 1, 1, 2]), None, "truncated");
        assert_eq!(
            decode_udp(&[1, 0, 0, 1, 1, 2, 3, 4, 0, 53]),
            None,
            "reserved"
        );
    }

    #[tokio::test]
    async fn failures_are_reported() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        assert!(matches!(
            result,
            Err(Socks5Error::Refused("connection refused"))
        ));

        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0xFF]).await.unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        assert!(matches!(result, Err(Socks5Error::NoAcceptableMethod)));

        let (mut client, mut server) = duplex(256);
        let credentials = Credentials {
            username: "u".to_owned(),
            password: "bad".to_owned(),
        };
        let script = async {
            expect(&mut server, &[5, 2, 0, 2]).await;
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 7];
            server.read_exact(&mut auth).await.unwrap();
            server.write_all(&[1, 1]).await.unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), Some(&credentials)), script);
        assert!(matches!(result, Err(Socks5Error::AuthFailed)));

        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[4, 0]).await.unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        assert!(matches!(result, Err(Socks5Error::Version(4))));
    }
}
