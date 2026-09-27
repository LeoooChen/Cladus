//! SOCKS5 client handshake (RFC 1928, username/password auth per RFC 1929).

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
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
}

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 1;

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
        (NO_AUTH, _) => {}
        (USER_PASS, Some(credentials)) => authenticate(stream, credentials).await?,
        _ => return Err(Socks5Error::NoAcceptableMethod),
    }

    let mut request = vec![VERSION, CMD_CONNECT, 0];
    match target {
        SocketAddr::V4(addr) => {
            request.push(1);
            request.extend(addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            request.push(4);
            request.extend(addr.ip().octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;

    // VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Socks5Error::Version(head[0]));
    }
    if head[1] != 0 {
        return Err(Socks5Error::Refused(reply_text(head[1])));
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await?),
        _ => return Err(Socks5Error::Malformed),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

async fn authenticate<S>(stream: &mut S, credentials: &Credentials) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (user, pass) = (credentials.username.as_bytes(), credentials.password.as_bytes());
    let mut message = vec![1, user.len() as u8];
    message.extend(user);
    message.push(pass.len() as u8);
    message.extend(pass);
    stream.write_all(&message).await?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    if status[1] == 0 {
        Ok(())
    } else {
        Err(Socks5Error::AuthFailed)
    }
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
            server.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
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
            server.write_all(&[5, 0, 0, 3, 4, b'p', b'r', b'o', b'x', 0, 80]).await.unwrap();
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
            request.extend("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
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
    async fn failures_are_reported() {
        let (mut client, mut server) = duplex(256);
        let script = async {
            expect(&mut server, &[5, 1, 0]).await;
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        };
        let (result, ()) = tokio::join!(connect(&mut client, target(), None), script);
        assert!(matches!(result, Err(Socks5Error::Refused("connection refused"))));

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
