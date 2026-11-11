//! Fresh, proxy-only DNS verification for an alternate TLS destination.
use crate::{relay::ProxyEndpoint, socks5};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub(crate) async fn candidates(
    proxy: &ProxyEndpoint,
    resolver: SocketAddr,
    host: &str,
    original: Ipv6Addr,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    timeout(Duration::from_secs(5), async {
        let (v4, v6) = tokio::try_join!(
            lookup(proxy, resolver, host, 1),
            lookup(proxy, resolver, host, 28)
        )?;
        if !v6.contains(&IpAddr::V6(original)) {
            return Err(invalid(
                "SNI does not resolve to the original IPv6 destination",
            ));
        }
        let mut result = Vec::new();
        for ip in v4.into_iter().filter(IpAddr::is_ipv4) {
            let address = SocketAddr::new(ip, port);
            if !result.contains(&address) {
                result.push(address);
            }
        }
        if result.is_empty() {
            return Err(invalid("verified hostname has no IPv4 addresses"));
        }
        Ok(result)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "fallback DNS verification timed out",
        )
    })?
}

async fn lookup(
    proxy: &ProxyEndpoint,
    resolver: SocketAddr,
    host: &str,
    kind: u16,
) -> io::Result<Vec<IpAddr>> {
    use std::hash::{BuildHasher, RandomState};
    let id = RandomState::new().hash_one((host, kind)) as u16;
    let query = query(host, kind, id)?;
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
    socks5::connect(&mut stream, resolver, proxy.credentials.as_ref())
        .await
        .map_err(io::Error::other)?;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&query).await?;
    let len = stream.read_u16().await? as usize;
    let mut answer = vec![0; len];
    stream.read_exact(&mut answer).await?;
    addresses(&answer, &query, host, kind)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn query(host: &str, kind: u16, id: u16) -> io::Result<Vec<u8>> {
    if !crate::tls_hello::valid_hostname(host) {
        return Err(invalid("invalid fallback DNS hostname"));
    }
    let mut q = id.to_be_bytes().to_vec();
    q.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.push(0);
    q.extend(kind.to_be_bytes());
    q.extend([0, 1]);
    Ok(q)
}

/// Follow compression without trusting offsets, cycles, or expanded lengths.
fn name(message: &[u8], cursor: &mut usize) -> io::Result<String> {
    let mut at = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut expanded = 1;
    for _ in 0..128 {
        let size = *message
            .get(at)
            .ok_or_else(|| invalid("truncated DNS name"))?;
        if size & 0xc0 == 0xc0 {
            let low = *message
                .get(at + 1)
                .ok_or_else(|| invalid("truncated DNS pointer"))?;
            if !jumped {
                *cursor = at + 2;
                jumped = true;
            }
            at = ((size as usize & 63) << 8) | low as usize;
            if at < 12 {
                return Err(invalid("invalid DNS pointer"));
            }
            continue;
        }
        if size > 63 {
            return Err(invalid("invalid DNS label"));
        }
        at += 1;
        if size == 0 {
            if !jumped {
                *cursor = at;
            }
            return Ok(labels.join("."));
        }
        expanded += 1 + size as usize;
        if expanded > 255 {
            return Err(invalid("DNS name too long"));
        }
        let label = message
            .get(at..at + size as usize)
            .ok_or_else(|| invalid("truncated DNS label"))?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(invalid("invalid DNS hostname label"));
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += size as usize;
    }
    Err(invalid("DNS compression loop"))
}

fn addresses(answer: &[u8], query: &[u8], host: &str, kind: u16) -> io::Result<Vec<IpAddr>> {
    if answer.len() < 12
        || answer[..2] != query[..2]
        || answer[2] & 0xfa != 0x80
        || answer[3] & 15 != 0
        || answer[4..6] != [0, 1]
    {
        return Err(invalid("invalid, truncated or unsuccessful DNS answer"));
    }
    let mut at = 12;
    if !name(answer, &mut at)?.eq_ignore_ascii_case(host)
        || answer.get(at..at + 4) != Some(&query[query.len() - 4..])
    {
        return Err(invalid("DNS response question mismatch"));
    }
    at += 4;
    let mut aliases = Vec::new();
    let mut ips = Vec::new();
    for _ in 0..u16::from_be_bytes([answer[6], answer[7]]) {
        let owner = name(answer, &mut at)?;
        let head = answer
            .get(at..at + 10)
            .ok_or_else(|| invalid("truncated DNS record"))?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let class = u16::from_be_bytes([head[2], head[3]]);
        let size = u16::from_be_bytes([head[8], head[9]]) as usize;
        at += 10;
        let data = answer
            .get(at..at + size)
            .ok_or_else(|| invalid("truncated DNS record data"))?;
        if class == 1 {
            match (rtype, data.len()) {
                (1, 4) if kind == 1 => {
                    ips.push((owner, IpAddr::from(<[u8; 4]>::try_from(data).unwrap())))
                }
                (28, 16) if kind == 28 => {
                    ips.push((owner, IpAddr::from(<[u8; 16]>::try_from(data).unwrap())))
                }
                (5, _) => {
                    let mut end = at;
                    let target = name(answer, &mut end)?;
                    if end != at + size {
                        return Err(invalid("invalid CNAME length"));
                    }
                    aliases.push((owner, target));
                }
                _ => {}
            }
        }
        at += size;
    }
    let mut current = host.to_ascii_lowercase();
    for _ in 0..16 {
        let result: Vec<_> = ips
            .iter()
            .filter(|(n, _)| n == &current)
            .map(|(_, ip)| *ip)
            .collect();
        if !result.is_empty() {
            return Ok(result);
        }
        match aliases.iter().find(|(n, _)| n == &current) {
            Some((_, target)) => current = target.clone(),
            None => return Ok(Vec::new()),
        }
    }
    Err(invalid("CNAME chain too long or cyclic"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cname_chain_is_followed_without_accepting_unrelated_addresses() {
        let q = query("example.com", 1, 7).unwrap();
        let mut a = q.clone();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 3;
        let alias = b"\x05alias\x07example\x00";
        a.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
        a.extend((alias.len() as u16).to_be_bytes());
        let offset = a.len();
        a.extend(alias);
        a.extend(b"\x05other\x07example\x00");
        a.extend([0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
        a.extend([0xc0 | (offset >> 8) as u8, offset as u8]);
        a.extend([0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
        assert_eq!(
            addresses(&a, &q, "example.com", 1).unwrap(),
            ["203.0.113.10".parse::<IpAddr>().unwrap()]
        );
    }
    #[test]
    fn dns_answers_require_the_question_and_owner_to_match() {
        let q = query("example.com", 1, 42).unwrap();
        let mut a = q.clone();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 1]);
        assert_eq!(
            addresses(&a, &q, "example.com", 1).unwrap(),
            ["203.0.113.1".parse::<IpAddr>().unwrap()]
        );
        for len in 0..a.len() {
            assert!(addresses(&a[..len], &q, "example.com", 1).is_err());
        }
        a[0] ^= 1;
        assert!(addresses(&a, &q, "example.com", 1).is_err());
        a[0] ^= 1;
        a[2] |= 2;
        assert!(addresses(&a, &q, "example.com", 1).is_err());
        let mut looped = vec![0; 12];
        looped.extend([0xc0, 12]);
        assert!(name(&looped, &mut 12).is_err());
    }
}
