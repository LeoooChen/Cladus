//! Inspect only a bounded, plaintext TLS ClientHello; never decrypt TLS.

pub(crate) const MAX_HELLO: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hello {
    More,
    Pass,
    Retryable(String),
}

pub(crate) fn inspect(bytes: &[u8]) -> Hello {
    if bytes.len() > MAX_HELLO {
        return Hello::Pass;
    }
    let mut at = 0;
    let mut handshake = Vec::new();
    loop {
        if bytes.len() - at < 5 {
            return Hello::More;
        }
        if bytes[at] != 22 || bytes[at + 1] != 3 {
            return Hello::Pass;
        }
        let len = u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]) as usize;
        if len == 0 || len > 16384 {
            return Hello::Pass;
        }
        if at + 5 + len > bytes.len() {
            return Hello::More;
        }
        handshake.extend_from_slice(&bytes[at + 5..at + 5 + len]);
        at += 5 + len;
        if handshake.first().is_some_and(|v| *v != 1) {
            return Hello::Pass;
        }
        if handshake.len() >= 4 {
            let wanted = 4
                + ((handshake[1] as usize) << 16
                    | (handshake[2] as usize) << 8
                    | handshake[3] as usize);
            if wanted > MAX_HELLO {
                return Hello::Pass;
            }
            if handshake.len() >= wanted {
                // Never replay coalesced handshake/application/early data.
                if handshake.len() != wanted || at != bytes.len() {
                    return Hello::Pass;
                }
                return hostname(&handshake[4..]).map_or(Hello::Pass, Hello::Retryable);
            }
        }
        if at == bytes.len() {
            return Hello::More;
        }
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(value)
    }
    fn byte(&mut self) -> Option<usize> {
        Some(self.take(1)?[0] as usize)
    }
    fn word(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
}

fn hostname(body: &[u8]) -> Option<String> {
    let mut r = Reader(body);
    r.take(34)?; // legacy version and random
    let session = r.byte()?;
    if session > 32 {
        return None;
    }
    r.take(session)?;
    let ciphers = r.word()?;
    if ciphers == 0 || ciphers % 2 != 0 {
        return None;
    }
    r.take(ciphers)?;
    let compression = r.byte()?;
    if compression == 0 {
        return None;
    }
    r.take(compression)?;
    let extension_len = r.word()?;
    let mut extensions = Reader(r.take(extension_len)?);
    if !r.0.is_empty() {
        return None;
    }
    let mut name = None;
    while !extensions.0.is_empty() {
        let kind = extensions.word()?;
        let len = extensions.word()?;
        let value = extensions.take(len)?;
        // TLS 1.3 early data can contain a POST. ECH hides the actual hostname.
        if kind == 42 || kind == 0xfe0d {
            return None;
        }
        if kind == 0 {
            if name.is_some() {
                return None;
            }
            let mut names = Reader(value);
            let size = names.word()?;
            if size != names.0.len() || names.byte()? != 0 {
                return None;
            }
            let size = names.word()?;
            let host = std::str::from_utf8(names.take(size)?).ok()?;
            if !names.0.is_empty() || !valid_hostname(host) {
                return None;
            }
            name = Some(host.to_ascii_lowercase());
        }
    }
    name
}

pub(crate) fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn hello(host: &str, extra: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let mut ext = vec![0, 0];
        ext.extend(((host.len() + 5) as u16).to_be_bytes());
        ext.extend(((host.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend((host.len() as u16).to_be_bytes());
        ext.extend(host.as_bytes());
        ext.extend(extra);
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut hs = vec![1, 0];
        hs.extend((body.len() as u16).to_be_bytes());
        hs.extend(body);
        let mut record = vec![22, 3, 1];
        record.extend((hs.len() as u16).to_be_bytes());
        record.extend(hs);
        record
    }
    #[test]
    fn fragments_are_bounded_and_only_client_hello_is_replayable() {
        let h = hello("chatgpt.com", &[]);
        for len in 0..h.len() {
            assert_eq!(inspect(&h[..len]), Hello::More);
        }
        assert_eq!(inspect(&h), Hello::Retryable("chatgpt.com".into()));
        for ext in [&[0, 42, 0, 0][..], &[0xfe, 0x0d, 0, 0]] {
            assert_eq!(inspect(&hello("chatgpt.com", ext)), Hello::Pass);
        }
        let mut extra = h.clone();
        extra.extend(b"POST /v1/responses HTTP/1.1\r\n");
        assert_eq!(inspect(&extra), Hello::Pass);
        assert_eq!(inspect(b"POST / HTTP/1.1"), Hello::Pass);
        let mut split = vec![22, 3, 1, 0, 7];
        split.extend(&h[5..12]);
        split.extend([22, 3, 1]);
        split.extend(((h.len() - 12) as u16).to_be_bytes());
        split.extend(&h[12..]);
        assert_eq!(inspect(&split), Hello::Retryable("chatgpt.com".into()));
        assert_eq!(inspect(&hello("bad.example/other", &[])), Hello::Pass);
    }
}
