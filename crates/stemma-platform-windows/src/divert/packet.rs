//! In-place views of IPv4/IPv6 packets carrying TCP or UDP, and construction
//! of UDP packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

const FLAG_SYN: u8 = 0x02;
const FLAG_ACK: u8 = 0x10;

/// An unfragmented IPv4 or IPv6 packet, including IPv6 option headers.
pub struct Packet<'a> {
    buf: &'a mut [u8],
    ipv6: bool,
    protocol: u8,
    /// Offset of the transport header.
    transport: usize,
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Option<Self> {
        let (ipv6, protocol, transport, total) = match buf.first()? >> 4 {
            4 if buf.len() >= 20 => {
                let header_len = usize::from(buf[0] & 0x0F) * 4;
                let fragment = u16::from_be_bytes([buf[6], buf[7]]) & 0x3FFF;
                if header_len < 20 || fragment != 0 {
                    return None; // fragments: only the first carries ports
                }
                let total = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
                (false, buf[9], header_len, total)
            }
            6 if buf.len() >= 40 => {
                let total = 40 + usize::from(u16::from_be_bytes([buf[4], buf[5]]));
                let (mut protocol, mut transport) = (buf[6], 40);
                while matches!(protocol, 0 | 43 | 44 | 60) {
                    let header = buf.get(transport..transport + 8)?;
                    let length = if protocol == 44 {
                        if header[2..4] != [0, 0] {
                            return None; // only atomic fragments carry a complete datagram
                        }
                        8
                    } else {
                        if protocol == 43 && header[3] != 0 {
                            return None; // routing is not complete
                        }
                        (usize::from(header[1]) + 1) * 8
                    };
                    protocol = header[0];
                    transport += length;
                    if transport > total {
                        return None;
                    }
                }
                (true, protocol, transport, total)
            }
            _ => return None,
        };
        let min = match protocol {
            TCP => 20,
            UDP => 8,
            _ => return None,
        };
        if total < transport + min || buf.len() < total {
            return None;
        }
        let buf = &mut buf[..total];
        if protocol == TCP {
            let header = usize::from(buf[transport + 12] >> 4) * 4;
            if header < 20 || transport + header > total {
                return None;
            }
        } else {
            let length = usize::from(u16::from_be_bytes([buf[transport + 4], buf[transport + 5]]));
            if length < 8 || transport + length > total {
                return None;
            }
        }
        Some(Self {
            buf,
            ipv6,
            protocol,
            transport,
        })
    }

    pub fn is_ipv6(&self) -> bool {
        self.ipv6
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn src(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip(), self.src_port())
    }

    pub fn dst(&self) -> SocketAddr {
        SocketAddr::new(self.dst_ip(), self.dst_port())
    }

    fn src_ip(&self) -> IpAddr {
        if self.ipv6 {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&self.buf[8..24]).expect("16 bytes"),
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&self.buf[12..16]).expect("4 bytes"),
            ))
        }
    }

    fn dst_ip(&self) -> IpAddr {
        if self.ipv6 {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&self.buf[24..40]).expect("16 bytes"),
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&self.buf[16..20]).expect("4 bytes"),
            ))
        }
    }

    pub fn swap_addresses(&mut self) {
        let range = if self.ipv6 { 8..40 } else { 12..20 };
        let half = range.len() / 2;
        let (src, dst) = self.buf[range].split_at_mut(half);
        src.swap_with_slice(dst);
    }

    pub fn src_port(&self) -> u16 {
        self.read_u16(self.transport)
    }

    pub fn dst_port(&self) -> u16 {
        self.read_u16(self.transport + 2)
    }

    pub fn set_src_port(&mut self, port: u16) {
        let at = self.transport;
        self.buf[at..at + 2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, port: u16) {
        let at = self.transport + 2;
        self.buf[at..at + 2].copy_from_slice(&port.to_be_bytes());
    }

    /// TCP sequence number.
    pub fn seq(&self) -> u32 {
        let at = self.transport + 4;
        u32::from_be_bytes(self.buf[at..at + 4].try_into().expect("4 bytes"))
    }

    /// The first packet of a TCP connection: SYN without ACK.
    pub fn is_initial_syn(&self) -> bool {
        self.protocol == TCP && self.buf[self.transport + 13] & (FLAG_SYN | FLAG_ACK) == FLAG_SYN
    }

    /// UDP payload.
    pub fn payload(&self) -> &[u8] {
        let start = self.transport + 8;
        let length = usize::from(self.read_u16(self.transport + 4));
        let end = (self.transport + length).clamp(start, self.buf.len());
        &self.buf[start..end]
    }

    fn read_u16(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }
}

/// Builds an IP/UDP packet from `from` to `to` (checksums left zero).
/// `None` if the address families differ or the payload is too large.
pub fn build_udp(from: SocketAddr, to: SocketAddr, payload: &[u8], id: u16) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let mut packet = match (from.ip(), to.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20u16.checked_add(udp_len)?;
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&id.to_be_bytes());
            p[8] = 64;
            p[9] = UDP;
            p[12..16].copy_from_slice(&src.octets());
            p[16..20].copy_from_slice(&dst.octets());
            p
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&udp_len.to_be_bytes());
            p[6] = UDP;
            p[7] = 64;
            p[8..24].copy_from_slice(&src.octets());
            p[24..40].copy_from_slice(&dst.octets());
            p
        }
        _ => return None,
    };
    packet.extend(from.port().to_be_bytes());
    packet.extend(to.port().to_be_bytes());
    packet.extend(udp_len.to_be_bytes());
    packet.extend([0, 0]);
    packet.extend(payload);
    Some(packet)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal IPv4/TCP packet (checksums not filled in).
    pub(crate) fn tcp_packet(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn tcp6_packet(src: &str, sport: u16, dst: &str, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = FLAG_SYN;
        p
    }

    #[test]
    fn reads_and_rewrites_ipv4_tcp() {
        let mut p = tcp_packet([10, 0, 0, 2], 50000, [203, 0, 113, 10], 443, FLAG_SYN);
        let mut pkt = Packet::parse(&mut p).unwrap();
        assert!(pkt.is_initial_syn());
        assert!(!pkt.is_ipv6());
        assert_eq!(pkt.seq(), 0x1234_5678);
        assert_eq!(pkt.dst(), "203.0.113.10:443".parse().unwrap());
        pkt.swap_addresses();
        pkt.set_dst_port(40000);
        assert_eq!(pkt.src(), "203.0.113.10:50000".parse().unwrap());
        assert_eq!(pkt.dst(), "10.0.0.2:40000".parse().unwrap());
        pkt.set_src_port(443);
        assert_eq!(pkt.src_port(), 443);
    }

    #[test]
    fn reads_and_rewrites_ipv6_tcp() {
        let mut p = tcp6_packet("2001:db8::2", 50000, "2001:db8::10", 443);
        let mut pkt = Packet::parse(&mut p).unwrap();
        assert!(pkt.is_ipv6() && pkt.is_initial_syn());
        assert_eq!(pkt.dst(), "[2001:db8::10]:443".parse().unwrap());
        pkt.swap_addresses();
        assert_eq!(pkt.src(), "[2001:db8::10]:50000".parse().unwrap());
        assert_eq!(pkt.dst(), "[2001:db8::2]:443".parse().unwrap());
    }

    #[test]
    fn syn_ack_is_not_initial() {
        let mut p = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, FLAG_SYN | FLAG_ACK);
        assert!(!Packet::parse(&mut p).unwrap().is_initial_syn());
    }

    #[test]
    fn rejects_other_protocols_fragments_and_short_packets() {
        let mut icmp = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        icmp[9] = 1;
        assert!(Packet::parse(&mut icmp).is_none());
        let mut fragment = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        fragment[7] = 1;
        assert!(Packet::parse(&mut fragment).is_none());
        let mut more_fragments = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        more_fragments[6] = 0x20;
        assert!(Packet::parse(&mut more_fragments).is_none());
        let mut short = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        assert!(Packet::parse(&mut short[..30]).is_none());
        let mut extension = tcp6_packet("::1", 1, "::2", 2);
        extension[6] = 0; // hop-by-hop options header
        assert!(Packet::parse(&mut extension).is_none());
    }

    #[test]
    fn builds_udp_packets_that_parse_back() {
        let from: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let to: SocketAddr = "192.168.1.5:50000".parse().unwrap();
        let mut p = build_udp(from, to, b"answer", 7).unwrap();
        assert_eq!(p.len(), 20 + 8 + 6);
        let pkt = Packet::parse(&mut p).unwrap();
        assert_eq!((pkt.protocol(), pkt.src(), pkt.dst()), (UDP, from, to));
        assert_eq!(pkt.payload(), b"answer");

        let from: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
        let to: SocketAddr = "[2001:db8::5]:50000".parse().unwrap();
        let mut p = build_udp(from, to, b"x", 0).unwrap();
        let pkt = Packet::parse(&mut p).unwrap();
        assert_eq!((pkt.src(), pkt.dst(), pkt.payload()), (from, to, &b"x"[..]));

        assert!(build_udp(from, "1.2.3.4:5".parse().unwrap(), b"", 0).is_none());
    }

    #[test]
    fn ipv6_options_before_transport_are_supported() {
        let original = tcp6_packet("2001:db8::1", 50000, "2001:db8::2", 443);
        let mut packet = original[..40].to_vec();
        packet[6] = 0;
        packet[4..6].copy_from_slice(&36u16.to_be_bytes());
        packet.extend([60, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend([TCP, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend(&original[40..]);
        let mut parsed = Packet::parse(&mut packet).unwrap();
        assert!(parsed.is_initial_syn());
        assert_eq!(parsed.dst_port(), 443);
        parsed.set_dst_port(12345);
        assert_eq!(parsed.dst_port(), 12345);
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        let mut packet = tcp_packet([1; 4], 1, [2; 4], 2, FLAG_SYN);
        packet[32] = 4 << 4;
        assert!(Packet::parse(&mut packet).is_none());
        packet[32] = 5 << 4;
        packet[3] = 60;
        assert!(Packet::parse(&mut packet).is_none());
        let mut udp = build_udp(
            "1.1.1.1:1".parse().unwrap(),
            "2.2.2.2:2".parse().unwrap(),
            b"abc",
            0,
        )
        .unwrap();
        udp[25] = 7;
        assert!(Packet::parse(&mut udp).is_none());
        udp[25] = 99;
        assert!(Packet::parse(&mut udp).is_none());
    }
}
