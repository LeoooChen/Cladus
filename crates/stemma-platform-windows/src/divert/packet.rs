//! In-place view of an IPv4/TCP packet.

pub struct Ipv4Tcp<'a> {
    buf: &'a mut [u8],
    /// Offset of the TCP header.
    tcp: usize,
}

const FLAG_SYN: u8 = 0x02;
const FLAG_ACK: u8 = 0x10;

impl<'a> Ipv4Tcp<'a> {
    /// `None` unless `buf` starts with an unfragmented IPv4 packet carrying
    /// a complete TCP header.
    pub fn parse(buf: &'a mut [u8]) -> Option<Self> {
        if buf.len() < 20 || buf[0] >> 4 != 4 || buf[9] != 6 {
            return None;
        }
        let header_len = usize::from(buf[0] & 0x0F) * 4;
        let fragment_offset = u16::from_be_bytes([buf[6], buf[7]]) & 0x1FFF;
        if header_len < 20 || fragment_offset != 0 || buf.len() < header_len + 20 {
            return None;
        }
        Some(Self {
            buf,
            tcp: header_len,
        })
    }

    pub fn swap_addresses(&mut self) {
        let (src, dst) = self.buf[12..20].split_at_mut(4);
        src.swap_with_slice(dst);
    }

    pub fn src_port(&self) -> u16 {
        self.read_u16(self.tcp)
    }

    pub fn dst_port(&self) -> u16 {
        self.read_u16(self.tcp + 2)
    }

    pub fn set_src_port(&mut self, port: u16) {
        self.buf[self.tcp..self.tcp + 2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.buf[self.tcp + 2..self.tcp + 4].copy_from_slice(&port.to_be_bytes());
    }

    pub fn seq(&self) -> u32 {
        let at = self.tcp + 4;
        u32::from_be_bytes(self.buf[at..at + 4].try_into().expect("4 bytes"))
    }

    /// The first packet of a connection: SYN without ACK.
    pub fn is_initial_syn(&self) -> bool {
        self.buf[self.tcp + 13] & (FLAG_SYN | FLAG_ACK) == FLAG_SYN
    }

    fn read_u16(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal IPv4/TCP packet (checksums not filled in).
    pub(crate) fn tcp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    #[test]
    fn reads_and_rewrites_fields() {
        let mut p = tcp_packet([10, 0, 0, 2], 50000, [203, 0, 113, 10], 443, FLAG_SYN);
        let mut pkt = Ipv4Tcp::parse(&mut p).unwrap();
        assert!(pkt.is_initial_syn());
        assert_eq!(pkt.seq(), 0x1234_5678);
        pkt.swap_addresses();
        pkt.set_dst_port(40000);
        assert_eq!((pkt.src_port(), pkt.dst_port()), (50000, 40000));
        pkt.set_src_port(443);
        assert_eq!(pkt.src_port(), 443);
        assert_eq!(&p[12..20], &[203, 0, 113, 10, 10, 0, 0, 2]);
    }

    #[test]
    fn syn_ack_is_not_initial() {
        let mut p = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, FLAG_SYN | FLAG_ACK);
        assert!(!Ipv4Tcp::parse(&mut p).unwrap().is_initial_syn());
    }

    #[test]
    fn rejects_non_tcp_fragments_and_short_packets() {
        let mut udp = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        udp[9] = 17;
        assert!(Ipv4Tcp::parse(&mut udp).is_none());
        let mut fragment = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        fragment[7] = 1;
        assert!(Ipv4Tcp::parse(&mut fragment).is_none());
        let mut short = tcp_packet([1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 0);
        assert!(Ipv4Tcp::parse(&mut short[..30]).is_none());
        let mut ipv6 = vec![0x60; 60];
        assert!(Ipv4Tcp::parse(&mut ipv6).is_none());
    }
}
