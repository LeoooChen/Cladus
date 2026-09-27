//! Lookups in the system's socket tables.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedUdpTable, UDP_TABLE_OWNER_PID};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// `MIB_UDPROW_OWNER_PID`.
#[repr(C)]
struct UdpRow {
    local_addr: u32,
    local_port: u32,
    owning_pid: u32,
}

/// `MIB_UDP6ROW_OWNER_PID`.
#[repr(C)]
struct Udp6Row {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    owning_pid: u32,
}

/// The process that owns the UDP socket bound to local `port`. IPv4 traffic
/// can come from a dual-stack IPv6 socket, so IPv4 looks in both tables.
pub fn udp_owner(app: SocketAddr) -> Option<u32> {
    let matches = |ip: IpAddr, port: u32| {
        port_of(port) == app.port() && (ip.is_unspecified() || ip.to_canonical() == app.ip())
    };
    let mut owners = find_all(AF_INET6, |row: &Udp6Row| {
        matches(Ipv6Addr::from(row.local_addr).into(), row.local_port).then_some(row.owning_pid)
    });
    if app.is_ipv4() {
        owners.extend(find_all(AF_INET, |row: &UdpRow| {
            matches(
                Ipv4Addr::from(row.local_addr.to_ne_bytes()).into(),
                row.local_port,
            )
            .then_some(row.owning_pid)
        }));
    }
    owners.sort_unstable();
    owners.dedup();
    (owners.len() == 1).then(|| owners[0])
}

/// Ports are stored in network byte order in the low 16 bits.
fn port_of(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// Reads a `MIB_UDP*TABLE_OWNER_PID` and returns the first match of `pick`.
fn find_all<Row, T>(family: u32, pick: impl Fn(&Row) -> Option<T>) -> Vec<T> {
    let mut size = 0u32;
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..4 {
        // SAFETY: `buffer` holds `size` bytes (none on the first call).
        let rc = unsafe {
            GetExtendedUdpTable(
                if buffer.is_empty() {
                    null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                &mut size,
                0,
                family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER {
            // The table may grow between calls; leave some room.
            buffer = vec![0u64; (size as usize + 1024).div_ceil(8)];
            size = (buffer.len() * 8) as u32;
            continue;
        }
        if rc != 0 || buffer.is_empty() {
            return Vec::new();
        }
        // SAFETY: the table starts with its entry count followed by that many
        // rows, and the rows are 4-byte aligned after the u32 count.
        let rows = unsafe {
            let count = *buffer.as_ptr().cast::<u32>() as usize;
            let first = buffer.as_ptr().cast::<u8>().add(4).cast::<Row>();
            std::slice::from_raw_parts(first, count)
        };
        return rows.iter().filter_map(&pick).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    fn finds_the_owner_of_a_udp_socket() {
        let me = std::process::id();
        let v4 = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(udp_owner(v4.local_addr().unwrap()), Some(me));
        let v6 = UdpSocket::bind("[::]:0").unwrap();
        assert_eq!(udp_owner(v6.local_addr().unwrap()), Some(me));
    }
}
