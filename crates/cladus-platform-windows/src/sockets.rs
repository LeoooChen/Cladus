//! Lookups in the system's socket tables.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

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

/// `MIB_TCPROW_OWNER_PID`.
#[repr(C)]
struct TcpRow {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

/// `MIB_TCP6ROW_OWNER_PID`.
#[repr(C)]
struct Tcp6Row {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

/// One row of the system's TCP or UDP table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketEntry {
    pub tcp: bool,
    pub pid: u32,
    pub local: SocketAddr,
    /// `None` for UDP and listening TCP sockets.
    pub remote: Option<SocketAddr>,
    /// TCP state name, `BOUND` for UDP.
    pub state: &'static str,
}

/// Every TCP connection and UDP endpoint with its owning process.
pub fn socket_table() -> Vec<SocketEntry> {
    let v4 = |a: u32, p: u32| SocketAddr::new(Ipv4Addr::from(a.to_ne_bytes()).into(), port_of(p));
    let v6 = |a: [u8; 16], p: u32| SocketAddr::new(Ipv6Addr::from(a).into(), port_of(p));
    let remote =
        |addr: SocketAddr, state| (state != 2 && !addr.ip().is_unspecified()).then_some(addr);
    let mut entries = find_all(tcp_table, AF_INET, |r: &TcpRow| {
        Some(SocketEntry {
            tcp: true,
            pid: r.owning_pid,
            local: v4(r.local_addr, r.local_port),
            remote: remote(v4(r.remote_addr, r.remote_port), r.state),
            state: tcp_state(r.state),
        })
    });
    entries.extend(find_all(tcp_table, AF_INET6, |r: &Tcp6Row| {
        Some(SocketEntry {
            tcp: true,
            pid: r.owning_pid,
            local: v6(r.local_addr, r.local_port),
            remote: remote(v6(r.remote_addr, r.remote_port), r.state),
            state: tcp_state(r.state),
        })
    }));
    let udp = |pid, local| SocketEntry {
        tcp: false,
        pid,
        local,
        remote: None,
        state: "BOUND",
    };
    entries.extend(find_all(udp_table, AF_INET, |r: &UdpRow| {
        Some(udp(r.owning_pid, v4(r.local_addr, r.local_port)))
    }));
    entries.extend(find_all(udp_table, AF_INET6, |r: &Udp6Row| {
        Some(udp(r.owning_pid, v6(r.local_addr, r.local_port)))
    }));
    entries
}

fn tcp_state(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

type TableFn = unsafe fn(*mut std::ffi::c_void, *mut u32, u32) -> u32;

/// # Safety
/// `buffer` must be null or hold `*size` bytes.
unsafe fn tcp_table(buffer: *mut std::ffi::c_void, size: *mut u32, family: u32) -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { GetExtendedTcpTable(buffer, size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0) }
}

/// # Safety
/// As for [`tcp_table`].
unsafe fn udp_table(buffer: *mut std::ffi::c_void, size: *mut u32, family: u32) -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { GetExtendedUdpTable(buffer, size, 0, family, UDP_TABLE_OWNER_PID, 0) }
}

/// The process that owns the UDP socket bound to local `port`. IPv4 traffic
/// can come from a dual-stack IPv6 socket, so IPv4 looks in both tables.
pub fn udp_owner(app: SocketAddr) -> Option<u32> {
    let matches = |ip: IpAddr, port: u32| {
        port_of(port) == app.port() && (ip.is_unspecified() || ip.to_canonical() == app.ip())
    };
    let mut owners = find_all(udp_table, AF_INET6, |row: &Udp6Row| {
        matches(Ipv6Addr::from(row.local_addr).into(), row.local_port).then_some(row.owning_pid)
    });
    if app.is_ipv4() {
        owners.extend(find_all(udp_table, AF_INET, |row: &UdpRow| {
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

/// Reads a `MIB_*TABLE_OWNER_PID` and returns every match of `pick`.
fn find_all<Row, T>(table: TableFn, family: u32, pick: impl Fn(&Row) -> Option<T>) -> Vec<T> {
    let mut size = 0u32;
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..4 {
        // SAFETY: `buffer` holds `size` bytes (none on the first call).
        let rc = unsafe {
            table(
                if buffer.is_empty() {
                    null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                &mut size,
                family,
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

    #[test]
    fn lists_tcp_connections() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let table = socket_table();
        let me = std::process::id();
        assert!(
            table
                .iter()
                .any(|e| e.pid == me && e.state == "LISTEN" && e.remote.is_none())
        );
        assert!(table.iter().any(|e| e.pid == me
            && e.state == "ESTABLISHED"
            && e.local == client.local_addr().unwrap()
            && e.remote == Some(listener.local_addr().unwrap())));
    }
}
