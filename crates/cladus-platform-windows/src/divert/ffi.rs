//! Minimal WinDivert 2.2 bindings, resolved from `WinDivert.dll` at run time.
//!
//! WinDivert is LGPL-3.0/GPL-2.0 licensed. Loading the unmodified DLL at run
//! time (instead of linking an LGPL binding crate) keeps Cladus itself MIT.

use std::ffi::CString;
use std::mem::{size_of, transmute_copy};
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;

use cladus_core::platform::PlatformError;
use windows_sys::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

use crate::util::{last_error, os_error, wide};

pub const LAYER_NETWORK: i32 = 0;
pub const LAYER_SOCKET: i32 = 3;
pub const FLAG_SNIFF: u64 = 0x1;
pub const FLAG_RECV_ONLY: u64 = 0x4;
pub const EVENT_SOCKET_BIND: u8 = 3;
pub const EVENT_SOCKET_CONNECT: u8 = 4;
pub const EVENT_SOCKET_CLOSE: u8 = 7;
pub const PARAM_QUEUE_LENGTH: i32 = 0;
pub const PARAM_QUEUE_TIME: i32 = 1;
pub const PARAM_QUEUE_SIZE: i32 = 2;
pub const PARAM_VERSION_MAJOR: i32 = 3;
pub const PARAM_VERSION_MINOR: i32 = 4;
const SHUTDOWN_RECV: i32 = 1;
/// Largest packet WinDivert delivers (`WINDIVERT_MTU_MAX`).
pub const MTU_MAX: usize = 40 + 0xFFFF;

/// `WINDIVERT_ADDRESS`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    /// QueryPerformanceCounter ticks, the same clock at every layer.
    pub timestamp: i64,
    /// Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 ...
    bits: u32,
    reserved: u32,
    data: [u64; 8],
}

const _: () = assert!(size_of::<Address>() == 80);

const OUTBOUND_BIT: u32 = 1 << 17;
const IPV6_BIT: u32 = 1 << 20;

impl Address {
    pub fn zeroed() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 8],
        }
    }

    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }

    pub fn is_ipv6(&self) -> bool {
        self.bits & IPV6_BIT != 0
    }

    /// Interface and sub-interface index of a network-layer packet.
    pub fn interface(&self) -> (u32, u32) {
        (self.data[0] as u32, (self.data[0] >> 32) as u32)
    }

    /// An address for injecting an inbound network-layer packet.
    pub fn inbound(interface: (u32, u32), ipv6: bool) -> Self {
        let mut addr = Self::zeroed();
        addr.data[0] = u64::from(interface.0) | u64::from(interface.1) << 32;
        if ipv6 {
            addr.bits |= IPV6_BIT;
        }
        addr
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.bits |= OUTBOUND_BIT;
        } else {
            self.bits &= !OUTBOUND_BIT;
        }
    }

    /// The socket-layer view of the address. Only meaningful for events
    /// received on a socket-layer handle.
    pub fn socket(&self) -> SocketData {
        // SAFETY: SocketData is plain data no larger than the union.
        unsafe { self.data.as_ptr().cast::<SocketData>().read_unaligned() }
    }
}

/// `WINDIVERT_DATA_SOCKET`. Addresses are IPv6 in host byte order, least
/// significant word first; IPv4 addresses appear IPv4-mapped (`::ffff:a.b.c.d`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketData {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

const _: () = assert!(size_of::<SocketData>() <= 64);

impl SocketData {
    pub fn remote_ip(&self) -> IpAddr {
        let [a, b, c, d] = self.remote_addr.map(u128::from);
        Ipv6Addr::from_bits(a | b << 32 | c << 64 | d << 96).to_canonical()
    }
}

type OpenFn = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const u8, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, i32) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type SetParamFn = unsafe extern "C" fn(HANDLE, i32, u64) -> i32;
type GetParamFn = unsafe extern "C" fn(HANDLE, i32, *mut u64) -> i32;
type CalcChecksumsFn = unsafe extern "C" fn(*mut u8, u32, *mut Address, u64) -> i32;

/// The loaded WinDivert API.
pub struct WinDivert {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    set_param: SetParamFn,
    get_param: GetParamFn,
    calc_checksums: CalcChecksumsFn,
}

impl WinDivert {
    /// Loads `WinDivert.dll` from `dir`. The driver `WinDivert64.sys` must be
    /// in the same directory; WinDivert installs it on first use.
    pub fn load(dir: &Path) -> Result<Arc<Self>, PlatformError> {
        let dir = std::path::absolute(dir)
            .map_err(|e| PlatformError::Other(format!("invalid WinDivert directory: {e}")))?;
        for file in ["WinDivert.dll", "WinDivert64.sys"] {
            if !dir.join(file).is_file() {
                return Err(PlatformError::Other(format!(
                    "{file} not found in {}",
                    dir.display()
                )));
            }
        }
        let path = wide(dir.join("WinDivert.dll"));
        // SAFETY: `path` is an absolute, NUL-terminated path. The module is
        // never unloaded.
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(os_error("loading WinDivert.dll", last_error()));
        }
        // SAFETY: each symbol is looked up by its exported name and cast to
        // the signature declared in windivert.h.
        unsafe {
            Ok(Arc::new(Self {
                open: symbol(module, b"WinDivertOpen\0")?,
                recv: symbol(module, b"WinDivertRecv\0")?,
                send: symbol(module, b"WinDivertSend\0")?,
                shutdown: symbol(module, b"WinDivertShutdown\0")?,
                close: symbol(module, b"WinDivertClose\0")?,
                set_param: symbol(module, b"WinDivertSetParam\0")?,
                get_param: symbol(module, b"WinDivertGetParam\0")?,
                calc_checksums: symbol(module, b"WinDivertHelperCalcChecksums\0")?,
            }))
        }
    }

    /// Recomputes the IP and transport checksums of `packet` in place.
    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut Address) {
        // SAFETY: `packet` is a valid, writable buffer of the given length.
        unsafe { (self.calc_checksums)(packet.as_mut_ptr(), packet.len() as u32, addr, 0) };
    }
}

/// # Safety
/// `T` must be the function pointer type of the exported symbol `name`.
unsafe fn symbol<T>(module: HMODULE, name: &[u8]) -> Result<T, PlatformError> {
    // SAFETY: `name` is NUL-terminated.
    let proc = unsafe { GetProcAddress(module, name.as_ptr()) };
    match proc {
        // SAFETY: guaranteed by the caller.
        Some(proc) => Ok(unsafe { transmute_copy(&proc) }),
        None => Err(PlatformError::Other(format!(
            "WinDivert.dll does not export {}",
            String::from_utf8_lossy(&name[..name.len() - 1])
        ))),
    }
}

/// An open WinDivert handle. Receiving and sending are thread-safe.
pub struct Handle {
    api: Arc<WinDivert>,
    raw: HANDLE,
}

// SAFETY: WinDivert handles may be used concurrently from multiple threads.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(
        api: &Arc<WinDivert>,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> Result<Self, PlatformError> {
        let filter_c = CString::new(filter).expect("filter has no NUL bytes");
        // SAFETY: `filter_c` is NUL-terminated.
        let raw = unsafe { (api.open)(filter_c.as_ptr().cast(), layer, priority, flags) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(os_error(
                format!("WinDivertOpen(\"{filter}\")"),
                last_error(),
            ));
        }
        Ok(Self {
            api: Arc::clone(api),
            raw,
        })
    }

    pub fn api(&self) -> &WinDivert {
        &self.api
    }

    /// Receives one packet (or event, with an empty buffer). Returns the
    /// packet length or the Win32 error code.
    pub fn recv(&self, packet: &mut [u8], addr: &mut Address) -> Result<usize, u32> {
        let mut len = 0u32;
        let (ptr, cap) = if packet.is_empty() {
            (null_mut(), 0)
        } else {
            (packet.as_mut_ptr(), packet.len() as u32)
        };
        // SAFETY: `ptr` is null or a writable buffer of `cap` bytes.
        let ok = unsafe { (self.api.recv)(self.raw, ptr, cap, &mut len, addr) };
        if ok != 0 {
            Ok(len as usize)
        } else {
            Err(last_error())
        }
    }

    pub fn send(&self, packet: &[u8], addr: &Address) -> Result<(), u32> {
        // SAFETY: `packet` is a readable buffer of the given length.
        let ok = unsafe {
            (self.api.send)(
                self.raw,
                packet.as_ptr(),
                packet.len() as u32,
                null_mut(),
                addr,
            )
        };
        if ok != 0 { Ok(()) } else { Err(last_error()) }
    }

    pub fn set_param(&self, param: i32, value: u64) {
        // SAFETY: valid handle; invalid values are rejected by WinDivert.
        unsafe { (self.api.set_param)(self.raw, param, value) };
    }

    pub fn param(&self, param: i32) -> u64 {
        let mut value = 0;
        // SAFETY: `value` is a valid out pointer.
        unsafe { (self.api.get_param)(self.raw, param, &mut value) };
        value
    }

    /// Stops capturing. Already queued packets can still be received; after
    /// that `recv` fails with `ERROR_NO_DATA`. Sending keeps working.
    pub fn shutdown_recv(&self) {
        // SAFETY: valid handle.
        unsafe { (self.api.shutdown)(self.raw, SHUTDOWN_RECV) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe { (self.api.close)(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(remote_addr: [u32; 4]) -> SocketData {
        SocketData {
            endpoint_id: 0,
            parent_endpoint_id: 0,
            process_id: 0,
            local_addr: [0; 4],
            remote_addr,
            local_port: 0,
            remote_port: 0,
            protocol: 6,
        }
    }

    #[test]
    fn remote_addresses() {
        // As reported for a connection to 203.0.113.9.
        let data = socket([0xCB00_7109, 0xFFFF, 0, 0]);
        assert_eq!(data.remote_ip(), "203.0.113.9".parse::<IpAddr>().unwrap());
        let data = socket([1, 0, 0, 0x2001_0DB8]);
        assert_eq!(data.remote_ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn inbound_address_carries_the_interface() {
        let addr = Address::inbound((7, 3), true);
        assert_eq!(addr.interface(), (7, 3));
        assert!(addr.is_ipv6());
    }
}
