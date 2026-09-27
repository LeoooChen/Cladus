//! Per-interface system DNS settings via `SetInterfaceDnsSettings` (Windows 10 2004+).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use stemma_core::platform::{DnsServers, InterfaceDns, PlatformError, SystemDns};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
    DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH, SetInterfaceDnsSettings,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows_sys::core::GUID;

use crate::util::{os_error, wide};

pub struct WinSystemDns;

impl SystemDns for WinSystemDns {
    fn capture(&self) -> Result<Vec<InterfaceDns>, PlatformError> {
        let mut size = 16 * 1024u32;
        let mut buffer: Vec<u64> = Vec::new();
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut rc = ERROR_BUFFER_OVERFLOW;
        for _ in 0..3 {
            buffer.resize((size as usize).div_ceil(8), 0);
            // SAFETY: the buffer is 8-byte aligned and `size` bytes long.
            rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if rc != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        if rc != NO_ERROR {
            return Err(os_error("GetAdaptersAddresses", rc));
        }
        let mut result = Vec::new();
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: the list was filled in by GetAdaptersAddresses and lives in `buffer`.
            let a = unsafe { &*adapter };
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp
                || (a.IfType != IF_TYPE_ETHERNET_CSMACD && a.IfType != IF_TYPE_IEEE80211)
                || a.FirstGatewayAddress.is_null()
                || a.AdapterName.is_null()
            {
                continue;
            }
            // SAFETY: AdapterName is a NUL-terminated ANSI GUID string.
            let id = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast()) }
                .to_string_lossy()
                .into_owned();
            let name = if a.FriendlyName.is_null() {
                id.clone()
            } else {
                // SAFETY: FriendlyName is NUL-terminated UTF-16.
                String::from_utf16_lossy(unsafe { wide_str(a.FriendlyName) })
            };
            let (mut v4, mut v6) = (Vec::new(), Vec::new());
            let mut server = a.FirstDnsServerAddress;
            while !server.is_null() {
                // SAFETY: as above.
                let s = unsafe { &*server };
                server = s.Next;
                // SAFETY: lpSockaddr points at a sockaddr of the given length.
                match unsafe { sockaddr_ip(s.Address.lpSockaddr) } {
                    Some(IpAddr::V4(ip)) => v4.push(IpAddr::V4(ip)),
                    Some(IpAddr::V6(ip)) if !is_site_local_default(ip) => v6.push(IpAddr::V6(ip)),
                    _ => {}
                }
            }
            // Only change an interface whose mode can be restored exactly.
            let (Some(auto4), Some(auto6)) = (
                is_automatic(&format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{id}"
                )),
                is_automatic(&format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{id}"
                )),
            ) else {
                tracing::warn!(interface = %name, "cannot read its DNS mode; leaving it unchanged");
                continue;
            };
            result.push(InterfaceDns {
                id,
                name,
                v4: DnsServers {
                    automatic: auto4,
                    servers: v4,
                },
                v6: DnsServers {
                    automatic: auto6,
                    servers: v6,
                },
            });
        }
        Ok(result)
    }

    fn redirect(&self, id: &str, v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(), PlatformError> {
        set(id, false, &v4.to_string())?;
        set(id, true, &v6.to_string())
    }

    fn restore(&self, original: &InterfaceDns) -> Result<(), PlatformError> {
        let list = |servers: &DnsServers| {
            if servers.automatic {
                String::new()
            } else {
                servers
                    .servers
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        };
        set(&original.id, false, &list(&original.v4))?;
        set(&original.id, true, &list(&original.v6))
    }
}

/// fec0:0:0:ffff::1-3 are placeholders Windows reports when no IPv6 DNS is known.
fn is_site_local_default(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0xfec0 && s[1..4] == [0, 0, 0xffff] && s[4..7] == [0, 0, 0] && (1..=3).contains(&s[7])
}

/// An empty list returns the interface to automatic (DHCP/RA) servers.
fn set(id: &str, ipv6: bool, servers: &str) -> Result<(), PlatformError> {
    let guid =
        parse_guid(id).ok_or_else(|| PlatformError::Other(format!("invalid interface id {id}")))?;
    let mut name_server = wide(servers);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | if ipv6 { DNS_SETTING_IPV6 } else { 0 }) as u64,
        NameServer: name_server.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: settings and the string it points to outlive the call.
    let rc = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if rc == NO_ERROR {
        Ok(())
    } else {
        Err(os_error("SetInterfaceDnsSettings", rc))
    }
}

/// The NameServer registry value holds only explicitly configured servers;
/// a missing or blank value means automatic.
fn is_automatic(subkey: &str) -> Option<bool> {
    let key = wide(subkey);
    let value = wide("NameServer");
    let mut bytes = 0u32;
    // SAFETY: querying the size with a null buffer.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Some(true);
    }
    if rc != NO_ERROR {
        return None;
    }
    let mut text = vec![0u16; bytes as usize / 2 + 1];
    // SAFETY: `text` holds at least `bytes` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            text.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if rc != NO_ERROR {
        return None;
    }
    let text =
        String::from_utf16_lossy(&text[..text.iter().position(|&c| c == 0).unwrap_or(text.len())]);
    Some(
        text.trim_matches(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .is_empty(),
    )
}

/// # Safety
/// `p` must be a NUL-terminated UTF-16 string.
unsafe fn wide_str<'a>(p: *const u16) -> &'a [u16] {
    let mut len = 0;
    // SAFETY: guaranteed by the caller.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the terminator are readable.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// # Safety
/// `sa` must be null or point at a valid socket address.
unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: every sockaddr starts with the family; the cast matches it.
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let sin = &*sa.cast::<SOCKADDR_IN>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.S_un.S_addr,
                ))))
            }
            AF_INET6 => {
                let sin = &*sa.cast::<SOCKADDR_IN6>();
                Some(IpAddr::V6(Ipv6Addr::from(sin.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

fn parse_guid(s: &str) -> Option<GUID> {
    let hex: String = s
        .trim_matches(|c| c == '{' || c == '}')
        .split('-')
        .collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let n = u128::from_str_radix(&hex, 16).ok()?;
    Some(GUID::from_u128(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_parse() {
        let guid = parse_guid("{01234567-89AB-CDEF-0123-456789ABCDEF}").unwrap();
        assert_eq!(
            (guid.data1, guid.data2, guid.data3),
            (0x0123_4567, 0x89ab, 0xcdef)
        );
        assert_eq!(guid.data4, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert!(parse_guid("{0123}").is_none());
    }

    #[test]
    fn capture_works() {
        // Reading needs no privileges; every returned interface has an id.
        for interface in WinSystemDns.capture().unwrap() {
            assert!(parse_guid(&interface.id).is_some(), "{interface:?}");
        }
    }
}
