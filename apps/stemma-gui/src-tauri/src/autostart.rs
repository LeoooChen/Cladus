//! Starting at logon through `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//! Stemma runs unelevated, so no scheduled task or UAC prompt is involved.

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegDeleteKeyValueW,
    RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE: &str = "Stemma";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn os_error(rc: u32) -> String {
    std::io::Error::from_raw_os_error(rc as i32).to_string()
}

fn command() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    Ok(format!("\"{}\" --autostart", exe.display()))
}

fn current() -> Option<String> {
    let (key, value) = (wide(KEY), wide(VALUE));
    let mut buffer = vec![0u16; 2048];
    let mut bytes = (buffer.len() * 2) as u32;
    // SAFETY: buffer holds `bytes` bytes; strings are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

pub fn enabled() -> bool {
    current().is_some()
}

pub fn set(enable: bool) -> Result<(), String> {
    let (key, value) = (wide(KEY), wide(VALUE));
    if !enable {
        // SAFETY: valid NUL-terminated strings.
        let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) };
        return if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(os_error(rc))
        };
    }
    let data = wide(&command()?);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: the out pointer is valid; the key is closed below.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut handle,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(os_error(rc));
    }
    // SAFETY: `data` is NUL-terminated UTF-16 of the given byte length.
    let rc = unsafe {
        RegSetValueExW(
            handle,
            value.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    // SAFETY: opened above.
    unsafe { RegCloseKey(handle) };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(os_error(rc))
    }
}

/// An entry that points at another copy (e.g. an old install location) is
/// corrected to this executable.
pub fn repair() {
    if let (Some(existing), Ok(expected)) = (current(), command())
        && !existing.eq_ignore_ascii_case(&expected)
    {
        let _ = set(true);
    }
}
