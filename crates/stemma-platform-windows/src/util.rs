use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

use stemma_core::platform::PlatformError;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// A kernel handle that is closed on drop.
pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl OwnedHandle {
    pub(crate) fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and owned exclusively by this value.
        unsafe { CloseHandle(self.0) };
    }
}

// SAFETY: kernel handles may be used and closed from any thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above; the handle value itself is never mutated.
unsafe impl Sync for OwnedHandle {}

pub(crate) fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

pub(crate) fn os_error(operation: impl Into<String>, code: u32) -> PlatformError {
    PlatformError::Os {
        operation: operation.into(),
        code: code as i32,
        message: std::io::Error::from_raw_os_error(code as i32).to_string(),
    }
}

/// NUL-terminated UTF-16 for Win32 calls.
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(once(0)).collect()
}

pub(crate) fn qpc_now() -> i64 {
    let mut value = 0;
    // SAFETY: `value` is a valid out pointer; the call cannot fail on Windows XP+.
    unsafe { QueryPerformanceCounter(&mut value) };
    value
}

pub(crate) fn qpc_frequency() -> i64 {
    let mut value = 0;
    // SAFETY: as above.
    unsafe { QueryPerformanceFrequency(&mut value) };
    value
}
