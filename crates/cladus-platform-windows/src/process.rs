//! Synchronous queries about running processes.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use cladus_core::model::ProcessKey;
use cladus_core::platform::{ProcessDescription, ProcessInspector};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, PROCESSINFOCLASS, ProcessBasicInformation,
    ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, FILETIME, HANDLE, UNICODE_STRING};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetProcessTimes, OpenMutexW, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, SYNCHRONIZATION_SYNCHRONIZE,
};

use crate::util::OwnedHandle;
use cladus_core::platform::PlatformError;

/// Keeps concurrent Cladus engines from redirecting the same traffic and
/// stopping one another's ETW session.
pub struct EngineInstance {
    _mutex: OwnedHandle,
}

impl EngineInstance {
    pub fn acquire() -> Result<Self, PlatformError> {
        if !is_elevated() {
            return Err(PlatformError::Other(
                "cladus-engine must run as administrator".to_owned(),
            ));
        }
        let name = crate::util::wide("Global\\CladusEngine");
        // SAFETY: valid NUL-terminated name and default security attributes;
        // OwnedHandle closes the returned handle on every path.
        let raw = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        let error = crate::util::last_error();
        let mutex = OwnedHandle::new(raw)
            .ok_or_else(|| crate::util::os_error("creating the engine instance mutex", error))?;
        if error == ERROR_ALREADY_EXISTS {
            return Err(PlatformError::Other(
                "another Cladus engine is already running".to_owned(),
            ));
        }
        Ok(Self { _mutex: mutex })
    }
}

/// ProcessSequenceNumber: the boot-unique identity that ETW reports as
/// `ProcessSequenceNumber` (Windows 10 1709+).
const PROCESS_SEQUENCE_NUMBER: PROCESSINFOCLASS = 92;

/// Reads process information with `PROCESS_QUERY_LIMITED_INFORMATION`.
#[derive(Clone, Copy, Debug, Default)]
pub struct WinProcessInspector;

impl ProcessInspector for WinProcessInspector {
    fn live_key(&self, pid: u32) -> Option<ProcessKey> {
        let handle = open(pid)?;
        Some(ProcessKey {
            pid,
            instance: sequence_number(&handle)?,
        })
    }

    fn describe(&self, pid: u32) -> Option<ProcessDescription> {
        let handle = open(pid)?;
        let instance = sequence_number(&handle)?;
        let path = image_path(&handle)?;
        let name = path.rsplit('\\').next().unwrap_or(&path).to_owned();
        Some(ProcessDescription {
            key: ProcessKey { pid, instance },
            parent_pid: parent_pid(&handle),
            name,
            create_time: create_time(&handle),
        })
    }

    fn image_path(&self, key: ProcessKey) -> Option<String> {
        image_path(&open_key(key)?)
    }

    fn cmdline(&self, key: ProcessKey) -> Option<String> {
        cmdline(&open_key(key)?)
    }
}

fn open(pid: u32) -> Option<OwnedHandle> {
    if pid == 0 {
        return None;
    }
    // SAFETY: plain Win32 call; the returned handle is owned by OwnedHandle.
    OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

/// Opens `key` only if its PID still belongs to that process.
fn open_key(key: ProcessKey) -> Option<OwnedHandle> {
    let handle = open(key.pid)?;
    (sequence_number(&handle)? == key.instance).then_some(handle)
}

/// Reads a fixed-size information class into `value`.
fn query<T>(handle: &OwnedHandle, class: PROCESSINFOCLASS, value: &mut T) -> bool {
    let mut returned = 0;
    // SAFETY: `value` is a valid, writable buffer of the size passed.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.0,
            class,
            (value as *mut T).cast::<c_void>(),
            size_of::<T>() as u32,
            &mut returned,
        )
    };
    status >= 0
}

fn sequence_number(handle: &OwnedHandle) -> Option<u64> {
    let mut value = 0u64;
    (query(handle, PROCESS_SEQUENCE_NUMBER, &mut value) && value != 0).then_some(value)
}

/// Parent PID recorded at creation. The parent may have exited since and
/// the PID may have been reused, so callers must validate it.
fn parent_pid(handle: &OwnedHandle) -> u32 {
    #[repr(C)]
    struct BasicInformation {
        exit_status: i32,
        peb: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }
    let mut info = BasicInformation {
        exit_status: 0,
        peb: null_mut(),
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    if query(handle, ProcessBasicInformation, &mut info) {
        info.inherited_from_unique_process_id as u32
    } else {
        0
    }
}

/// Creation time as a FILETIME value, 0 on failure. Same unit as the ETW
/// `CreateTime` field.
fn create_time(handle: &OwnedHandle) -> u64 {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: all out pointers are valid.
    let ok =
        unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) };
    if ok == 0 {
        return 0;
    }
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

fn image_path(handle: &OwnedHandle) -> Option<String> {
    let mut buffer = vec![0u16; 32 * 1024];
    let mut len = buffer.len() as u32;
    // SAFETY: `buffer` holds `len` UTF-16 units.
    let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buffer[..len as usize]))
}

fn cmdline(handle: &OwnedHandle) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: a zero-length query only reports the required size.
    unsafe {
        NtQueryInformationProcess(
            handle.0,
            ProcessCommandLineInformation,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if (needed as usize) < size_of::<UNICODE_STRING>() {
        return None;
    }
    // u64 storage keeps the UNICODE_STRING header aligned.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `needed` bytes.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.0,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if status < 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with a UNICODE_STRING whose
    // Buffer points into the same allocation.
    let text = unsafe {
        let header = &*buffer.as_ptr().cast::<UNICODE_STRING>();
        if header.Buffer.is_null() || header.Length == 0 {
            return Some(String::new());
        }
        std::slice::from_raw_parts(header.Buffer, usize::from(header.Length) / 2)
    };
    Some(String::from_utf16_lossy(text))
}

/// True if Clew, the program Cladus succeeds, is running. Clew holds a named
/// single-instance mutex.
pub fn clew_is_running() -> bool {
    let name = crate::util::wide("Global\\Clew_SingleInstance");
    // SAFETY: `name` is NUL-terminated; the handle is closed by OwnedHandle.
    OwnedHandle::new(unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) }).is_some()
}

/// True if the current process runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let Some(token) = OwnedHandle::new(token) else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    // SAFETY: `elevation` is a valid buffer of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_current_process() {
        let inspector = WinProcessInspector;
        let pid = std::process::id();
        let me = inspector
            .describe(pid)
            .expect("current process is readable");
        assert_eq!(me.key.pid, pid);
        assert_ne!(me.key.instance, 0);
        assert!(me.name.to_lowercase().ends_with(".exe"), "{}", me.name);
        assert_ne!(me.create_time, 0);
        assert_eq!(inspector.live_key(pid), Some(me.key));

        let path = inspector.image_path(me.key).unwrap();
        assert!(path.ends_with(&me.name), "{path}");
        let cmdline = inspector.cmdline(me.key).unwrap();
        assert!(!cmdline.is_empty());

        let stale = ProcessKey {
            pid,
            instance: me.key.instance + 1,
        };
        assert_eq!(inspector.cmdline(stale), None);
    }

    #[test]
    fn parent_is_an_older_process() {
        let inspector = WinProcessInspector;
        let me = inspector.describe(std::process::id()).unwrap();
        if let Some(parent) = inspector.describe(me.parent_pid) {
            assert!(parent.create_time <= me.create_time);
        }
    }
}
