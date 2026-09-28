//! Local authorization and protected service-owned directories.

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io;
use std::mem::size_of;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::util::{OwnedHandle, wide};

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by a LocalAlloc-based Win32 API.
        unsafe { LocalFree(self.0) };
    }
}

fn descriptor(sddl: &str) -> io::Result<LocalMemory> {
    let mut pointer = null_mut();
    // SAFETY: the input is terminated and the output pointer is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            1,
            &mut pointer,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalMemory(pointer))
}

fn sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u64>> {
    let mut buffer = vec![0u64; 9];
    let mut size = (buffer.len() * 8) as u32;
    // SAFETY: storage is aligned and at least SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

pub fn secure_directory(path: &Path) -> io::Result<()> {
    secure_directory_with_acl(path, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

/// A service executable must never be replaceable by a standard user, even
/// when the installer is pointed outside Program Files.
pub fn secure_install_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(io::Error::other(
            "choose a dedicated installation directory",
        ));
    }
    if path.exists() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if !matches!(
                name.as_str(),
                "stemma.exe"
                    | "stemma-engine.exe"
                    | "windivert.dll"
                    | "windivert64.sys"
                    | "licenses"
                    | "license"
                    | "third_party_notices.md"
                    | "unins000.exe"
                    | "unins000.dat"
            ) || std::fs::symlink_metadata(entry.path())?.file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err(io::Error::other(
                    "installation directory contains unrelated files or reparse points",
                ));
            }
        }
    }
    secure_directory_with_acl(
        path,
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
    )
}

fn secure_directory_with_acl(path: &Path, sddl: &str) -> io::Result<()> {
    let descriptor = descriptor(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: valid path and security attributes live through directory creation.
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(err);
        }
    }
    // Do not follow a planted junction, or permit rename while checking ACLs.
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "service data directory must not be a file or reparse point",
        ));
    }
    let (mut owner, mut allocation) = (null_mut(), null_mut());
    // SAFETY: the directory handle is open and all out pointers are valid.
    let rc = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut allocation,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _allocation = LocalMemory(allocation);
    let (admins, system) = (sid(WinBuiltinAdministratorsSid)?, sid(WinLocalSystemSid)?);
    // SAFETY: all three SIDs come from successful security APIs and are alive.
    let trusted = !owner.is_null()
        && unsafe {
            EqualSid(owner, admins.as_ptr().cast_mut().cast()) != 0
                || EqualSid(owner, system.as_ptr().cast_mut().cast()) != 0
        };
    if !trusted {
        return Err(io::Error::other(
            "service data directory is not owned by SYSTEM or Administrators",
        ));
    }
    let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
    // SAFETY: the parsed descriptor is valid and contains a DACL.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err(io::Error::other(
            "invalid service directory security descriptor",
        ));
    }
    // SAFETY: valid handle and ACL; the directory remains open against rename.
    let rc = unsafe {
        SetSecurityInfo(
            directory.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc as i32))
    }
}

pub(crate) fn create_pipe(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = descriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)")?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: the descriptor and attributes live until pipe creation returns.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
}

struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: this guard is dropped on the same thread before any await.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing a privileged worker under a client identity is unsafe.
            std::process::abort();
        }
    }
}

pub(crate) fn authorize_client(pipe: &NamedPipeServer) -> io::Result<()> {
    // SAFETY: pipe is connected and its handshake has been read on this handle.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = Impersonation;
    let mut token: HANDLE = null_mut();
    // SAFETY: the current thread is impersonating the client; out pointer is valid.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle::new(token).ok_or_else(io::Error::last_os_error)?;
    let mut needed = 0;
    // SAFETY: the first call only queries the required buffer size.
    unsafe { GetTokenInformation(token.0, TokenGroups, null_mut(), 0, &mut needed) };
    if needed < size_of::<TOKEN_GROUPS>() as u32 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: storage is aligned and has at least `needed` writable bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenGroups,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let admins = sid(WinBuiltinAdministratorsSid)?;
    // SAFETY: GetTokenInformation returned a complete TOKEN_GROUPS and SID array.
    let authorized = unsafe {
        let groups = &*storage.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            .iter()
            .any(|group| EqualSid(group.Sid, admins.as_ptr().cast_mut().cast()) != 0)
    };
    // A filtered administrator carries BA as deny-only. Membership (rather
    // than enabled privileges) is intentional: the GUI must not require UAC.
    if authorized {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "only local administrators may control Stemma",
        ))
    }
}
