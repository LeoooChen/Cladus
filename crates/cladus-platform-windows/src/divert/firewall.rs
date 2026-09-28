//! A port-scoped Windows Firewall exception for the internal TCP reflector.

use std::path::PathBuf;
use std::process::{Command, Output};

use tracing::{debug, warn};

use cladus_core::platform::PlatformError;

const RULE: &str = "Cladus TCP reflection {A931F2F9-36B8-4C52-9C9B-76AC7B86E1A3}";

pub(super) struct FirewallRule {
    netsh: PathBuf,
}

impl FirewallRule {
    pub(super) fn open(port: u16) -> Result<Self, PlatformError> {
        let netsh = netsh_path()?;
        let program = std::env::current_exe()
            .map_err(|err| PlatformError::Other(format!("cannot find engine path: {err}")))?;
        // Replace a stale rule left by a crash. Only one engine can run at once.
        let _ = remove_stale();
        let output = run(
            &netsh,
            "add",
            &[
                format!("name={RULE}"),
                "dir=in".to_owned(),
                "action=allow".to_owned(),
                "protocol=TCP".to_owned(),
                format!("localport={port}"),
                format!("program={}", program.display()),
                "profile=any".to_owned(),
                "enable=yes".to_owned(),
            ],
        )
        .map_err(|err| PlatformError::Other(format!("cannot configure Windows Firewall: {err}")))?;
        if !output.status.success() {
            return Err(PlatformError::Other(format!(
                "cannot allow the internal TCP listener through Windows Firewall: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            )));
        }
        debug!(
            port,
            "opened Windows Firewall for the internal TCP listener"
        );
        Ok(Self { netsh })
    }
}

impl Drop for FirewallRule {
    fn drop(&mut self) {
        match run(&self.netsh, "delete", &[format!("name={RULE}")]) {
            Ok(output) if output.status.success() => {}
            Ok(output) => warn!(
                status = %output.status,
                "could not remove the internal TCP firewall rule"
            ),
            Err(err) => warn!(%err, "could not remove the internal TCP firewall rule"),
        }
    }
}

fn run(netsh: &PathBuf, action: &str, options: &[String]) -> std::io::Result<Output> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    Command::new(netsh)
        .args(["advfirewall", "firewall", action, "rule"])
        .args(options)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

fn netsh_path() -> Result<PathBuf, PlatformError> {
    let windows = std::env::var_os("SystemRoot")
        .ok_or_else(|| PlatformError::Other("SystemRoot is not set".to_owned()))?;
    Ok(PathBuf::from(windows).join("System32").join("netsh.exe"))
}

pub(super) fn remove_stale() -> Result<(), PlatformError> {
    let netsh = netsh_path()?;
    run(&netsh, "delete", &[format!("name={RULE}")]).map_err(|err| {
        PlatformError::Other(format!("cannot remove Windows Firewall rule: {err}"))
    })?;
    Ok(())
}
