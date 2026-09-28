//! Redirecting the system's DNS to the local forwarder, with a journal.
//!
//! Original settings are written to the journal before anything changes, and
//! the journal is removed only once every interface has been restored. A
//! journal left behind by a crash is replayed on the next start.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use stemma_core::platform::{InterfaceDns, SystemDns};
use tracing::{info, warn};

/// Where the system resolver is pointed while DNS is redirected.
pub const LISTEN_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
pub const LISTEN_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    interfaces: Vec<InterfaceDns>,
}

pub struct DnsRedirect {
    system: Arc<dyn SystemDns>,
    journal: PathBuf,
    applied: Mutex<Vec<InterfaceDns>>,
}

impl DnsRedirect {
    pub fn new(system: Arc<dyn SystemDns>, journal: PathBuf) -> anyhow::Result<Self> {
        // Never replace a previous run's original settings with redirected ones.
        recover(system.as_ref(), &journal)?;
        Ok(Self {
            system,
            journal,
            applied: Mutex::new(Vec::new()),
        })
    }

    /// Redirects interfaces not redirected yet, including ones that appeared
    /// since the last call. Returns the original servers seen so far.
    pub fn apply(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut applied = self.applied.lock().unwrap();
        let known: HashSet<String> = applied.iter().map(|i| i.id.clone()).collect();
        let fresh: Vec<InterfaceDns> = self
            .system
            .capture()?
            .into_iter()
            .filter(|i| !known.contains(&i.id))
            .map(sanitize)
            .collect();
        if !fresh.is_empty() {
            let mut failures = Vec::new();
            let mut all = applied.clone();
            all.extend(fresh.iter().cloned());
            write_journal(&self.journal, &all)?;
            for interface in fresh {
                // Recorded even on failure, so restoring covers a partial change.
                let result = self.system.redirect(&interface.id, LISTEN_V4, LISTEN_V6);
                match result {
                    Ok(()) => info!(interface = %interface.name, "DNS redirected to the forwarder"),
                    Err(err) => failures.push(format!("{}: {err}", interface.name)),
                }
                applied.push(interface);
            }
            if !failures.is_empty() {
                anyhow::bail!("cannot redirect DNS: {}", failures.join("; "));
            }
        }
        Ok(original_servers(&applied))
    }

    /// Restores every interface; the journal is kept if any restore failed.
    pub fn restore(&self) -> anyhow::Result<()> {
        let mut applied = self.applied.lock().unwrap();
        if applied.is_empty() {
            return Ok(());
        }
        let failed = restore_all(self.system.as_ref(), &applied);
        if failed.is_empty() {
            remove_journal(&self.journal)?;
            applied.clear();
            Ok(())
        } else {
            write_journal(&self.journal, &failed)?;
            *applied = failed;
            anyhow::bail!(
                "DNS of {} interface(s) could not be restored",
                applied.len()
            )
        }
    }
}

impl Drop for DnsRedirect {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            warn!("{err:#}");
        }
    }
}

/// Replays a journal left by a previous run. Returns whether one existed.
pub fn recover(system: &dyn SystemDns, journal: &Path) -> anyhow::Result<bool> {
    let text = match std::fs::read_to_string(journal) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).context("cannot read the DNS journal"),
    };
    let entries: Journal = serde_json::from_str(&text).context("the DNS journal is corrupt")?;
    info!(
        interfaces = entries.interfaces.len(),
        "restoring DNS settings from the journal"
    );
    let failed = restore_all(system, &entries.interfaces);
    if failed.is_empty() {
        remove_journal(journal)?;
        Ok(true)
    } else {
        write_journal(journal, &failed)?;
        anyhow::bail!("DNS of {} interface(s) could not be restored", failed.len())
    }
}

fn restore_all(system: &dyn SystemDns, interfaces: &[InterfaceDns]) -> Vec<InterfaceDns> {
    let mut failed = Vec::new();
    for interface in interfaces {
        match system.restore(interface) {
            Ok(()) => info!(interface = %interface.name, "DNS restored"),
            Err(err) => {
                warn!(interface = %interface.name, "cannot restore DNS: {err}");
                failed.push(interface.clone());
            }
        }
    }
    failed
}

/// Settings that already point at the forwarder (a journal was lost) are
/// restored as automatic rather than to the forwarder itself.
fn sanitize(mut interface: InterfaceDns) -> InterfaceDns {
    let ours = |ip: &IpAddr| *ip == IpAddr::V4(LISTEN_V4) || *ip == IpAddr::V6(LISTEN_V6);
    for family in [&mut interface.v4, &mut interface.v6] {
        family.servers.retain(|ip| !ours(ip));
        if !family.automatic && family.servers.is_empty() {
            family.automatic = true;
        }
    }
    interface
}

fn original_servers(interfaces: &[InterfaceDns]) -> Vec<IpAddr> {
    let mut servers: Vec<IpAddr> = Vec::new();
    for ip in interfaces
        .iter()
        .flat_map(|i| i.v4.servers.iter().chain(&i.v6.servers))
    {
        if !servers.contains(ip) {
            servers.push(*ip);
        }
    }
    servers
}

fn write_journal(path: &Path, interfaces: &[InterfaceDns]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let journal = Journal {
        interfaces: interfaces.to_vec(),
    };
    crate::host::atomic_write(path, serde_json::to_string_pretty(&journal)?.as_bytes())
}

fn remove_journal(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            Err(err).context("cannot remove the DNS journal")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use stemma_core::platform::{DnsServers, PlatformError};

    use super::*;

    /// A fake system: interface id -> (v4 servers, automatic).
    #[derive(Default)]
    struct Fake {
        state: Mutex<Vec<InterfaceDns>>,
        fail_restore: Mutex<bool>,
    }

    impl SystemDns for Fake {
        fn capture(&self) -> Result<Vec<InterfaceDns>, PlatformError> {
            Ok(self.state.lock().unwrap().clone())
        }
        fn redirect(&self, id: &str, v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(), PlatformError> {
            for i in self.state.lock().unwrap().iter_mut().filter(|i| i.id == id) {
                i.v4 = DnsServers {
                    automatic: false,
                    servers: vec![v4.into()],
                };
                i.v6 = DnsServers {
                    automatic: false,
                    servers: vec![v6.into()],
                };
            }
            Ok(())
        }
        fn restore(&self, original: &InterfaceDns) -> Result<(), PlatformError> {
            if *self.fail_restore.lock().unwrap() {
                return Err(PlatformError::Other("nope".into()));
            }
            for i in self
                .state
                .lock()
                .unwrap()
                .iter_mut()
                .filter(|i| i.id == original.id)
            {
                *i = original.clone();
            }
            Ok(())
        }
    }

    fn interface(id: &str, automatic: bool, server: &str) -> InterfaceDns {
        InterfaceDns {
            id: id.into(),
            name: id.into(),
            v4: DnsServers {
                automatic,
                servers: vec![server.parse().unwrap()],
            },
            v6: DnsServers {
                automatic: true,
                servers: vec![],
            },
        }
    }

    fn temp_journal(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stemma-dns-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("state").join("dns-journal.json")
    }

    #[test]
    fn redirect_restore_and_new_interfaces() {
        let fake = Arc::new(Fake::default());
        let original = vec![
            interface("a", true, "192.168.1.1"),
            interface("b", false, "9.9.9.9"),
        ];
        *fake.state.lock().unwrap() = original.clone();
        let journal = temp_journal("cycle");
        let redirect = DnsRedirect::new(fake.clone(), journal.clone()).unwrap();
        let servers = redirect.apply().unwrap();
        assert_eq!(
            servers,
            [
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "9.9.9.9".parse().unwrap()
            ]
        );
        assert!(journal.exists());
        assert!(
            fake.state
                .lock()
                .unwrap()
                .iter()
                .all(|i| i.v4.servers == [IpAddr::V4(LISTEN_V4)])
        );
        // A new interface appears and is picked up on the next pass.
        fake.state
            .lock()
            .unwrap()
            .push(interface("c", true, "10.0.0.1"));
        redirect.apply().unwrap();
        redirect.restore().unwrap();
        assert!(!journal.exists());
        let mut expected = original;
        expected.push(interface("c", true, "10.0.0.1"));
        assert_eq!(*fake.state.lock().unwrap(), expected);
    }

    #[test]
    fn a_crash_is_recovered_from_the_journal() {
        let fake = Arc::new(Fake::default());
        let original = vec![interface("a", false, "1.1.1.1")];
        *fake.state.lock().unwrap() = original.clone();
        let journal = temp_journal("crash");
        let redirect = DnsRedirect::new(fake.clone(), journal.clone()).unwrap();
        redirect.apply().unwrap();
        std::mem::forget(redirect); // crash: no restore
        assert!(recover(fake.as_ref(), &journal).unwrap());
        assert_eq!(*fake.state.lock().unwrap(), original);
        assert!(!recover(fake.as_ref(), &journal).unwrap());
    }

    #[test]
    fn failed_restores_stay_in_the_journal() {
        let fake = Arc::new(Fake::default());
        *fake.state.lock().unwrap() = vec![interface("a", true, "1.1.1.1")];
        let journal = temp_journal("fail");
        let redirect = DnsRedirect::new(fake.clone(), journal.clone()).unwrap();
        redirect.apply().unwrap();
        *fake.fail_restore.lock().unwrap() = true;
        assert!(redirect.restore().is_err());
        assert!(journal.exists());
        *fake.fail_restore.lock().unwrap() = false;
        redirect.restore().unwrap();
        assert!(!journal.exists());
    }

    #[test]
    fn stale_forwarder_settings_restore_as_automatic() {
        let clean = sanitize(interface("a", false, "127.0.0.2"));
        assert!(clean.v4.automatic && clean.v4.servers.is_empty());
    }

    #[test]
    fn failed_recovery_cannot_overwrite_the_original_journal() {
        let fake = Arc::new(Fake::default());
        let original = vec![interface("a", false, "9.9.9.9")];
        let journal = temp_journal("preserve");
        write_journal(&journal, &original).unwrap();
        let before = std::fs::read(&journal).unwrap();
        *fake.fail_restore.lock().unwrap() = true;
        assert!(DnsRedirect::new(fake.clone(), journal.clone()).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        *fake.fail_restore.lock().unwrap() = false;
        let redirect = DnsRedirect::new(fake, journal.clone()).unwrap();
        assert!(!journal.exists());
        drop(redirect);
    }
}
