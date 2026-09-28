//! Windows backend for Cladus.
//!
//! - [`divert`]: TCP and UDP interception with WinDivert, which is loaded at
//!   run time.
//! - [`etw`]: process start/exit events from the Kernel-Process ETW provider.
//! - [`process`]: synchronous queries about running processes.
//! - [`sockets`]: lookups in the system's socket tables.
#![cfg(windows)]

pub mod divert;
pub mod dns;
pub mod etw;
pub mod ipc;
pub mod process;
pub mod security;
pub mod service;
pub mod sockets;
mod util;

pub use divert::{Interceptor, WinDivert};
pub use dns::WinSystemDns;
pub use etw::EtwProcessSource;
pub use process::{EngineInstance, WinProcessInspector, clew_is_running, is_elevated};
