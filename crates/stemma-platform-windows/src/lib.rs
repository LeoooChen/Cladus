//! Windows backend for Stemma.
//!
//! - [`divert`]: TCP interception with WinDivert, which is loaded at run time.
//! - [`etw`]: process start/exit events from the Kernel-Process ETW provider.
//! - [`process`]: synchronous queries about running processes.
#![cfg(windows)]

pub mod divert;
pub mod etw;
pub mod process;
mod util;

pub use divert::{TcpInterceptor, WinDivert};
pub use etw::EtwProcessSource;
pub use process::{WinProcessInspector, clew_is_running, is_elevated};
