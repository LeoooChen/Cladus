//! TCP interception with WinDivert.
//!
//! Two handles cooperate. A socket-layer handle reports every `connect()`
//! with its process ID, and a decision is published per local port. A
//! network-layer handle sees every outbound IPv4 TCP packet: packets of
//! proxied flows are reflected into the local acceptor by swapping source and
//! destination and re-injecting them inbound (WinDivert's streamdump
//! technique), and the acceptor's replies are swapped back. The network layer
//! has no process IDs and the socket layer cannot touch packets; the local
//! port is the key they share.

mod ffi;
mod packet;
mod parker;
mod tcp;
mod tracker;

pub use ffi::WinDivert;
pub use tcp::TcpInterceptor;
