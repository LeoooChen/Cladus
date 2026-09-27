//! The Stemma traffic engine: connects a platform backend to the decision
//! core and relays redirected connections through SOCKS5 proxies.

pub mod engine;
pub mod host;
pub mod logs;
pub mod relay;
pub mod socks5;
pub mod udp;
