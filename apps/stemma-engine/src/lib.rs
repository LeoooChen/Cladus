//! The Stemma traffic engine: connects a platform backend to the decision
//! core and relays redirected connections through SOCKS5 proxies.

pub mod engine;
pub mod relay;
pub mod socks5;
