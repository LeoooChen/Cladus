//! Platform-independent domain logic for Cladus.
//!
//! Nothing in this crate performs I/O, spawns threads, depends on an async
//! runtime or calls an operating-system API. Platform backends implement the
//! traits in [`platform`] and feed events into a [`decision::DecisionCore`],
//! which owns the process tree and answers "should this connection be
//! proxied, and through which group?".

pub mod clew;
pub mod config;
pub mod decision;
pub mod matching;
pub mod model;
pub mod platform;
pub mod policy;
pub mod rules;
pub mod tree;
