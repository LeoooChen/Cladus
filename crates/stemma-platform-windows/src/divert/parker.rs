//! SYN parking: holding a new connection's first SYN until the socket layer
//! has decided whether to proxy the connection.
//!
//! The socket layer reports a CONNECT slightly before its SYN, but the two
//! layers are read by independent threads, and the decision may need a
//! synchronous process lookup. A SYN that finds no decision is copied into a
//! bounded pool and its port marked `Pending`. When the decision lands, the
//! socket thread queues the pool slot here and the injector thread sends the
//! SYN on: unchanged for direct flows, redirected to the acceptor for proxied
//! ones. A SYN that waits longer than the watchdog is sent unchanged and its
//! port pinned `Abandoned`, so a late decision cannot redirect a connection
//! that is already established.

use std::collections::VecDeque;
use std::ptr::null;
use std::sync::Mutex;
use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use tracing::{debug, error, warn};
use windows_sys::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateEventW, CreateWaitableTimerExW, SetEvent,
    SetWaitableTimer, TIMER_ALL_ACCESS, WaitForMultipleObjects,
};

use super::ffi::Address;
use super::tracker::{Decision, PortTracker, SlotState, Word, pool_tag};
use crate::util::{OwnedHandle, qpc_now};

/// Largest SYN that can be parked. SYNs are small; a TCP Fast Open SYN
/// carries at most one MSS of data.
pub const MAX_SYN: usize = 2048;

pub type Send<'a> = &'a dyn Fn(&mut [u8], &mut Address, Decision);

pub struct Parker {
    entries: Box<[Entry]>,
    hint: AtomicU32,
    in_use: AtomicU32,
    peak: AtomicU32,
    queue: Mutex<VecDeque<(Word, Decision)>>,
    wake: OwnedHandle,
    /// Watchdog timeout in timestamp ticks.
    watchdog: i64,
    stopping: AtomicBool,
    pub released_by_decision: AtomicU64,
    pub released_by_watchdog: AtomicU64,
}

struct Entry {
    busy: AtomicBool,
    generation: AtomicU32,
    packet: Mutex<Parked>,
}

struct Parked {
    data: Vec<u8>,
    addr: Address,
    port: u16,
    parked_at: i64,
}

impl Parker {
    pub fn new(pool_size: usize, watchdog_ticks: i64) -> Self {
        let entries = (0..pool_size)
            .map(|_| Entry {
                busy: AtomicBool::new(false),
                generation: AtomicU32::new(1),
                packet: Mutex::new(Parked {
                    data: Vec::with_capacity(MAX_SYN),
                    addr: Address::zeroed(),
                    port: 0,
                    parked_at: 0,
                }),
            })
            .collect();
        // SAFETY: creates an unnamed auto-reset event.
        let wake = unsafe { CreateEventW(null(), 0, 0, null()) };
        Self {
            entries,
            hint: AtomicU32::new(0),
            in_use: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            queue: Mutex::new(VecDeque::new()),
            wake: OwnedHandle::new(wake).expect("CreateEventW failed"),
            watchdog: watchdog_ticks,
            stopping: AtomicBool::new(false),
            released_by_decision: AtomicU64::new(0),
            released_by_watchdog: AtomicU64::new(0),
        }
    }

    pub fn in_use(&self) -> u32 {
        self.in_use.load(Relaxed)
    }

    pub fn peak(&self) -> u32 {
        self.peak.load(Relaxed)
    }

    /// Copies a SYN into the pool. Returns its (generation tag, index), or
    /// `None` if the pool is full or the packet too large.
    pub fn park(&self, packet: &[u8], addr: &Address, port: u16) -> Option<(u32, u32)> {
        if packet.len() > MAX_SYN {
            return None;
        }
        let index = self.alloc()?;
        let entry = &self.entries[index];
        let mut parked = entry.packet.lock().unwrap();
        parked.data.clear();
        parked.data.extend_from_slice(packet);
        parked.addr = *addr;
        parked.port = port;
        parked.parked_at = qpc_now();
        drop(parked);
        Some((pool_tag(entry.generation.load(Acquire)), index as u32))
    }

    /// Returns a pool slot without sending its packet.
    pub fn free(&self, index: u32) {
        let entry = &self.entries[index as usize];
        entry.generation.fetch_add(1, AcqRel);
        entry.busy.store(false, Release);
        self.in_use.fetch_sub(1, Relaxed);
    }

    /// The decision for a parked SYN has been published; send it on.
    pub fn release(&self, word: Word, decision: Decision) {
        self.queue.lock().unwrap().push_back((word, decision));
        // SAFETY: valid event handle.
        unsafe { SetEvent(self.wake.0) };
    }

    /// The injector thread: sends released SYNs and runs the watchdog until
    /// [`stop`](Self::stop) is called, then releases everything still parked.
    pub fn run(&self, tracker: &PortTracker, send: Send<'_>) {
        let timer = millisecond_timer();
        if timer.is_none() {
            warn!("no waitable timer; SYN watchdog runs every 50 ms");
        }
        let handles: Vec<_> = [Some(self.wake.0), timer.as_ref().map(|t| t.0)]
            .into_iter()
            .flatten()
            .collect();
        while !self.stopping.load(Acquire) {
            // SAFETY: all handles are valid for the duration of the wait.
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 50) };
            self.drain(send);
            self.sweep(tracker, send, false);
        }
        self.drain(send);
        self.sweep(tracker, send, true);
    }

    pub fn stop(&self) {
        self.stopping.store(true, Release);
        // SAFETY: valid event handle.
        unsafe { SetEvent(self.wake.0) };
    }

    fn alloc(&self) -> Option<usize> {
        let n = self.entries.len();
        let start = self.hint.fetch_add(1, Relaxed) as usize;
        for k in 0..n {
            let index = (start + k) % n;
            if self.entries[index]
                .busy
                .compare_exchange(false, true, AcqRel, Relaxed)
                .is_ok()
            {
                let used = self.in_use.fetch_add(1, Relaxed) + 1;
                self.peak.fetch_max(used, Relaxed);
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn drain(&self, send: Send<'_>) {
        loop {
            let Some((word, decision)) = self.queue.lock().unwrap().pop_front() else {
                return;
            };
            if let Some((mut packet, mut addr)) = self.take_out(word.index(), word.generation()) {
                self.released_by_decision.fetch_add(1, Relaxed);
                send(&mut packet, &mut addr, decision);
            }
        }
    }

    /// Sends every SYN that waited past the watchdog (all of them when
    /// `force` is set) unchanged, pinning its port `Abandoned` first.
    pub(crate) fn sweep(&self, tracker: &PortTracker, send: Send<'_>, force: bool) {
        let now = qpc_now();
        for (index, entry) in self.entries.iter().enumerate() {
            if !entry.busy.load(Acquire) {
                continue;
            }
            let (port, syn_ts, parked_at) = {
                let parked = entry.packet.lock().unwrap();
                (parked.port, parked.addr.timestamp, parked.parked_at)
            };
            if !force && now - parked_at < self.watchdog {
                continue;
            }
            let view = tracker.load(port);
            if view.word.state() != SlotState::Pending || view.word.index() != index as u32 {
                continue;
            }
            if !tracker.pin_abandoned(port, view.word, syn_ts) {
                continue; // the decision won the race
            }
            if let Some((mut packet, mut addr)) = self.take_out(index as u32, view.word.generation()) {
                if !force {
                    self.released_by_watchdog.fetch_add(1, Relaxed);
                    debug!(port, "SYN released without a decision");
                }
                send(&mut packet, &mut addr, Decision::Direct);
            }
        }
    }

    /// Copies a parked packet out and frees its slot. The caller owns the
    /// slot through the tracker word it won.
    fn take_out(&self, index: u32, generation: u32) -> Option<(Vec<u8>, Address)> {
        let entry = &self.entries[index as usize];
        let parked = entry.packet.lock().unwrap();
        if pool_tag(entry.generation.load(Acquire)) != generation {
            error!(index, "parked SYN generation mismatch");
            return None;
        }
        let out = (parked.data.clone(), parked.addr);
        drop(parked);
        self.free(index);
        Some(out)
    }
}

/// A periodic 1 ms timer. A plain 1 ms wait would be rounded up to the
/// system tick (15.6 ms), far longer than the watchdog.
fn millisecond_timer() -> Option<OwnedHandle> {
    // SAFETY: plain Win32 calls; the handle is owned by OwnedHandle.
    unsafe {
        let mut timer = CreateWaitableTimerExW(
            null(),
            null(),
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            TIMER_ALL_ACCESS,
        );
        if timer.is_null() {
            timer = CreateWaitableTimerExW(null(), null(), 0, TIMER_ALL_ACCESS);
        }
        let timer = OwnedHandle::new(timer)?;
        let due = -10_000i64; // 1 ms from now, in 100 ns units
        (SetWaitableTimer(timer.0, &due, 1, None, null(), 0) != 0).then_some(timer)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::divert::tracker::Publish;

    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    fn syn_addr(timestamp: i64) -> Address {
        let mut addr = Address::zeroed();
        addr.timestamp = timestamp;
        addr
    }

    #[test]
    fn pool_slots_are_reused_with_a_new_generation() {
        let parker = Parker::new(2, i64::MAX);
        let (g1, i1) = parker.park(&[1], &syn_addr(0), 1).unwrap();
        let (_, i2) = parker.park(&[2], &syn_addr(0), 2).unwrap();
        assert_ne!(i1, i2);
        assert_eq!(parker.park(&[3], &syn_addr(0), 3), None, "pool is full");
        parker.free(i1);
        let (g3, i3) = parker.park(&[4], &syn_addr(0), 4).unwrap();
        assert_eq!(i3, i1);
        assert_ne!(g3, g1);
        assert_eq!((parker.in_use(), parker.peak()), (2, 2));
        assert_eq!(parker.park(&[0; MAX_SYN + 1], &syn_addr(0), 5), None);
    }

    #[test]
    fn released_syn_is_sent_with_its_decision() {
        let tracker = PortTracker::new(100);
        let parker = Parker::new(4, i64::MAX);
        let (generation, index) = parker.park(&[0xAB], &syn_addr(20), 5000).unwrap();
        assert!(tracker.try_park(5000, Word::EMPTY, generation, index, 20));
        let decision = Decision::Proxied { group: 1 };
        let Publish::Released(word) = tracker.publish(5000, decision, IP, 443, 10) else {
            panic!("expected release");
        };
        parker.release(word, decision);

        let sent = RefCell::new(Vec::new());
        let send = |p: &mut [u8], _: &mut Address, d: Decision| sent.borrow_mut().push((p.to_vec(), d));
        parker.drain(&send);
        assert_eq!(*sent.borrow(), vec![(vec![0xAB], decision)]);
        assert_eq!(parker.in_use(), 0);
    }

    #[test]
    fn watchdog_releases_undecided_syn_and_pins_the_port() {
        let tracker = PortTracker::new(100);
        let parker = Parker::new(4, 0);
        let (generation, index) = parker.park(&[0xCD], &syn_addr(20), 5000).unwrap();
        assert!(tracker.try_park(5000, Word::EMPTY, generation, index, 20));

        let sent = RefCell::new(Vec::new());
        let send = |p: &mut [u8], _: &mut Address, d: Decision| sent.borrow_mut().push((p.to_vec(), d));
        parker.sweep(&tracker, &send, false);
        assert_eq!(*sent.borrow(), vec![(vec![0xCD], Decision::Direct)]);
        assert_eq!(tracker.state(5000), SlotState::Abandoned);
        assert_eq!(parker.released_by_watchdog.load(Relaxed), 1);
        // The decision for that flow arrives too late and is rejected.
        let late = tracker.publish(5000, Decision::Proxied { group: 1 }, IP, 443, 10);
        assert_eq!(late, Publish::LateRejected);
    }
}
