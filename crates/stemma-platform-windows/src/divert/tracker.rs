//! Per-local-port connection state shared by the WinDivert threads.
//!
//! Each local TCP port has one slot. Its state lives in a single atomic word
//! `{state:8 | tag:24 | index:32}` so every transition is one compare-and-swap:
//!
//! - `Empty`: nothing known about a flow on this port.
//! - `Pending`: the network layer parked this flow's SYN (tag = pool
//!   generation, index = pool slot) and waits for the socket layer's decision.
//! - `Proxied` / `Direct`: decided. The tag is a sequence number, so a word
//!   identifies one decision: a relay clears exactly the flow it served even
//!   if the port was reused and decided the same way again meanwhile.
//! - `Abandoned`: no decision arrived in time; the SYN was sent on unchanged.
//!   A decision that arrives later for the same flow is rejected, because
//!   redirecting an established connection breaks it.
//!
//! Writers: the socket-layer thread publishes decisions and handles CLOSE;
//! network workers only park (`Empty` → `Pending`) and pin (`→ Abandoned`);
//! the parking injector pins on timeout; a finished relay clears its own word.
//! Auxiliary fields are written before the releasing CAS and read after an
//! acquiring load. A torn read can at worst misroute one packet.
//!
//! Timestamps are WinDivert kernel timestamps (QueryPerformanceCounter
//! ticks), the same clock at the socket and network layers.

use std::net::Ipv4Addr;
use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};

pub const PORTS: usize = 1 << 16;
const NO_INDEX: u32 = u32::MAX;
const TAG_MASK: u32 = 0x00FF_FFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Empty,
    Pending,
    Proxied,
    Direct,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word(u64);

impl Word {
    pub const EMPTY: Self = Self(0);

    fn new(state: SlotState, tag: u32, index: u32) -> Self {
        let state = match state {
            SlotState::Empty => 0u64,
            SlotState::Pending => 1,
            SlotState::Proxied => 2,
            SlotState::Direct => 3,
            SlotState::Abandoned => 4,
        };
        Self(state << 56 | u64::from(tag & TAG_MASK) << 32 | u64::from(index))
    }

    pub fn state(self) -> SlotState {
        match self.0 >> 56 {
            1 => SlotState::Pending,
            2 => SlotState::Proxied,
            3 => SlotState::Direct,
            4 => SlotState::Abandoned,
            _ => SlotState::Empty,
        }
    }

    /// Pool generation of a `Pending` word.
    pub fn generation(self) -> u32 {
        (self.0 >> 32) as u32 & TAG_MASK
    }

    /// Pool slot of a `Pending` word.
    pub fn index(self) -> u32 {
        self.0 as u32
    }
}

pub fn pool_tag(generation: u32) -> u32 {
    generation & TAG_MASK
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Proxied { group: u32 },
    Direct,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publish {
    Stored,
    /// The flow's SYN was parked; the caller now owns its pool slot.
    Released(Word),
    /// The flow already went out direct.
    LateRejected,
}

#[derive(Clone, Copy, Debug)]
pub struct SlotView {
    pub word: Word,
    pub connect_ts: i64,
    pub syn_ts: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    pub word: Word,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub group: u32,
}

#[derive(Default)]
#[repr(align(64))]
struct Slot {
    word: AtomicU64,
    /// Timestamp of the CONNECT that produced the current decision.
    connect_ts: AtomicI64,
    /// Timestamp of the SYN that was parked or sent on while undecided.
    syn_ts: AtomicI64,
    remote_ip: AtomicU32,
    remote_port: AtomicU32,
    group: AtomicU32,
    /// Initial sequence number of the last SYN handled on this port.
    syn_seq: AtomicU32,
}

pub struct PortTracker {
    slots: Box<[Slot]>,
    sequence: AtomicU32,
    ttl: i64,
}

impl PortTracker {
    /// `ttl`: how much older than a SYN a decision may be and still belong
    /// to that SYN's flow, in timestamp ticks.
    pub fn new(ttl: i64) -> Self {
        Self {
            slots: (0..PORTS).map(|_| Slot::default()).collect(),
            sequence: AtomicU32::new(1),
            ttl,
        }
    }

    pub fn ttl(&self) -> i64 {
        self.ttl
    }

    fn slot(&self, port: u16) -> &Slot {
        &self.slots[usize::from(port)]
    }

    fn next_tag(&self) -> u32 {
        self.sequence.fetch_add(1, Relaxed)
    }

    pub fn load(&self, port: u16) -> SlotView {
        let slot = self.slot(port);
        SlotView {
            word: Word(slot.word.load(Acquire)),
            connect_ts: slot.connect_ts.load(Relaxed),
            syn_ts: slot.syn_ts.load(Relaxed),
        }
    }

    pub fn state(&self, port: u16) -> SlotState {
        Word(self.slot(port).word.load(Acquire)).state()
    }

    /// Original destination port of a proxied flow.
    pub fn proxied_remote_port(&self, port: u16) -> Option<u16> {
        let slot = self.slot(port);
        (Word(slot.word.load(Acquire)).state() == SlotState::Proxied)
            .then(|| slot.remote_port.load(Relaxed) as u16)
    }

    // ---- network workers -------------------------------------------------

    pub fn note_syn(&self, port: u16, seq: u32) {
        self.slot(port).syn_seq.store(seq, Relaxed);
    }

    /// A SYN repeating the ISN of the last one on this port is the same
    /// connection retransmitting. Windows randomizes the ISN per connection.
    pub fn is_retransmit(&self, port: u16, seq: u32) -> bool {
        self.slot(port).syn_seq.load(Relaxed) == seq
    }

    pub fn try_park(&self, port: u16, expected: Word, generation: u32, index: u32, syn_ts: i64) -> bool {
        let slot = self.slot(port);
        slot.syn_ts.store(syn_ts, Relaxed);
        let pending = Word::new(SlotState::Pending, generation, index);
        slot.word
            .compare_exchange(expected.0, pending.0, AcqRel, Acquire)
            .is_ok()
    }

    /// Marks the flow whose SYN (sent at `syn_ts`) went out undecided.
    pub fn pin_abandoned(&self, port: u16, expected: Word, syn_ts: i64) -> bool {
        let slot = self.slot(port);
        slot.syn_ts.store(syn_ts, Relaxed);
        let abandoned = Word::new(SlotState::Abandoned, self.next_tag(), NO_INDEX);
        slot.word
            .compare_exchange(expected.0, abandoned.0, AcqRel, Acquire)
            .is_ok()
    }

    // ---- socket-layer thread -----------------------------------------------

    /// Re-injecting a parked SYN makes the socket layer report a second
    /// CONNECT for the same flow. It carries the same remote endpoint and
    /// arrives within the TTL of the decision.
    pub fn is_echo(&self, port: u16, connect_ts: i64, remote_ip: Ipv4Addr, remote_port: u16) -> bool {
        let slot = self.slot(port);
        let state = Word(slot.word.load(Acquire)).state();
        matches!(state, SlotState::Proxied | SlotState::Direct)
            && connect_ts - slot.connect_ts.load(Relaxed) <= self.ttl
            && slot.remote_ip.load(Relaxed) == u32::from(remote_ip)
            && slot.remote_port.load(Relaxed) == u32::from(remote_port)
    }

    /// Records the decision for the flow whose CONNECT happened at `connect_ts`.
    pub fn publish(
        &self,
        port: u16,
        decision: Decision,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        connect_ts: i64,
    ) -> Publish {
        let slot = self.slot(port);
        let (state, group) = match decision {
            Decision::Proxied { group } => (SlotState::Proxied, group),
            Decision::Direct => (SlotState::Direct, 0),
        };
        loop {
            let current = Word(slot.word.load(Acquire));
            // A CONNECT always precedes its SYN: older than the released SYN
            // means this decision is for the flow that already went direct.
            if current.state() == SlotState::Abandoned && connect_ts < slot.syn_ts.load(Relaxed) {
                return Publish::LateRejected;
            }
            slot.connect_ts.store(connect_ts, Relaxed);
            slot.remote_ip.store(u32::from(remote_ip), Relaxed);
            slot.remote_port.store(u32::from(remote_port), Relaxed);
            slot.group.store(group, Relaxed);
            let decided = Word::new(state, self.next_tag(), NO_INDEX);
            if slot
                .word
                .compare_exchange(current.0, decided.0, AcqRel, Acquire)
                .is_ok()
            {
                return match current.state() {
                    SlotState::Pending => Publish::Released(current),
                    _ => Publish::Stored,
                };
            }
        }
    }

    /// Socket CLOSE on `port`. Returns the pending word if the flow's SYN was
    /// still parked; its pool slot must be freed.
    ///
    /// CLOSE is reported at `closesocket()`, before the connection is done
    /// on the wire, so proxied slots are left to the relay.
    pub fn on_close(&self, port: u16, close_ts: i64) -> Option<Word> {
        let slot = self.slot(port);
        loop {
            let current = Word(slot.word.load(Acquire));
            let flow_ts = match current.state() {
                SlotState::Empty | SlotState::Proxied => return None,
                SlotState::Direct => slot.connect_ts.load(Relaxed),
                SlotState::Pending | SlotState::Abandoned => slot.syn_ts.load(Relaxed),
            };
            if flow_ts > close_ts {
                // The CLOSE of an earlier flow on this port.
                return None;
            }
            if slot
                .word
                .compare_exchange(current.0, Word::EMPTY.0, AcqRel, Acquire)
                .is_ok()
            {
                return (current.state() == SlotState::Pending).then_some(current);
            }
        }
    }

    // ---- acceptor and relays -------------------------------------------------

    pub fn take(&self, port: u16) -> Option<Taken> {
        let slot = self.slot(port);
        let word = Word(slot.word.load(Acquire));
        (word.state() == SlotState::Proxied).then(|| Taken {
            word,
            remote_ip: Ipv4Addr::from(slot.remote_ip.load(Relaxed)),
            remote_port: slot.remote_port.load(Relaxed) as u16,
            group: slot.group.load(Relaxed),
        })
    }

    /// Clears the slot if it still holds `word`.
    pub fn clear_if(&self, port: u16, word: Word) -> bool {
        self.slot(port)
            .word
            .compare_exchange(word.0, Word::EMPTY.0, AcqRel, Acquire)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: i64 = 100;
    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const PROXY: Decision = Decision::Proxied { group: 7 };

    #[test]
    fn word_packing() {
        let w = Word::new(SlotState::Pending, 0x0123_4567, 42);
        assert_eq!(w.state(), SlotState::Pending);
        assert_eq!(w.generation(), 0x23_4567);
        assert_eq!(w.index(), 42);
        assert_eq!(Word::EMPTY.state(), SlotState::Empty);
    }

    #[test]
    fn publish_on_empty_is_stored_and_taken() {
        let t = PortTracker::new(TTL);
        assert_eq!(t.publish(5000, PROXY, IP, 443, 10), Publish::Stored);
        let taken = t.take(5000).unwrap();
        assert_eq!((taken.remote_ip, taken.remote_port, taken.group), (IP, 443, 7));
        assert_eq!(t.proxied_remote_port(5000), Some(443));
        assert_eq!(t.publish(5001, Decision::Direct, IP, 443, 10), Publish::Stored);
        assert_eq!(t.take(5001), None);
    }

    #[test]
    fn publish_on_pending_hands_over_the_parked_slot() {
        let t = PortTracker::new(TTL);
        assert!(t.try_park(5000, Word::EMPTY, 3, 9, 20));
        let Publish::Released(word) = t.publish(5000, PROXY, IP, 443, 10) else {
            panic!("expected the parked SYN to be released");
        };
        assert_eq!((word.generation(), word.index()), (3, 9));
        assert_eq!(t.state(5000), SlotState::Proxied);
    }

    #[test]
    fn park_fails_when_a_decision_landed_first() {
        let t = PortTracker::new(TTL);
        let seen = t.load(5000).word;
        t.publish(5000, PROXY, IP, 443, 10);
        assert!(!t.try_park(5000, seen, 1, 1, 20));
    }

    #[test]
    fn late_decision_for_an_abandoned_flow_is_rejected() {
        let t = PortTracker::new(TTL);
        assert!(t.try_park(5000, Word::EMPTY, 1, 1, 20));
        let pending = t.load(5000).word;
        assert!(t.pin_abandoned(5000, pending, 20));
        assert_eq!(t.publish(5000, PROXY, IP, 443, 10), Publish::LateRejected);
        // A new flow on the same port connects after the abandoned SYN.
        assert_eq!(t.publish(5000, PROXY, IP, 443, 30), Publish::Stored);
    }

    #[test]
    fn echo_connect_is_recognized() {
        let t = PortTracker::new(TTL);
        t.publish(5000, PROXY, IP, 443, 10);
        assert!(t.is_echo(5000, 50, IP, 443));
        assert!(!t.is_echo(5000, 50, IP, 80));
        assert!(!t.is_echo(5000, 10 + TTL + 1, IP, 443));
    }

    #[test]
    fn close_clears_direct_and_pending_but_not_proxied() {
        let t = PortTracker::new(TTL);
        t.publish(1, Decision::Direct, IP, 443, 10);
        assert_eq!(t.on_close(1, 5), None, "close of an earlier flow");
        assert_eq!(t.state(1), SlotState::Direct);
        assert_eq!(t.on_close(1, 50), None);
        assert_eq!(t.state(1), SlotState::Empty);

        t.publish(2, PROXY, IP, 443, 10);
        assert_eq!(t.on_close(2, 50), None);
        assert_eq!(t.state(2), SlotState::Proxied);

        assert!(t.try_park(3, Word::EMPTY, 4, 8, 20));
        assert_eq!(t.on_close(3, 10), None, "close of a flow before the parked SYN");
        let word = t.on_close(3, 30).unwrap();
        assert_eq!((word.generation(), word.index()), (4, 8));
        assert_eq!(t.state(3), SlotState::Empty);
    }

    #[test]
    fn relay_clears_only_its_own_flow() {
        let t = PortTracker::new(TTL);
        t.publish(5000, PROXY, IP, 443, 10);
        let first = t.take(5000).unwrap().word;
        // The port is reused and proxied again before the first relay ends.
        t.publish(5000, PROXY, IP, 443, 500);
        assert!(!t.clear_if(5000, first));
        assert_eq!(t.state(5000), SlotState::Proxied);
        let second = t.take(5000).unwrap().word;
        assert!(t.clear_if(5000, second));
        assert_eq!(t.state(5000), SlotState::Empty);
    }

    #[test]
    fn retransmit_detection_by_isn() {
        let t = PortTracker::new(TTL);
        t.note_syn(5000, 111);
        assert!(t.is_retransmit(5000, 111));
        assert!(!t.is_retransmit(5000, 222));
    }
}
