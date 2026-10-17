//! Sans-io NAP discovery state machine.
//!
//! Owns no socket and no clock. The caller drives it by:
//!
//! - asking [`Discovery::poll`] what to do next, given the current time
//! - performing the requested action (send a UDP datagram, wait for the
//!   next event, or take the final result)
//! - handing inbound datagrams back via [`Discovery::handle_inbound`]
//!
//! Because the engine has no I/O, it works identically under tokio,
//! `std::net::UdpSocket`, embedded transports, and WASM hosts that
//! expose UDP through a custom interface. The thin tokio runner in
//! [`super::runner`] is a ~30-line driver around this state machine.

use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use crate::discovery::error::NapError;
use crate::discovery::wire::DiscoveredConsole;
use crate::discovery::wire::NAP_PORT;
use crate::discovery::wire::NapRequest;
use crate::discovery::wire::encode_request;
use crate::discovery::wire::parse_response;

/// Tunables for a single discovery run. The runner picks defaults
/// suitable for either subnet broadcast or unicast resolve via the
/// constructor methods; tweak the fields directly when neither default
/// fits.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Where the request packets are sent. `255.255.255.255:730` for a
    /// subnet broadcast; a specific console's `IP:730` for a unicast
    /// probe.
    pub destination: SocketAddr,
    /// Total time the engine collects replies for. The first
    /// [`DiscoveryAction::Done`] fires once `now` reaches
    /// `start + listen_for`, returning whatever has accumulated so far.
    pub listen_for: Duration,

    /// Number of *additional* sends after the initial one. `0` sends
    /// the request once; `3` sends it four times total. XBDM
    /// occasionally drops a UDP packet on a busy kit, so a couple of
    /// retransmits dramatically improves discovery reliability.
    pub retransmits: u32,
    /// Spacing between consecutive sends. The initial send fires at
    /// `start`, and each retransmit follows `retransmit_interval` after
    /// the previous one.
    pub retransmit_interval: Duration,

    /// Whether the caller plans to set `SO_BROADCAST` before sending.
    /// The state machine itself doesn't touch the socket -- this flag
    /// is carried so the I/O wrapper can configure the socket
    /// uniformly. Required for `255.255.255.255` destinations.
    pub broadcast: bool,
}

impl DiscoveryConfig {
    /// Subnet-wide identify defaults: broadcast to `255.255.255.255:730`,
    /// listen for 1.5 s, 3 retransmits at 400 ms intervals.
    pub fn broadcast() -> Self {
        Self {
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), NAP_PORT),
            listen_for: Duration::from_millis(1500),
            retransmits: 3,
            retransmit_interval: Duration::from_millis(400),
            broadcast: true,
        }
    }

    /// Unicast resolve defaults: a single packet to a specific address,
    /// 500 ms listen window, no retransmit.
    pub fn unicast(target: SocketAddr) -> Self {
        Self {
            destination: target,
            listen_for: Duration::from_millis(500),
            retransmits: 0,
            retransmit_interval: Duration::from_millis(0),
            broadcast: false,
        }
    }
}

/// What the caller should do next. Returned by [`Discovery::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryAction {
    /// Send `payload` to `dest`. The caller is responsible for opening
    /// the socket, setting `SO_BROADCAST` when [`DiscoveryConfig::broadcast`]
    /// is true, and propagating any send errors however it likes
    /// (typically: log + continue, since UDP sends rarely fail).
    SendDatagram { dest: SocketAddr, payload: Vec<u8> },
    /// No outbound work is pending; wait for inbound bytes or for `until`
    /// (whichever comes first), then call [`Discovery::poll`] again.
    /// `until` is monotonic-clock-free -- it's whatever `Instant` value
    /// the caller passed in at construction time, advanced by the
    /// machine's own scheduling.
    Wait { until: Instant },
    /// Discovery finished (deadline hit, or the lookup-by-name filter
    /// matched). Carries the de-duplicated list of consoles seen.
    Done(Vec<DiscoveredConsole>),
}

/// Sans-io NAP discovery state machine. See module docs for the I/O
/// loop pattern. The machine never panics on duplicate inbound bytes,
/// malformed packets, or out-of-order calls -- the worst it does is
/// return `Done` early.
#[derive(Debug)]
pub struct Discovery {
    /// Cached encoded request packet -- the same bytes go out for every
    /// send (initial + retransmits).
    encoded_request: Vec<u8>,
    /// Where each send should go.
    destination: SocketAddr,

    /// Wall-clock instant after which `poll` returns `Done` with
    /// whatever has accumulated.
    deadline: Instant,
    /// When the next send should fire, or `None` once all sends have
    /// been issued.
    next_send_at: Option<Instant>,
    /// Sends remaining (including the upcoming `next_send_at`).
    sends_left: u32,
    /// Spacing applied between consecutive sends.
    retransmit_interval: Duration,

    /// Source addresses we've already processed -- the first reply per
    /// address wins, including for replies the filter would have
    /// rejected (saves redoing the parse on retransmit echoes).
    seen: HashSet<SocketAddr>,
    /// Replies the filter accepted, in arrival order.
    discovered: Vec<DiscoveredConsole>,

    /// Acceptance policy. Drives both per-reply keep-or-drop and the
    /// "stop early on first match" behavior used by `find_by_name`.
    filter: DiscoveryFilter,
    /// Latched once `find_by_name` has its match -- subsequent `poll`
    /// returns `Done` immediately even if the deadline hasn't fired.
    completed: bool,
}

impl Discovery {
    /// Identify every console on the segment. Sends a `WhatIsYourName`
    /// (`0x03`) packet, then collects replies until the deadline.
    pub fn broadcast(config: DiscoveryConfig, start: Instant) -> Self {
        let request = NapRequest::what_is_your_name();

        // `what_is_your_name` carries an empty name, so encoding cannot
        // fail.
        Self::new(request, config, DiscoveryFilter::All, start).expect("broadcast request encodes")
    }

    /// Resolve a specific name to its `DiscoveredConsole`. Stops on the
    /// first matching reply; returns whatever accumulated by the
    /// deadline if no match arrives.
    ///
    /// Returns [`NapError`] when the supplied name is too long or
    /// contains a control character that XBDM's name handler rejects.
    pub fn lookup(
        name: impl Into<String>,
        config: DiscoveryConfig,
        start: Instant,
    ) -> Result<Self, NapError> {
        let name = name.into();
        let request = NapRequest::lookup(name.clone());

        Self::new(request, config, DiscoveryFilter::StopOnName(name), start)
    }

    fn new(
        request: NapRequest,
        config: DiscoveryConfig,
        filter: DiscoveryFilter,
        start: Instant,
    ) -> Result<Self, NapError> {
        let encoded_request = encode_request(&request)?;

        Ok(Self {
            encoded_request,
            destination: config.destination,
            deadline: start + config.listen_for,
            // The initial send always fires at `start`.
            next_send_at: Some(start),
            sends_left: config.retransmits.saturating_add(1),
            retransmit_interval: config.retransmit_interval,
            seen: HashSet::new(),
            discovered: Vec::new(),
            filter,
            completed: false,
        })
    }

    /// Decide what the I/O loop should do next given the current time.
    /// Idempotent within a single instant -- calling `poll` repeatedly
    /// with the same `now` (no inbound bytes between calls) returns the
    /// same `Wait { until }` until the timer fires or
    /// [`Self::handle_inbound`] is called.
    pub fn poll(&mut self, now: Instant) -> DiscoveryAction {
        if self.completed || now >= self.deadline {
            return DiscoveryAction::Done(std::mem::take(&mut self.discovered));
        }

        // Send branch fires first so a tied `now == next_send_at` time
        // value doesn't accidentally schedule a Wait that's already
        // past.
        if let Some(send_at) = self.next_send_at
            && send_at <= now
        {
            self.sends_left = self.sends_left.saturating_sub(1);
            self.next_send_at = if self.sends_left > 0 {
                Some(now + self.retransmit_interval)
            } else {
                None
            };
            return DiscoveryAction::SendDatagram {
                dest: self.destination,
                payload: self.encoded_request.clone(),
            };
        }

        let until = match self.next_send_at {
            Some(send_at) => self.deadline.min(send_at),
            None => self.deadline,
        };

        DiscoveryAction::Wait { until }
    }

    /// Hand a datagram received from `src` to the engine. Malformed
    /// packets and duplicate sources are silently ignored. The next
    /// [`Self::poll`] call will reflect any state change (e.g. an
    /// early `Done` for a successful `find_by_name`).
    pub fn handle_inbound(&mut self, src: SocketAddr, payload: &[u8]) {
        // Dedup *before* parsing so retransmit echoes from the same
        // console don't pay the parse cost twice.
        if !self.seen.insert(src) {
            return;
        }

        let Ok(reply) = parse_response(payload) else {
            return;
        };

        let console = DiscoveredConsole {
            name: reply.name,
            addr: src,
        };
        let keep = match &self.filter {
            DiscoveryFilter::All => true,
            // The console answers a lookup that matches its name ignoring
            // ASCII case and replies with its own spelling.
            DiscoveryFilter::StopOnName(name) => console.name.eq_ignore_ascii_case(name),
        };
        if !keep {
            return;
        }

        // First match wins; any further poll gets the early Done.
        if matches!(&self.filter, DiscoveryFilter::StopOnName(_)) {
            self.completed = true;
        }

        self.discovered.push(console);
    }
}

/// Reply-acceptance policy. Constructed indirectly via
/// [`Discovery::broadcast`] / [`Discovery::lookup`].
#[derive(Debug, Clone)]
enum DiscoveryFilter {
    /// Keep every successful parse. Used by `discover_all`-style runs.
    All,
    /// Only keep replies whose name matches; complete on the first
    /// match. Used by `find_by_name`-style runs.
    StopOnName(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(retransmits: u32, interval_ms: u64, listen_ms: u64) -> DiscoveryConfig {
        let mut config = DiscoveryConfig::broadcast();
        config.retransmits = retransmits;
        config.retransmit_interval = Duration::from_millis(interval_ms);
        config.listen_for = Duration::from_millis(listen_ms);

        config
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn xbox_reply(name: &str) -> Vec<u8> {
        let mut packet = vec![0x02, name.len() as u8];
        packet.extend_from_slice(name.as_bytes());

        packet
    }

    #[test]
    fn first_poll_sends_initial_packet() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 100), start);
        let action = discovery.poll(start);
        match action {
            DiscoveryAction::SendDatagram { dest, payload } => {
                assert_eq!(dest, DiscoveryConfig::broadcast().destination);
                assert_eq!(payload, vec![0x03, 0x00]);
            }
            other => panic!("expected initial send, got {other:?}"),
        }
    }

    #[test]
    fn after_initial_send_with_no_retransmits_waits_until_deadline() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 1500), start);
        // Drain the initial send.
        discovery.poll(start);
        match discovery.poll(start) {
            DiscoveryAction::Wait { until } => {
                assert_eq!(until, start + Duration::from_millis(1500));
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn retransmit_fires_when_interval_elapses() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(2, 400, 1500), start);
        // Initial send.
        assert!(matches!(
            discovery.poll(start),
            DiscoveryAction::SendDatagram { .. }
        ));
        // Before interval elapses: Wait.
        match discovery.poll(start + Duration::from_millis(200)) {
            DiscoveryAction::Wait { until } => {
                assert_eq!(until, start + Duration::from_millis(400));
            }
            other => panic!("expected Wait, got {other:?}"),
        }
        // After interval: send #2.
        assert!(matches!(
            discovery.poll(start + Duration::from_millis(400)),
            DiscoveryAction::SendDatagram { .. }
        ));
        // Then send #3 at +800ms.
        assert!(matches!(
            discovery.poll(start + Duration::from_millis(800)),
            DiscoveryAction::SendDatagram { .. }
        ));
        // No more sends -- next event is the deadline.
        match discovery.poll(start + Duration::from_millis(900)) {
            DiscoveryAction::Wait { until } => {
                assert_eq!(until, start + Duration::from_millis(1500));
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn deadline_returns_done_with_collected_replies() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 500), start);
        discovery.poll(start);
        let src: SocketAddr = "192.168.1.50:730".parse().unwrap();
        discovery.handle_inbound(src, &xbox_reply("deanxbox"));
        match discovery.poll(start + Duration::from_millis(500)) {
            DiscoveryAction::Done(consoles) => {
                assert_eq!(consoles.len(), 1);
                assert_eq!(consoles[0].name, "deanxbox");
                assert_eq!(consoles[0].addr, src);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn dedup_drops_repeated_addr() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 500), start);
        discovery.poll(start);
        let src: SocketAddr = "10.0.0.5:730".parse().unwrap();
        discovery.handle_inbound(src, &xbox_reply("dean"));
        discovery.handle_inbound(src, &xbox_reply("dean")); // retransmit echo
        let DiscoveryAction::Done(consoles) = discovery.poll(start + Duration::from_millis(500))
        else {
            panic!("expected Done")
        };
        assert_eq!(consoles.len(), 1);
    }

    #[test]
    fn malformed_packets_are_silently_ignored() {
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 500), start);
        discovery.poll(start);
        let src: SocketAddr = "10.0.0.5:730".parse().unwrap();
        discovery.handle_inbound(src, &[]); // empty
        discovery.handle_inbound("10.0.0.6:730".parse().unwrap(), &[0x42, 0x00]); // bad opcode
        let DiscoveryAction::Done(consoles) = discovery.poll(start + Duration::from_millis(500))
        else {
            panic!("expected Done")
        };
        assert!(consoles.is_empty());
    }

    #[test]
    fn lookup_completes_on_first_match() {
        let start = t0();
        let mut discovery = Discovery::lookup("deanxbox", config_with(0, 0, 1500), start).unwrap();
        discovery.poll(start);
        discovery.handle_inbound("10.0.0.5:730".parse().unwrap(), &xbox_reply("otherxbox"));
        discovery.handle_inbound("10.0.0.6:730".parse().unwrap(), &xbox_reply("deanxbox"));
        // Even though deadline is 1500ms out, we should be Done now.
        let DiscoveryAction::Done(consoles) = discovery.poll(start) else {
            panic!("expected early Done")
        };
        assert_eq!(consoles.len(), 1);
        assert_eq!(consoles[0].name, "deanxbox");
    }

    #[test]
    fn lookup_filter_drops_non_matching_names() {
        let start = t0();
        let mut discovery = Discovery::lookup("deanxbox", config_with(0, 0, 500), start).unwrap();
        discovery.poll(start);
        discovery.handle_inbound("10.0.0.5:730".parse().unwrap(), &xbox_reply("notdean"));
        let DiscoveryAction::Done(consoles) = discovery.poll(start + Duration::from_millis(500))
        else {
            panic!("expected Done")
        };
        assert!(consoles.is_empty());
    }

    #[test]
    fn lookup_with_invalid_name_errors_at_construction() {
        let start = t0();
        let result = Discovery::lookup("bad\nname", DiscoveryConfig::broadcast(), start);
        assert!(matches!(result, Err(NapError::NameContainsControlChar)));
    }

    #[test]
    fn poll_after_done_returns_done_again_with_empty_results() {
        // Once `Done` has been taken, subsequent calls return Done with
        // an empty Vec rather than re-yielding the original results.
        // This matches std iterator-style "after exhaustion, fused"
        // semantics and prevents callers from accidentally double-
        // processing the same list.
        let start = t0();
        let mut discovery = Discovery::broadcast(config_with(0, 0, 100), start);
        discovery.poll(start);
        discovery.handle_inbound("10.0.0.5:730".parse().unwrap(), &xbox_reply("dean"));
        let first = discovery.poll(start + Duration::from_millis(100));
        let second = discovery.poll(start + Duration::from_millis(100));
        match (first, second) {
            (DiscoveryAction::Done(a), DiscoveryAction::Done(b)) => {
                assert_eq!(a.len(), 1);
                assert!(b.is_empty());
            }
            other => panic!("expected two Done, got {other:?}"),
        }
    }
}
