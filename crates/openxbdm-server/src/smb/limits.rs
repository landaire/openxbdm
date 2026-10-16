//! Time limits of connections, which keep the few connection slots
//! available.

use smb2_server::fs::FileTime;

/// A length of time in FILETIME units (100 nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TimeSpan(u64);

impl TimeSpan {
    const fn seconds(seconds: u64) -> Self {
        Self(seconds * 10_000_000)
    }

    /// Time from `earlier` to `later`; none when `later` is before it.
    const fn between(earlier: FileTime, later: FileTime) -> Self {
        Self(later.0.saturating_sub(earlier.0))
    }
}

/// A connection must complete a logon this long after it is accepted.
pub(crate) const LOGON_LIMIT: TimeSpan = TimeSpan::seconds(30);
/// A message or reply in progress may make no progress this long.
pub(crate) const STALL_LIMIT: TimeSpan = TimeSpan::seconds(30);
/// A connection without open files may send no request this long.
pub(crate) const IDLE_LIMIT: TimeSpan = TimeSpan::seconds(15 * 60);
/// When every slot holds a session, a connection that sent no request
/// this long makes room for a new one. The console cannot detect a peer
/// that vanished (XNet has no TCP keep-alive), so a vanished client
/// holding open files would otherwise keep its slot.
pub(crate) const RECLAIM_LIMIT: TimeSpan = TimeSpan::seconds(5 * 60);

/// Times of a connection's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Activity {
    pub(crate) accepted: FileTime,
    /// Last byte received or sent.
    pub(crate) progress: FileTime,
    /// Last complete request.
    pub(crate) request: FileTime,
}

/// What a connection holds when its limits are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Usage {
    /// A session completed its logon.
    pub(crate) session: bool,
    /// Files or pipes are open.
    pub(crate) opens: bool,
    /// A message is partly received or a reply partly sent.
    pub(crate) in_transfer: bool,
}

/// The limit a connection exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expiry {
    NoLogon,
    Stalled,
    Idle,
}

impl Activity {
    pub(crate) const fn new(now: FileTime) -> Self {
        Self {
            accepted: now,
            progress: now,
            request: now,
        }
    }

    /// The limit exceeded at `now`. Time before an event, as after the
    /// clock was set back, counts as none.
    pub(crate) fn expiry(&self, usage: Usage, now: FileTime) -> Option<Expiry> {
        let since = |time: FileTime| TimeSpan::between(time, now);
        if !usage.session && since(self.accepted) >= LOGON_LIMIT {
            Some(Expiry::NoLogon)
        } else if usage.in_transfer && since(self.progress) >= STALL_LIMIT {
            Some(Expiry::Stalled)
        } else if !usage.opens && since(self.request) >= IDLE_LIMIT {
            Some(Expiry::Idle)
        } else {
            None
        }
    }
}

/// The connection to close for a new one when every slot is in use: the
/// earliest accepted of those without a session, otherwise the one that
/// sent no request for the longest time if that is at least
/// [`RECLAIM_LIMIT`]. `connections` yields each slot's index, activity,
/// and whether it has a session.
pub(crate) fn eviction(
    connections: impl Iterator<Item = (usize, Activity, bool)> + Clone,
    now: FileTime,
) -> Option<usize> {
    let without_session = connections
        .clone()
        .filter(|&(_, _, session)| !session)
        .min_by_key(|&(_, activity, _)| activity.accepted)
        .map(|(index, _, _)| index);
    without_session.or_else(|| {
        connections
            .filter(|&(_, activity, _)| TimeSpan::between(activity.request, now) >= RECLAIM_LIMIT)
            .min_by_key(|&(_, activity, _)| activity.request)
            .map(|(index, _, _)| index)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: FileTime = FileTime(0x01db_0000_0000_0000);
    const SECOND: u64 = TimeSpan::seconds(1).0;
    const LOGON_LIMIT: u64 = super::LOGON_LIMIT.0;
    const STALL_LIMIT: u64 = super::STALL_LIMIT.0;
    const IDLE_LIMIT: u64 = super::IDLE_LIMIT.0;

    fn at(offset: u64) -> FileTime {
        FileTime(START.0 + offset)
    }

    const IDLE: Usage = Usage {
        session: true,
        opens: false,
        in_transfer: false,
    };

    #[test]
    fn connections_without_a_logon_expire() {
        let activity = Activity::new(START);
        let usage = Usage {
            session: false,
            ..IDLE
        };
        assert_eq!(activity.expiry(usage, at(LOGON_LIMIT - 1)), None);
        assert_eq!(
            activity.expiry(usage, at(LOGON_LIMIT)),
            Some(Expiry::NoLogon)
        );
        assert_eq!(activity.expiry(IDLE, at(LOGON_LIMIT)), None);
    }

    #[test]
    fn stalled_transfers_expire() {
        let mut activity = Activity::new(START);
        let usage = Usage {
            in_transfer: true,
            ..IDLE
        };
        activity.progress = at(SECOND);
        assert_eq!(activity.expiry(usage, at(STALL_LIMIT)), None);
        assert_eq!(
            activity.expiry(usage, at(SECOND + STALL_LIMIT)),
            Some(Expiry::Stalled)
        );
        assert_eq!(activity.expiry(IDLE, at(SECOND + STALL_LIMIT)), None);
    }

    #[test]
    fn idle_connections_expire_without_open_files() {
        let mut activity = Activity::new(START);
        activity.request = at(10 * SECOND);
        let end = at(10 * SECOND + IDLE_LIMIT);
        assert_eq!(activity.expiry(IDLE, FileTime(end.0 - 1)), None);
        assert_eq!(activity.expiry(IDLE, end), Some(Expiry::Idle));
        let open = Usage {
            opens: true,
            ..IDLE
        };
        assert_eq!(activity.expiry(open, end), None);
    }

    #[test]
    fn a_clock_set_back_expires_nothing() {
        let activity = Activity::new(START);
        let usage = Usage {
            session: false,
            opens: false,
            in_transfer: true,
        };
        assert_eq!(activity.expiry(usage, FileTime(0)), None);
    }

    #[test]
    fn eviction_takes_the_oldest_connection_without_a_session() {
        let connections = [
            (0, Activity::new(at(5)), false),
            (1, Activity::new(at(1)), true),
            (2, Activity::new(at(3)), false),
        ];
        assert_eq!(eviction(connections.into_iter(), at(10)), Some(2));
    }

    #[test]
    fn eviction_reclaims_the_longest_silent_session() {
        const RECLAIM_LIMIT: u64 = super::RECLAIM_LIMIT.0;
        let mut quiet = Activity::new(START);
        quiet.request = at(2 * SECOND);
        let mut busy = Activity::new(START);
        busy.request = at(4 * SECOND);
        let connections = [(0, busy, true), (1, quiet, true)];
        assert_eq!(
            eviction(connections.into_iter(), at(2 * SECOND + RECLAIM_LIMIT - 1)),
            None
        );
        assert_eq!(
            eviction(connections.into_iter(), at(4 * SECOND + RECLAIM_LIMIT)),
            Some(1)
        );
    }
}
