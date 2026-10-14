//! Time representations used on the wire.
//!
//! XBDM reports the console clock as a Windows `FILETIME`: a 64-bit count of
//! 100-nanosecond ticks since 1601-01-01T00:00:00 UTC. We keep that raw
//! representation inside [`FileTime`] and expose conversions to the stdlib
//! `SystemTime` by default, plus a `jiff::Timestamp` behind the `jiff`
//! feature flag.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Windows `FILETIME`: 100-ns ticks since 1601-01-01T00:00:00 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTime(u64);

/// Number of 100-ns ticks between the Windows epoch (1601-01-01) and the
/// Unix epoch (1970-01-01). That span is 11644473600 seconds.
const WIN_EPOCH_TO_UNIX_100NS: u64 = 11_644_473_600 * 10_000_000;

impl FileTime {
    pub const fn from_raw(ticks: u64) -> Self {
        Self(ticks)
    }

    pub const fn from_halves(high: u32, low: u32) -> Self {
        Self(((high as u64) << 32) | (low as u64))
    }

    pub const fn as_raw(self) -> u64 {
        self.0
    }

    pub const fn high(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn low(self) -> u32 {
        self.0 as u32
    }

    /// Convert to a stdlib `SystemTime`. FILETIME values earlier than the
    /// Unix epoch saturate at `UNIX_EPOCH`.
    pub fn into_system_time(self) -> SystemTime {
        let Some(unix_100ns) = self.0.checked_sub(WIN_EPOCH_TO_UNIX_100NS) else {
            return UNIX_EPOCH;
        };
        let secs = unix_100ns / 10_000_000;
        let nanos = (unix_100ns % 10_000_000) * 100;
        UNIX_EPOCH + Duration::new(secs, nanos as u32)
    }

    #[cfg(feature = "jiff")]
    pub fn into_jiff_timestamp(self) -> Result<jiff::Timestamp, jiff::Error> {
        let unix_100ns = self.0.saturating_sub(WIN_EPOCH_TO_UNIX_100NS) as i64;
        let secs = unix_100ns / 10_000_000;
        let nanos = (unix_100ns % 10_000_000) * 100;
        jiff::Timestamp::new(secs, nanos as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_time_converts_to_unix_epoch() {
        let ft = FileTime::from_raw(WIN_EPOCH_TO_UNIX_100NS);
        assert_eq!(ft.into_system_time(), UNIX_EPOCH);
    }

    #[test]
    fn file_time_below_unix_epoch_saturates() {
        let ft = FileTime::from_raw(0);
        assert_eq!(ft.into_system_time(), UNIX_EPOCH);
    }

    #[test]
    fn file_time_round_trip() {
        let now = SystemTime::now();
        let since = now.duration_since(UNIX_EPOCH).unwrap();
        let ticks = WIN_EPOCH_TO_UNIX_100NS
            + since.as_secs() * 10_000_000
            + since.subsec_nanos() as u64 / 100;
        let ft = FileTime::from_raw(ticks);
        let round = ft.into_system_time();
        let drift =
            round.duration_since(UNIX_EPOCH).unwrap().as_nanos() as i128 - since.as_nanos() as i128;
        assert!(drift.abs() < 100);
    }
}
