//! Message identifier window (MS-SMB2 3.3.1.1): the identifiers granted
//! by credits that the client has not used yet.

use crate::server::wire::Credits;
use crate::server::wire::MessageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditWindow {
    /// Lowest identifier that may still be unused.
    base: u64,
    /// One past the highest granted identifier.
    end: u64,
    /// Bit `n` set: identifier `base + n` is granted and unused.
    available: u128,
}

impl CreditWindow {
    /// The window of a new connection: identifier 0 for the first
    /// negotiate.
    pub const fn new() -> Self {
        Self {
            base: 0,
            end: 1,
            available: 1,
        }
    }

    /// Use identifier `id`; `false` when it is outside the window or
    /// already used.
    pub fn consume(&mut self, id: MessageId) -> bool {
        let id = id.0;
        if id < self.base || id >= self.end {
            return false;
        }

        let bit = 1u128 << (id - self.base);
        if self.available & bit == 0 {
            return false;
        }

        // Slide the window past the identifiers used at its start.
        self.available &= !bit;
        let shift = u64::from(self.available.trailing_zeros()).min(self.end - self.base);
        self.base += shift;
        self.available = self.available.checked_shr(shift as u32).unwrap_or(0);

        true
    }

    /// Grant up to `requested` new identifiers, at least one when the
    /// client holds none; returns the number granted.
    pub fn grant(&mut self, requested: Credits) -> Credits {
        /// Most identifiers granted and not yet used at any time.
        const WINDOW: u64 = 128;

        let requested = requested.0;
        let room = WINDOW - (self.end - self.base);
        let wanted = u64::from(requested.max(1));
        let granted = if self.available == 0 {
            wanted.min(room).max(1)
        } else {
            wanted.min(room)
        };

        for index in self.end - self.base..self.end - self.base + granted {
            self.available |= 1 << index;
        }
        self.end += granted;

        Credits(granted as u16)
    }

    /// Identifiers granted and unused.
    #[cfg(test)]
    pub fn outstanding(&self) -> u32 {
        self.available.count_ones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consume(window: &mut CreditWindow, id: u64) -> bool {
        window.consume(MessageId(id))
    }

    fn grant(window: &mut CreditWindow, requested: u16) -> u16 {
        window.grant(Credits(requested)).0
    }

    #[test]
    fn identifiers_are_used_once_in_any_order() {
        let mut window = CreditWindow::new();
        assert!(consume(&mut window, 0));
        assert!(!consume(&mut window, 0));
        assert_eq!(grant(&mut window, 3), 3);
        assert!(consume(&mut window, 3));
        assert!(consume(&mut window, 1));
        assert!(!consume(&mut window, 3));
        assert!(!consume(&mut window, 4));
        assert!(consume(&mut window, 2));
        assert_eq!(window.outstanding(), 0);
    }

    #[test]
    fn grants_stop_at_the_window_size() {
        let mut window = CreditWindow::new();
        assert_eq!(grant(&mut window, 1000), 127);
        assert_eq!(window.outstanding(), 128);
        assert_eq!(grant(&mut window, 10), 0);
        assert!(consume(&mut window, 5));
        assert_eq!(grant(&mut window, 10), 0);
        assert!(consume(&mut window, 0));
        assert_eq!(grant(&mut window, 10), 1);
    }

    #[test]
    fn a_client_without_credits_receives_one() {
        let mut window = CreditWindow::new();
        assert!(consume(&mut window, 0));
        assert_eq!(grant(&mut window, 0), 1);
        assert!(consume(&mut window, 1));
    }
}
