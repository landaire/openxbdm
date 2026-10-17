//! Errors of the cipher modes.

/// The message exceeds the length the cipher mode can protect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageTooLong;
