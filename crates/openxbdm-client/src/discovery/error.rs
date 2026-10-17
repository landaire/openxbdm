use crate::discovery::wire::MAX_NAME_LEN;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NapError {
    #[error("name is longer than {MAX_NAME_LEN} bytes and cannot fit in a NAP packet")]
    NameTooLong,
    #[error("name contains NUL, CR, or LF; the console compares names only up to a NUL")]
    NameContainsControlChar,
    #[error("response packet was empty")]
    EmptyPacket,
    #[error("response opcode was {got:#04x}; expected {expected:#04x}")]
    UnexpectedOpcode { expected: u8, got: u8 },
    #[error("response packet was truncated (header says {expected} name bytes, got {got})")]
    Truncated { expected: usize, got: usize },
    #[error("response name contained non-UTF-8 bytes")]
    NonUtf8Name,
}
