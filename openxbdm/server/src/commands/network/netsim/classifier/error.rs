/// Why a program is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramError {
    /// Malformed or not allowed (0x82da0017).
    Invalid,
    /// The stored copy exceeds the item or node objects (0x82da001c).
    OutOfMemory,
}

/// Why a program cannot be serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// The output does not fit (0x8007007a).
    TooLarge,
    /// An item holds a string, which the item encoder rejects
    /// (0x80070545).
    Unencodable,
}
