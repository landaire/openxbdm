//! NT status codes carried in the SMB 2 header (MS-ERREF 2.3).

/// A status the server produces or distinguishes, or another 32-bit NT
/// status code a backend returned.
macro_rules! statuses {
    ($($(#[$doc:meta])* $name:ident = $value:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum NtStatus {
            $($(#[$doc])* $name,)*
            /// A code without a variant of its own.
            Other(OtherStatus),
        }

        impl NtStatus {
            /// The status of a raw code; codes with a variant always map to
            /// it.
            pub const fn from_raw(raw: u32) -> Self {
                match raw {
                    $($value => Self::$name,)*
                    _ => Self::Other(OtherStatus(raw)),
                }
            }

            /// The 32-bit code on the wire.
            pub const fn raw(self) -> u32 {
                match self {
                    $(Self::$name => $value,)*
                    Self::Other(other) => other.0,
                }
            }
        }
    };
}

statuses! {
    Success = 0x0000_0000,
    Pending = 0x0000_0103,
    NotifyCleanup = 0x0000_010b,
    NotifyEnumDir = 0x0000_010c,
    BufferOverflow = 0x8000_0005,
    NoMoreFiles = 0x8000_0006,
    Unsuccessful = 0xc000_0001,
    NotImplemented = 0xc000_0002,
    InvalidInfoClass = 0xc000_0003,
    InfoLengthMismatch = 0xc000_0004,
    InvalidHandle = 0xc000_0008,
    InvalidParameter = 0xc000_000d,
    NoSuchFile = 0xc000_000f,
    InvalidDeviceRequest = 0xc000_0010,
    EndOfFile = 0xc000_0011,
    NoMediaInDevice = 0xc000_0013,
    MoreProcessingRequired = 0xc000_0016,
    NoMemory = 0xc000_0017,
    AccessDenied = 0xc000_0022,
    BufferTooSmall = 0xc000_0023,
    ObjectNameInvalid = 0xc000_0033,
    ObjectNameNotFound = 0xc000_0034,
    ObjectNameCollision = 0xc000_0035,
    ObjectPathInvalid = 0xc000_0039,
    ObjectPathNotFound = 0xc000_003a,
    ObjectPathSyntaxBad = 0xc000_003b,
    SharingViolation = 0xc000_0043,
    EasNotSupported = 0xc000_004f,
    FileLockConflict = 0xc000_0054,
    LockNotGranted = 0xc000_0055,
    DeletePending = 0xc000_0056,
    PrivilegeNotHeld = 0xc000_0061,
    LogonFailure = 0xc000_006d,
    NoneMapped = 0xc000_0073,
    RangeNotLocked = 0xc000_007e,
    DiskFull = 0xc000_007f,
    InsufficientResources = 0xc000_009a,
    BadImpersonationLevel = 0xc000_00a5,
    PipeBusy = 0xc000_00ae,
    FileIsADirectory = 0xc000_00ba,
    NotSupported = 0xc000_00bb,
    NetworkNameDeleted = 0xc000_00c9,
    BadNetworkName = 0xc000_00cc,
    RequestNotAccepted = 0xc000_00d0,
    NotSameDevice = 0xc000_00d4,
    FileRenamed = 0xc000_00d5,
    PipeEmpty = 0xc000_00d9,
    InternalError = 0xc000_00e5,
    DirectoryNotEmpty = 0xc000_0101,
    NotADirectory = 0xc000_0103,
    Cancelled = 0xc000_0120,
    CannotDelete = 0xc000_0121,
    FileClosed = 0xc000_0128,
    PipeBroken = 0xc000_014b,
    FsDriverRequired = 0xc000_019c,
    InvalidLockRange = 0xc000_01a1,
    UserSessionDeleted = 0xc000_0203,
    NotFound = 0xc000_0225,
    NotAReparsePoint = 0xc000_0275,
    NetworkSessionExpired = 0xc000_035c,
    FileNotAvailable = 0xc000_0467,
    NoPreauthIntegrityHashOverlap = 0xc05d_0000,
}

/// A status code that [`NtStatus`] has no variant for. Only
/// [`NtStatus::from_raw`] makes one, so equal codes compare equal.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OtherStatus(u32);

impl OtherStatus {
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl core::fmt::Debug for OtherStatus {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:#010x}", self.0)
    }
}

impl NtStatus {
    /// Severity is error (the two high bits are set).
    pub const fn is_error(self) -> bool {
        self.raw() >> 30 == 3
    }

    /// Severity is warning (high bits `10`).
    pub const fn is_warning(self) -> bool {
        self.raw() >> 30 == 2
    }
}

impl From<NtStatus> for u32 {
    fn from(status: NtStatus) -> Self {
        status.raw()
    }
}

impl From<u32> for NtStatus {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?} ({:#010x})", self, self.raw())
    }
}

#[cfg(test)]
mod tests {
    use super::NtStatus;

    #[test]
    fn raw_codes_round_trip_through_their_variants() {
        assert_eq!(
            NtStatus::from_raw(0xc000_0034),
            NtStatus::ObjectNameNotFound
        );
        assert_eq!(NtStatus::ObjectNameNotFound.raw(), 0xc000_0034);
        let other = NtStatus::from_raw(0xc000_0185);
        assert!(matches!(other, NtStatus::Other(_)));
        assert_eq!(other, NtStatus::from_raw(0xc000_0185));
        assert_eq!(other.raw(), 0xc000_0185);
        assert!(other.is_error());
        assert!(NtStatus::BufferOverflow.is_warning());
        assert!(!NtStatus::NotifyEnumDir.is_error());
    }
}
