//! Kernel status codes carried in replies and exception records.

/// A 32-bit kernel status value. Negative values (bit 31 set) are errors.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const SUCCESS: Self = Self(0);
    /// Generic failure; returned by most manipulate handlers.
    pub const UNSUCCESSFUL: Self = Self(0xc000_0001);
    pub const NOT_IMPLEMENTED: Self = Self(0xc000_0002);
    pub const INVALID_HANDLE: Self = Self(0xc000_0008);
    pub const INVALID_PARAMETER: Self = Self(0xc000_000d);
    pub const END_OF_FILE: Self = Self(0xc000_0011);
    pub const OBJECT_NAME_NOT_FOUND: Self = Self(0xc000_0034);
    /// Host file I/O without a debugger present (0x801b37ac).
    pub const DEBUGGER_INACTIVE: Self = Self(0xc000_0354);
    /// Exception code of a `tw`/`twi` trap with TO = 31.
    pub const BREAKPOINT: Self = Self(0x8000_0003);
    pub const SINGLE_STEP: Self = Self(0x8000_0004);
    pub const ACCESS_VIOLATION: Self = Self(0xc000_0005);
    /// Exception code of `twi 31, r0, 0x19`.
    pub const ASSERTION_FAILURE: Self = Self(0xc000_0420);

    pub const fn is_error(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }
}

impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtStatus({:#010x})", self.0)
    }
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}
