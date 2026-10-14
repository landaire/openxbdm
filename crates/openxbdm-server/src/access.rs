//! Connection privileges.

/// Privilege bits held by a connection and required by commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Access(u32);

impl Access {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(0x01);
    pub const WRITE: Self = Self(0x02);
    pub const CONTROL: Self = Self(0x04);
    pub const CONFIG: Self = Self(0x08);
    pub const MANAGE: Self = Self(0x10);
    /// Held by unlocked connections and by settings-file lines.
    pub const ALL: Self = Self(u32::MAX);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}
