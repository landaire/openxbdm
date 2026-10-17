//! Connection privileges.

xbox360_sys::flags! {
    /// Privilege bits held by a connection and required by commands.
    pub struct Access(u32) {
        READ = 0x01,
        WRITE = 0x02,
        CONTROL = 0x04,
        CONFIG = 0x08,
        MANAGE = 0x10,
    }
}

impl Access {
    /// Held by unlocked connections and by settings-file lines. Includes
    /// every bit, also the bits that have no named constant.
    pub const UNRESTRICTED: Self = Self(u32::MAX);
}
