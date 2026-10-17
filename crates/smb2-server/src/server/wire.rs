//! Field access and constants of the SMB 2 message layouts (MS-SMB2 2.2).
//!
//! Callers check a body's length against its fixed part before reading or
//! writing fields, so the accessors index directly.

/// Bytes of the SMB 2 header.
pub const HEADER_SIZE: usize = 64;
pub const PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
pub const SMB1_PROTOCOL_ID: [u8; 4] = [0xff, b'S', b'M', b'B'];

/// Header field offsets.
pub mod header {
    pub const STRUCTURE_SIZE: usize = 4;
    pub const CREDIT_CHARGE: usize = 6;
    pub const STATUS: usize = 8;
    pub const COMMAND: usize = 12;
    pub const CREDITS: usize = 14;
    pub const FLAGS: usize = 16;
    pub const NEXT_COMMAND: usize = 20;
    pub const MESSAGE_ID: usize = 24;
    pub const ASYNC_ID: usize = 32;
    pub const TREE_ID: usize = 36;
    pub const SESSION_ID: usize = 40;
    pub const SIGNATURE: usize = 48;
}

/// Header flags (MS-SMB2 2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HeaderFlags(pub u32);

impl HeaderFlags {
    pub const SERVER_TO_REDIR: Self = Self(0x0000_0001);
    pub const ASYNC_COMMAND: Self = Self(0x0000_0002);
    pub const RELATED_OPERATIONS: Self = Self(0x0000_0004);
    pub const SIGNED: Self = Self(0x0000_0008);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Identifier of a request, granted by credits (MS-SMB2 3.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

/// Identifier of a request that completes later (MS-SMB2 3.3.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsyncId(pub u64);

impl AsyncId {
    /// The first identifier a connection assigns.
    pub const FIRST: Self = Self(1);

    /// The identifier assigned after this one, skipping 0.
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1).max(1))
    }
}

/// Credits a request consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreditCharge(pub u16);

/// Credits a request asks for or a reply grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Credits(pub u16);

/// A command code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Command(pub u16);

impl Command {
    pub const NEGOTIATE: Self = Self(0x00);
    pub const SESSION_SETUP: Self = Self(0x01);
    pub const LOGOFF: Self = Self(0x02);
    pub const TREE_CONNECT: Self = Self(0x03);
    pub const TREE_DISCONNECT: Self = Self(0x04);
    pub const CREATE: Self = Self(0x05);
    pub const CLOSE: Self = Self(0x06);
    pub const FLUSH: Self = Self(0x07);
    pub const READ: Self = Self(0x08);
    pub const WRITE: Self = Self(0x09);
    pub const LOCK: Self = Self(0x0a);
    pub const IOCTL: Self = Self(0x0b);
    pub const CANCEL: Self = Self(0x0c);
    pub const ECHO: Self = Self(0x0d);
    pub const QUERY_DIRECTORY: Self = Self(0x0e);
    pub const CHANGE_NOTIFY: Self = Self(0x0f);
    pub const QUERY_INFO: Self = Self(0x10);
    pub const SET_INFO: Self = Self(0x11);
}

/// A dialect revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dialect(pub u16);

impl Dialect {
    pub const SMB_2_0_2: Self = Self(0x0202);
    pub const SMB_2_1: Self = Self(0x0210);
    pub const SMB_3_0: Self = Self(0x0300);
    pub const SMB_3_0_2: Self = Self(0x0302);
    pub const SMB_3_1_1: Self = Self(0x0311);
    /// Answer to a multi-protocol negotiate offering `SMB 2.???`.
    pub const WILDCARD: Self = Self(0x02ff);
}

/// Server-assigned identifier of an open (MS-SMB2 2.2.14.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    /// In a related compound request, the open of the preceding request.
    pub const RELATED: Self = Self {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };

    /// The first identifier a connection assigns.
    pub const FIRST: Self = Self::from_value(1);

    /// Persistent and volatile parts are the same value; the server keeps
    /// no durable handles.
    const fn from_value(value: u64) -> Self {
        Self {
            persistent: value,
            volatile: value,
        }
    }

    /// The identifier assigned after this one, skipping 0 and
    /// [`Self::RELATED`].
    pub const fn next(self) -> Self {
        match self.volatile.wrapping_add(1) {
            u64::MAX | 0 => Self::FIRST,
            next => Self::from_value(next),
        }
    }

    pub fn read(bytes: &[u8], offset: usize) -> Self {
        Self {
            persistent: u64_at(bytes, offset),
            volatile: u64_at(bytes, offset + 8),
        }
    }

    pub fn write(self, bytes: &mut [u8], offset: usize) {
        put_u64(bytes, offset, self.persistent);
        put_u64(bytes, offset + 8, self.volatile);
    }
}

pub fn u8_at(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

pub fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);

    u32::from_le_bytes(value)
}

pub fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);

    u64::from_le_bytes(value)
}

pub fn put_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

pub fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// The `length` bytes at `offset` from the start of the message, where the
/// body begins [`HEADER_SIZE`] bytes in. `None` when the range leaves the
/// message or starts inside the fixed part of the body.
pub fn buffer(message: &[u8], fixed: usize, offset: usize, length: usize) -> Option<&[u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if offset < HEADER_SIZE + fixed {
        return None;
    }

    message.get(offset..offset.checked_add(length)?)
}

/// Round up to a multiple of 8.
pub const fn align8(value: usize) -> usize {
    (value + 7) & !7
}
