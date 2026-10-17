//! Manipulate-state messages (packet type 2).
//!
//! The host sends a request; the kernel's command loop (0x801b7138)
//! answers each with a reply of the same api number. Message header,
//! little-endian (converted by 0x801b52c0 on receive and 0x801b59e8 on
//! send):
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0x00 | 4 | api number |
//! | 0x04 | 2 | processor level (zero) |
//! | 0x06 | 2 | processor |
//! | 0x08 | 4 | return status |
//! | 0x0c | 4 | unused |
//! | 0x10 | 0x28 | api-specific fields |
//!
//! Data follows the header in the same packet.

use core::num::NonZeroU32;

use crate::DecodeError;
use crate::NtStatus;
use crate::packet::MAX_PAYLOAD_LEN;
use crate::wire;

pub const HEADER_LEN: usize = 0x38;

/// Largest data block that fits one reply.
pub const MAX_TRANSFER_LEN: usize = MAX_PAYLOAD_LEN - HEADER_LEN;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ApiNumber(pub u32);

impl ApiNumber {
    pub const READ_VIRTUAL_MEMORY: Self = Self(0x3130);
    pub const WRITE_VIRTUAL_MEMORY: Self = Self(0x3131);
    /// Replies with the whole 0xa40-byte context, which exceeds the
    /// network packet limit; the reply overruns the transmit buffer and
    /// stops the kernel's network transport. Use [`Self::READ_CONTEXT_RANGE`].
    pub const GET_CONTEXT: Self = Self(0x3132);
    pub const SET_CONTEXT: Self = Self(0x3133);
    pub const WRITE_BREAKPOINT: Self = Self(0x3134);
    pub const RESTORE_BREAKPOINT: Self = Self(0x3135);
    pub const CONTINUE: Self = Self(0x3136);
    pub const READ_CONTROL_SPACE: Self = Self(0x3137);
    pub const WRITE_CONTROL_SPACE: Self = Self(0x3138);
    /// Always replies `STATUS_INVALID_PARAMETER` (0x801bb970).
    pub const REJECTED_3139: Self = Self(0x3139);
    /// Always replies `STATUS_INVALID_PARAMETER` (0x801bb970).
    pub const REJECTED_313A: Self = Self(0x313a);
    /// Restarts the console; no reply.
    pub const REBOOT: Self = Self(0x313b);
    /// Same as [`Self::CONTINUE`]; the control-set hook (0x801bb700) is empty.
    pub const CONTINUE_WITH_CONTROL: Self = Self(0x313c);
    pub const READ_PHYSICAL_MEMORY: Self = Self(0x313d);
    pub const WRITE_PHYSICAL_MEMORY: Self = Self(0x313e);
    pub const GET_VERSION: Self = Self(0x3146);
    pub const WRITE_BREAKPOINT_LIST: Self = Self(0x3147);
    pub const RESTORE_BREAKPOINT_LIST: Self = Self(0x3148);
    /// Bug check 0xe2; no reply.
    pub const BUG_CHECK: Self = Self(0x3149);
    pub const SWITCH_PROCESSOR: Self = Self(0x3150);
    /// Always replies `STATUS_UNSUCCESSFUL` (0x801b6940).
    pub const REJECTED_3151: Self = Self(0x3151);
    pub const SEARCH_MEMORY: Self = Self(0x3156);
    /// Calls 0x801b6e30 when 0x802196b8 is set. Purpose not analyzed.
    pub const API_3159: Self = Self(0x3159);
    pub const READ_CONTEXT_RANGE: Self = Self(0x315f);
    pub const WRITE_CONTEXT_RANGE: Self = Self(0x3160);

    fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::READ_VIRTUAL_MEMORY => "ReadVirtualMemory",
            Self::WRITE_VIRTUAL_MEMORY => "WriteVirtualMemory",
            Self::GET_CONTEXT => "GetContext",
            Self::SET_CONTEXT => "SetContext",
            Self::WRITE_BREAKPOINT => "WriteBreakpoint",
            Self::RESTORE_BREAKPOINT => "RestoreBreakpoint",
            Self::CONTINUE => "Continue",
            Self::READ_CONTROL_SPACE => "ReadControlSpace",
            Self::WRITE_CONTROL_SPACE => "WriteControlSpace",
            Self::REBOOT => "Reboot",
            Self::CONTINUE_WITH_CONTROL => "ContinueWithControl",
            Self::READ_PHYSICAL_MEMORY => "ReadPhysicalMemory",
            Self::WRITE_PHYSICAL_MEMORY => "WritePhysicalMemory",
            Self::GET_VERSION => "GetVersion",
            Self::WRITE_BREAKPOINT_LIST => "WriteBreakpointList",
            Self::RESTORE_BREAKPOINT_LIST => "RestoreBreakpointList",
            Self::BUG_CHECK => "BugCheck",
            Self::SWITCH_PROCESSOR => "SwitchProcessor",
            Self::SEARCH_MEMORY => "SearchMemory",
            Self::READ_CONTEXT_RANGE => "ReadContextRange",
            Self::WRITE_CONTEXT_RANGE => "WriteContextRange",
            _ => return None,
        })
    }
}

impl core::fmt::Debug for ApiNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "ApiNumber({:#x})", self.0),
        }
    }
}

/// Processor (hardware thread) index.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct Processor(pub u16);

/// Kernel breakpoint table index plus one (table at 0x802244d0, 32 slots).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointHandle(pub NonZeroU32);

/// How the kernel finishes the stop. The continue handler (0x801b7138)
/// tests only the sign bit.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ContinueDisposition {
    /// The exception is consumed; execution resumes at the context IAR.
    Handled,
    /// The exception is passed on to the normal exception dispatch.
    NotHandled,
}

impl ContinueDisposition {
    pub const fn status(self) -> NtStatus {
        match self {
            Self::Handled => NtStatus(0x0001_0001),
            Self::NotHandled => NtStatus(0x8001_0001),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Request {
    ReadVirtualMemory {
        address: u64,
        length: u32,
    },
    /// The data block carries the bytes.
    WriteVirtualMemory {
        address: u64,
        length: u32,
    },
    ReadPhysicalMemory {
        address: u64,
        length: u32,
    },
    WritePhysicalMemory {
        address: u64,
        length: u32,
    },
    ReadContextRange {
        offset: u32,
        length: u32,
    },
    /// The data block carries the bytes. The record is committed when the
    /// range ends at the end of the context.
    WriteContextRange {
        offset: u32,
        length: u32,
    },
    /// `address` must be 4-byte aligned.
    WriteBreakpoint {
        address: u64,
    },
    RestoreBreakpoint {
        handle: BreakpointHandle,
    },
    Continue {
        disposition: ContinueDisposition,
    },
    GetVersion,
    Reboot,
}

impl Request {
    pub const fn api(&self) -> ApiNumber {
        match self {
            Self::ReadVirtualMemory { .. } => ApiNumber::READ_VIRTUAL_MEMORY,
            Self::WriteVirtualMemory { .. } => ApiNumber::WRITE_VIRTUAL_MEMORY,
            Self::ReadPhysicalMemory { .. } => ApiNumber::READ_PHYSICAL_MEMORY,
            Self::WritePhysicalMemory { .. } => ApiNumber::WRITE_PHYSICAL_MEMORY,
            Self::ReadContextRange { .. } => ApiNumber::READ_CONTEXT_RANGE,
            Self::WriteContextRange { .. } => ApiNumber::WRITE_CONTEXT_RANGE,
            Self::WriteBreakpoint { .. } => ApiNumber::WRITE_BREAKPOINT,
            Self::RestoreBreakpoint { .. } => ApiNumber::RESTORE_BREAKPOINT,
            Self::Continue { .. } => ApiNumber::CONTINUE,
            Self::GetVersion => ApiNumber::GET_VERSION,
            Self::Reboot => ApiNumber::REBOOT,
        }
    }

    /// Whether the kernel answers this request with a reply.
    pub const fn expects_reply(&self) -> bool {
        !matches!(self, Self::Continue { .. } | Self::Reboot)
    }

    pub fn encode(&self, processor: Processor) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        wire::put_le32(&mut header, 0, self.api().0);
        wire::put_le16(&mut header, 6, processor.0);

        match *self {
            Self::ReadVirtualMemory { address, length }
            | Self::WriteVirtualMemory { address, length }
            | Self::ReadPhysicalMemory { address, length }
            | Self::WritePhysicalMemory { address, length } => {
                wire::put_le64(&mut header, 0x10, address);
                wire::put_le32(&mut header, 0x18, length);
            }
            Self::ReadContextRange { offset, length } => {
                wire::put_le32(&mut header, 0x10, offset);
                wire::put_le32(&mut header, 0x14, length);
            }
            Self::WriteContextRange { offset, length } => {
                wire::put_le32(&mut header, 0x14, offset);
                wire::put_le32(&mut header, 0x18, length);
            }
            Self::WriteBreakpoint { address } => wire::put_le64(&mut header, 0x10, address),
            Self::RestoreBreakpoint { handle } => wire::put_le32(&mut header, 0x10, handle.0.get()),
            Self::Continue { disposition } => {
                wire::put_le32(&mut header, 0x10, disposition.status().0)
            }
            // These requests carry no fields.
            Self::GetVersion | Self::Reboot => {}
        }

        header
    }
}

/// Reply to [`Request::GetVersion`] (0x801b6890).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Version {
    /// Constant 0x10c.
    pub major: u16,
    /// Kernel build number.
    pub minor: u16,
    /// Constant 6.
    pub protocol_version: u16,
    /// Constant 0xb.
    pub flags: u16,
    /// Constant 0x1f2.
    pub machine_type: u16,
    /// Byte at +0x1a, constant 0xc.
    pub max_packet_type: u8,
    pub kernel_base: u64,
    /// Kernel data address 0x801c07cc. Purpose not analyzed.
    pub unidentified_address_28: u64,
    /// Kernel data address 0x801cdb10. Purpose not analyzed.
    pub unidentified_address_30: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplyBody<'a> {
    ReadMemory {
        address: u64,
        requested: u32,
        actual: u32,
        data: &'a [u8],
    },
    WriteMemory {
        address: u64,
        actual: u32,
    },
    ReadContextRange {
        offset: u32,
        length: u32,
        actual: u32,
        data: &'a [u8],
    },
    WriteContextRange {
        offset: u32,
        length: u32,
        actual: u32,
    },
    WriteBreakpoint {
        address: u64,
        handle: Option<BreakpointHandle>,
    },
    RestoreBreakpoint {
        handle: u32,
    },
    Version(Version),
    /// An api without a typed decoding.
    Other {
        fields: &'a [u8],
        data: &'a [u8],
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Reply<'a> {
    pub api: ApiNumber,
    pub processor_level: u16,
    pub processor: Processor,
    pub status: NtStatus,
    pub body: ReplyBody<'a>,
}

impl<'a> Reply<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        if payload.len() < HEADER_LEN {
            return Err(DecodeError::MessageHeaderLength {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }

        let api = ApiNumber(wire::le32(payload, 0)?);
        let data = &payload[HEADER_LEN..];

        let body = match api {
            ApiNumber::READ_VIRTUAL_MEMORY | ApiNumber::READ_PHYSICAL_MEMORY => {
                ReplyBody::ReadMemory {
                    address: wire::le64(payload, 0x10)?,
                    requested: wire::le32(payload, 0x18)?,
                    actual: wire::le32(payload, 0x1c)?,
                    data,
                }
            }
            ApiNumber::WRITE_VIRTUAL_MEMORY | ApiNumber::WRITE_PHYSICAL_MEMORY => {
                ReplyBody::WriteMemory {
                    address: wire::le64(payload, 0x10)?,
                    actual: wire::le32(payload, 0x1c)?,
                }
            }
            ApiNumber::READ_CONTEXT_RANGE => ReplyBody::ReadContextRange {
                offset: wire::le32(payload, 0x10)?,
                length: wire::le32(payload, 0x14)?,
                actual: wire::le32(payload, 0x18)?,
                data,
            },
            ApiNumber::WRITE_CONTEXT_RANGE => ReplyBody::WriteContextRange {
                offset: wire::le32(payload, 0x14)?,
                length: wire::le32(payload, 0x18)?,
                actual: wire::le32(payload, 0x1c)?,
            },
            ApiNumber::WRITE_BREAKPOINT => ReplyBody::WriteBreakpoint {
                address: wire::le64(payload, 0x10)?,
                handle: NonZeroU32::new(wire::le32(payload, 0x18)?).map(BreakpointHandle),
            },
            ApiNumber::RESTORE_BREAKPOINT => ReplyBody::RestoreBreakpoint {
                handle: wire::le32(payload, 0x10)?,
            },
            ApiNumber::GET_VERSION => ReplyBody::Version(Version {
                major: wire::le16(payload, 0x10)?,
                minor: wire::le16(payload, 0x12)?,
                protocol_version: wire::le16(payload, 0x14)?,
                flags: wire::le16(payload, 0x16)?,
                machine_type: wire::le16(payload, 0x18)?,
                max_packet_type: payload[0x1a],
                kernel_base: wire::le64(payload, 0x20)?,
                unidentified_address_28: wire::le64(payload, 0x28)?,
                unidentified_address_30: wire::le64(payload, 0x30)?,
            }),
            _ => ReplyBody::Other {
                fields: &payload[0x10..HEADER_LEN],
                data,
            },
        };

        Ok(Self {
            api,
            processor_level: wire::le16(payload, 4)?,
            processor: Processor(wire::le16(payload, 6)?),
            status: NtStatus(wire::le32(payload, 8)?),
            body,
        })
    }
}
