//! State-change messages (packet type 7): the kernel stopped and waits
//! for manipulate requests.
//!
//! The message header is 0xf0 bytes. Fields below +0xc4 are little-endian
//! (converted by 0x801b57b0); the control report from +0xc4 on is copied
//! from the context in native big-endian order (0x801bb6d8).
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0x00 | 4 | new state: 0x3030 exception, 0x3031 load symbols |
//! | 0x04 | 2 | processor level (zero) |
//! | 0x06 | 2 | processor |
//! | 0x08 | 4 | number of processors |
//! | 0x10 | 8 | current thread, sign-extended |
//! | 0x18 | 8 | program counter, sign-extended |
//! | 0x20 | 0xa0 | state-specific fields |
//! | 0xc0 | 4 | instruction byte count (0x10) |
//! | 0xc4 | 16 | instruction bytes at the program counter |
//! | 0xd4 | 4 | CR, big-endian |
//! | 0xd8 | 8 | CTR, big-endian |
//! | 0xe0 | 4 | LR, big-endian |
//! | 0xe4 | 8 | GPR 3, big-endian |
//!
//! Load-symbols messages carry the image name as the data block.

use crate::DecodeError;
use crate::NtStatus;
use crate::manipulate::Processor;
use crate::wire;

pub const HEADER_LEN: usize = 0xf0;
pub const EXCEPTION_PARAMETER_COUNT: usize = 15;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NewState(pub u32);

impl NewState {
    pub const EXCEPTION: Self = Self(0x3030);
    pub const LOAD_SYMBOLS: Self = Self(0x3031);
}

impl core::fmt::Debug for NewState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::EXCEPTION => write!(f, "Exception"),
            Self::LOAD_SYMBOLS => write!(f, "LoadSymbols"),
            Self(raw) => write!(f, "NewState({raw:#x})"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: NtStatus,
    pub flags: u32,
    /// Address of a chained record.
    pub record: u64,
    pub address: u64,
    pub number_parameters: u32,
    pub information: [u64; EXCEPTION_PARAMETER_COUNT],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LoadSymbols {
    pub path_name_length: u32,
    pub base: u64,
    pub process_id: u64,
    pub checksum: u32,
    pub size_of_image: u32,
    pub unload: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StateBody {
    Exception {
        record: ExceptionRecord,
        first_chance: bool,
    },
    LoadSymbols(LoadSymbols),
    Other,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ControlReport {
    pub instruction_count: u32,
    pub instruction_stream: [u8; 16],
    pub cr: u32,
    pub ctr: u64,
    pub lr: u32,
    pub gpr3: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StateChange<'a> {
    pub new_state: NewState,
    pub processor_level: u16,
    pub processor: Processor,
    pub number_processors: u32,
    pub thread: u64,
    pub program_counter: u64,
    pub body: StateBody,
    pub control_report: ControlReport,
    /// Image name for load-symbols messages, without the NUL terminator.
    pub path: &'a [u8],
}

impl<'a> StateChange<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        if payload.len() < HEADER_LEN {
            return Err(DecodeError::MessageHeaderLength {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }

        let new_state = NewState(wire::le32(payload, 0)?);
        let data = &payload[HEADER_LEN..];

        let body = match new_state {
            NewState::EXCEPTION => {
                let mut information = [0u64; EXCEPTION_PARAMETER_COUNT];
                for (index, slot) in information.iter_mut().enumerate() {
                    *slot = wire::le64(payload, 0x40 + 8 * index)?;
                }

                StateBody::Exception {
                    record: ExceptionRecord {
                        code: NtStatus(wire::le32(payload, 0x20)?),
                        flags: wire::le32(payload, 0x24)?,
                        record: wire::le64(payload, 0x28)?,
                        address: wire::le64(payload, 0x30)?,
                        number_parameters: wire::le32(payload, 0x38)?,
                        information,
                    },
                    first_chance: wire::le32(payload, 0xb8)? != 0,
                }
            }
            NewState::LOAD_SYMBOLS => StateBody::LoadSymbols(LoadSymbols {
                path_name_length: wire::le32(payload, 0x20)?,
                base: wire::le64(payload, 0x28)?,
                process_id: wire::le64(payload, 0x30)?,
                checksum: wire::le32(payload, 0x38)?,
                size_of_image: wire::le32(payload, 0x3c)?,
                unload: payload[0x40] != 0,
            }),
            _ => StateBody::Other,
        };

        let path = match body {
            StateBody::LoadSymbols(symbols) => {
                let declared = symbols.path_name_length as usize;
                if declared != data.len() {
                    return Err(DecodeError::PathLengthMismatch {
                        state: new_state.0,
                        declared,
                        actual: data.len(),
                    });
                }

                match data.split_last() {
                    Some((0, name)) => name,
                    _ => data,
                }
            }
            _ => data,
        };

        let mut instruction_stream = [0u8; 16];
        instruction_stream.copy_from_slice(&payload[0xc4..0xd4]);

        Ok(Self {
            new_state,
            processor_level: wire::le16(payload, 4)?,
            processor: Processor(wire::le16(payload, 6)?),
            number_processors: wire::le32(payload, 8)?,
            thread: wire::le64(payload, 0x10)?,
            program_counter: wire::le64(payload, 0x18)?,
            body,
            control_report: ControlReport {
                instruction_count: wire::le32(payload, 0xc0)?,
                instruction_stream,
                cr: wire::be32(payload, 0xd4)?,
                ctr: wire::be64(payload, 0xd8)?,
                lr: wire::be32(payload, 0xe0)?,
                gpr3: wire::be64(payload, 0xe4)?,
            },
            path,
        })
    }

    pub fn exception(&self) -> Option<(&ExceptionRecord, bool)> {
        match &self.body {
            StateBody::Exception {
                record,
                first_chance,
            } => Some((record, *first_chance)),
            _ => None,
        }
    }
}
