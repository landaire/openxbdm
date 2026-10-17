//! Host file I/O messages (packet type 0xb). The kernel asks the host to
//! open (0x801b3748), read (0x801b3950) and close (0x801b3a90) files and
//! waits until the host answers each request.
//!
//! Message header, 0x40 bytes, little-endian (0x801b55b8). Requests and
//! replies share the layout; the kernel converts the reply fields of the api
//! named in the reply header.
//!
//! | Offset | Size | Open | Read | Close |
//! |-------:|-----:|------|------|-------|
//! | 0x00 | 4 | 0x3430 | 0x3431 | 0x3433 |
//! | 0x04 | 4 | reply status | reply status | reply status |
//! | 0x08 | 4 / 8 | desired access | handle (u64) | handle (u64) |
//! | 0x0c | 4 | file attributes | | |
//! | 0x10 | 4 / 8 | share access | file offset (u64) | |
//! | 0x14 | 4 | create disposition | | |
//! | 0x18 | 4 | create options | length (u32) | |
//! | 0x20 | 8 | reply: handle | | |
//! | 0x28 | 8 | reply: file size | | |
//!
//! An open request carries the NUL-terminated UTF-16LE path as data. A read
//! reply carries the file bytes as data directly after the header; the
//! kernel takes the byte count from the payload length.

mod error;
mod host;

use core::num::NonZeroU64;

use crate::DecodeError;
use crate::NtStatus;
use crate::packet::MAX_PAYLOAD_LEN;
use crate::wire;

pub use self::error::HostFileError;
pub use self::host::HostFileSystem;
pub use self::host::respond;

pub const HEADER_LEN: usize = 0x40;

/// Largest read length the kernel requests (0x801b39cc). A read reply must
/// not carry more data than the request's length: the kernel copies at most
/// that many bytes but checksums the whole payload, so a longer reply is
/// answered with a resend request.
pub const MAX_READ_LEN: usize = MAX_PAYLOAD_LEN - HEADER_LEN;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct FileIoApi(pub u32);

impl FileIoApi {
    pub const OPEN: Self = Self(0x3430);
    pub const READ: Self = Self(0x3431);
    /// Converted like a read; no kernel sender exists.
    pub const API_3432: Self = Self(0x3432);
    pub const CLOSE: Self = Self(0x3433);
}

impl core::fmt::Debug for FileIoApi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::OPEN => write!(f, "Open"),
            Self::READ => write!(f, "Read"),
            Self::CLOSE => write!(f, "Close"),
            Self(raw) => write!(f, "FileIoApi({raw:#x})"),
        }
    }
}

/// Handle the host assigns to an open file. The kernel stores it in its
/// 16-entry table at 0x80222040, where zero marks a free entry.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct HostFileHandle(pub NonZeroU64);

/// NUL-terminated UTF-16LE path from an open request. The kernel builds it
/// by widening each byte of an ANSI string, prefixed with `host:`
/// (0x8009f430), for example `host:\Device\Flash\xam.xex`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct HostPath<'a> {
    /// Code units before the terminator, little-endian.
    bytes: &'a [u8],
}

impl<'a> HostPath<'a> {
    fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        let (units, rest) = data.as_chunks::<2>();
        if !rest.is_empty() {
            return Err(DecodeError::OddPathLength { length: data.len() });
        }

        let Some(end) = units.iter().position(|unit| *unit == [0, 0]) else {
            return Err(DecodeError::UnterminatedPath);
        };

        Ok(Self {
            bytes: &data[..end * 2],
        })
    }

    pub fn units(&self) -> impl Iterator<Item = u16> + 'a {
        self.bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
    }

    /// Characters of the path; unpaired surrogates are errors.
    pub fn chars(&self) -> impl Iterator<Item = Result<char, core::char::DecodeUtf16Error>> + 'a {
        char::decode_utf16(self.units())
    }
}

impl core::fmt::Debug for HostPath<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"{self}\"")
    }
}

impl core::fmt::Display for HostPath<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write;

        for character in self.chars() {
            f.write_char(character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }

        Ok(())
    }
}

/// Open parameters. The module loader passes FILE_GENERIC_READ (0x120089),
/// FILE_ATTRIBUTE_NORMAL (0x80), read and write sharing (3), FILE_OPEN (1)
/// and FILE_SYNCHRONOUS_IO_NONALERT (0x20).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct OpenRequest<'a> {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub path: HostPath<'a>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub handle: HostFileHandle,
    pub offset: u64,
    /// At most [`MAX_READ_LEN`]; never zero.
    pub length: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CloseRequest {
    pub handle: HostFileHandle,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileIoRequest<'a> {
    Open(OpenRequest<'a>),
    Read(ReadRequest),
    Close(CloseRequest),
    Other { api: FileIoApi, payload: &'a [u8] },
}

impl<'a> FileIoRequest<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        if payload.len() < HEADER_LEN {
            return Err(DecodeError::MessageHeaderLength {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }

        let api = FileIoApi(wire::le32(payload, 0)?);
        let request = match api {
            FileIoApi::OPEN => Self::Open(OpenRequest {
                desired_access: wire::le32(payload, 0x08)?,
                file_attributes: wire::le32(payload, 0x0c)?,
                share_access: wire::le32(payload, 0x10)?,
                create_disposition: wire::le32(payload, 0x14)?,
                create_options: wire::le32(payload, 0x18)?,
                path: HostPath::decode(&payload[HEADER_LEN..])?,
            }),
            FileIoApi::READ => Self::Read(ReadRequest {
                handle: decode_handle(payload, 0x08, api)?,
                offset: wire::le64(payload, 0x10)?,
                length: wire::le32(payload, 0x18)?,
            }),
            FileIoApi::CLOSE => Self::Close(CloseRequest {
                handle: decode_handle(payload, 0x08, api)?,
            }),
            api => Self::Other { api, payload },
        };

        Ok(request)
    }

    pub fn api(&self) -> FileIoApi {
        match self {
            Self::Open(_) => FileIoApi::OPEN,
            Self::Read(_) => FileIoApi::READ,
            Self::Close(_) => FileIoApi::CLOSE,
            Self::Other { api, .. } => *api,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct OpenedFile {
    pub handle: HostFileHandle,
    pub size: u64,
}

/// Reply header. A successful read reply is followed by its data.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileIoReply {
    Opened(OpenedFile),
    Read,
    Closed,
    /// An error status. An open failure makes the kernel open the file
    /// from its own devices; a read failure ends the read with the bytes
    /// received so far.
    Failed {
        api: FileIoApi,
        status: NtStatus,
    },
}

impl FileIoReply {
    /// Decodes a host reply. Returns the reply and its data.
    pub fn decode(payload: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        if payload.len() < HEADER_LEN {
            return Err(DecodeError::MessageHeaderLength {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }

        let api = FileIoApi(wire::le32(payload, 0)?);
        let status = NtStatus(wire::le32(payload, 4)?);

        let reply = if status.is_error() {
            Self::Failed { api, status }
        } else {
            match api {
                FileIoApi::OPEN => Self::Opened(OpenedFile {
                    handle: decode_handle(payload, 0x20, api)?,
                    size: wire::le64(payload, 0x28)?,
                }),
                FileIoApi::READ => Self::Read,
                FileIoApi::CLOSE => Self::Closed,
                api => return Err(DecodeError::UnknownFileIoApi { api }),
            }
        };

        Ok((reply, &payload[HEADER_LEN..]))
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        wire::put_le32(&mut header, 0, self.api().0);

        match self {
            Self::Opened(opened) => {
                wire::put_le64(&mut header, 0x20, opened.handle.0.get());
                wire::put_le64(&mut header, 0x28, opened.size);
            }
            Self::Failed { status, .. } => wire::put_le32(&mut header, 4, status.0),
            // These replies carry only the api word.
            Self::Read | Self::Closed => {}
        }

        header
    }

    pub fn api(&self) -> FileIoApi {
        match self {
            Self::Opened(_) => FileIoApi::OPEN,
            Self::Read => FileIoApi::READ,
            Self::Closed => FileIoApi::CLOSE,
            Self::Failed { api, .. } => *api,
        }
    }
}

fn decode_handle(
    payload: &[u8],
    offset: usize,
    api: FileIoApi,
) -> Result<HostFileHandle, DecodeError> {
    NonZeroU64::new(wire::le64(payload, offset)?)
        .map(HostFileHandle)
        .ok_or(DecodeError::ZeroFileHandle { api })
}
