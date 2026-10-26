//! One request being handled and the outcome a handler gives it.

use core::cell::Cell;

use crate::server::ServerConfig;
use crate::server::error::RequestError;
use crate::server::security;
use crate::server::tables::Session;
use crate::server::tables::SessionId;
use crate::server::tables::SessionSlot;
use crate::server::tables::TreeId;
use crate::server::tables::TreeSlot;
use crate::server::wire;
use crate::server::wire::AsyncId;
use crate::server::wire::Command;
use crate::server::wire::CreditCharge;
use crate::server::wire::Credits;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;
use crate::server::wire::HeaderFlags;
use crate::server::wire::MessageId;
use crate::server::wire::header;
use crate::status::NtStatus;

/// Bytes of an error reply body.
pub(super) const ERROR_BODY: usize = 9;

/// The parsed header of a request.
#[derive(Debug, Clone, Copy)]
pub(super) struct RequestHeader {
    pub(super) command: Command,
    pub(super) credit_charge: CreditCharge,
    pub(super) credit_request: Credits,
    pub(super) flags: HeaderFlags,
    pub(super) message_id: MessageId,
    pub(super) async_id: AsyncId,
    pub(super) tree_id: TreeId,
    pub(super) session_id: SessionId,
}

impl RequestHeader {
    pub(super) fn parse(message: &[u8]) -> Self {
        Self {
            command: Command(wire::u16_at(message, header::COMMAND)),
            credit_charge: CreditCharge(wire::u16_at(message, header::CREDIT_CHARGE)),
            credit_request: Credits(wire::u16_at(message, header::CREDITS)),
            flags: HeaderFlags(wire::u32_at(message, header::FLAGS)),
            message_id: MessageId(wire::u64_at(message, header::MESSAGE_ID)),
            async_id: AsyncId(wire::u64_at(message, header::ASYNC_ID)),
            tree_id: TreeId(wire::u32_at(message, header::TREE_ID)),
            session_id: SessionId(wire::u64_at(message, header::SESSION_ID)),
        }
    }

    pub(super) fn is_related(&self) -> bool {
        self.flags.contains(HeaderFlags::RELATED_OPERATIONS)
    }

    pub(super) fn is_signed(&self) -> bool {
        self.flags.contains(HeaderFlags::SIGNED)
    }

    pub(super) fn is_async(&self) -> bool {
        self.flags.contains(HeaderFlags::ASYNC_COMMAND)
    }
}

/// One request being handled.
pub(super) struct Exchange<'a> {
    pub(super) config: ServerConfig,
    /// The request: header and body.
    pub(super) message: &'a [u8],
    pub(super) header: RequestHeader,

    pub(super) session: Option<SessionSlot>,
    pub(super) tree: Option<TreeSlot>,
    /// In a related compound chain, the open of the preceding request.
    pub(super) related_file: Option<Result<FileId, RequestError>>,
    /// The open the request named, once found.
    pub(super) named_file: Cell<Option<FileId>>,

    /// The request is the last of its chain, so it may complete later.
    pub(super) last: bool,
    /// The request arrived encrypted.
    pub(super) encrypted: bool,
}

impl Exchange<'_> {
    pub(super) fn body(&self) -> &[u8] {
        &self.message[HEADER_SIZE..]
    }

    /// The body when it holds at least `fixed` bytes and declares
    /// `structure_size`.
    pub(super) fn fixed_body(&self, structure_size: u16, fixed: usize) -> Result<&[u8], Failure> {
        let body = self.body();
        if body.len() < fixed || wire::u16_at(body, 0) != structure_size {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        Ok(body)
    }
}

/// A status of a reply with a regular body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    Success,
    /// The output buffer held only part of the data.
    BufferOverflow,
    /// The authentication exchange continues.
    MoreProcessingRequired,
    /// The changes of a watched directory were not kept; the client lists
    /// it again.
    NotifyEnumDirectory,
}

impl From<Completion> for NtStatus {
    fn from(completion: Completion) -> Self {
        match completion {
            Completion::Success => NtStatus::Success,
            Completion::BufferOverflow => NtStatus::BufferOverflow,
            Completion::MoreProcessingRequired => NtStatus::MoreProcessingRequired,
            Completion::NotifyEnumDirectory => NtStatus::NotifyEnumDir,
        }
    }
}

/// A reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Body {
    pub(super) completion: Completion,
    pub(super) length: usize,
}

impl Body {
    pub(super) const fn success(length: usize) -> Self {
        Self {
            completion: Completion::Success,
            length,
        }
    }
}

/// A request that ends without a regular body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// An error reply.
    Error(RequestError),
    /// The output buffer is smaller than the information; the error reply
    /// carries the required length.
    TooSmall { required: u32 },
    /// The request completes later; the reply now is an interim
    /// STATUS_PENDING with this async identifier.
    Pending { async_id: AsyncId },
    /// A protocol violation that ends the connection.
    Disconnect,
}

impl<E> From<E> for Failure
where
    E: Into<RequestError>,
{
    fn from(error: E) -> Self {
        Self::Error(error.into())
    }
}

pub(super) type Handled = Result<Body, Failure>;

/// Write an error body; returns its length.
pub(super) fn write_error_body(output: &mut [u8], required: Option<u32>) -> usize {
    output[..ERROR_BODY].fill(0);
    wire::put_u16(output, 0, ERROR_BODY as u16);

    match required {
        Some(required) if output.len() >= 12 => {
            wire::put_u32(output, 4, 4);
            wire::put_u32(output, 8, required);
            12
        }
        _ => ERROR_BODY,
    }
}

/// Write the four-byte body of LOGOFF, TREE_DISCONNECT, FLUSH, LOCK, and
/// ECHO replies.
pub(super) fn empty_body(output: &mut [u8]) -> usize {
    wire::put_u32(output, 0, 4);

    4
}

/// ECHO (MS-SMB2 3.3.5.17).
pub(super) fn echo(exchange: &Exchange<'_>, output: &mut [u8]) -> Handled {
    exchange.fixed_body(4, 4)?;

    Ok(Body::success(empty_body(output)))
}

/// Check a request's signature against its session (MS-SMB2 3.3.5.2.4).
pub(super) fn check_signature(exchange: &Exchange<'_>, session: &Session) -> Result<(), Failure> {
    if !exchange.header.is_signed() {
        if session.signing_required {
            return Err(Failure::Error(RequestError::AccessDenied));
        }
        return Ok(());
    }

    let Some(key) = session.signing else {
        return Err(Failure::Error(RequestError::AccessDenied));
    };
    if !security::verify(exchange.message, &key) {
        return Err(Failure::Error(RequestError::AccessDenied));
    }

    Ok(())
}
