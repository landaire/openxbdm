//! DCE/RPC over named pipes: the server service (srvsvc) share queries.
//!
//! A [`Pipe`] carries connection-oriented DCE/RPC (C706 chapter 12 with
//! the MS-RPCE extensions) in NDR 2.0 and answers the MS-SRVS queries that
//! clients use to list shares. Replies are not buffered: each
//! [`Pipe::read`] renders the reply again and copies the requested part.
//! A reply whose rendering changes between reads, because the share list
//! changed, fails with [`PipeError::ReplyChanged`].
//! RPC-level authentication is not supported.

mod error;
mod ndr;
mod pdu;
mod srvsvc;
#[cfg(test)]
mod tests;

use ndr::Writer;
use pdu::BindRequest;
use pdu::CALL_HEADER_LENGTH;
use pdu::COMMON_HEADER_LENGTH;
use pdu::ContextElement;
use pdu::ContextId;
use pdu::ContextResult;
use pdu::FaultStatus;
use pdu::FragmentHeader;
use pdu::Limits;
use pdu::PduFlags;
use pdu::RejectReason;
use srvsvc::Call;
use srvsvc::Opnum;

use crate::backend::Backend;
use crate::backend::UserKind;
use crate::utf16::Utf16Le;

pub use error::PduError;
pub use error::PipeError;
pub use pdu::CallId;
pub use pdu::DataFormat;
pub use pdu::PacketType;
pub use pdu::RpcVersion;

/// Bytes of a request stub or bind body the pipe holds.
const DATA_CAPACITY: usize = 384;
/// Presentation contexts in one bind.
const BIND_CONTEXTS: usize = 8;
/// Presentation contexts accepted on the association.
const ACCEPTED_CONTEXTS: usize = 4;

/// Pipe names the server opens on IPC$, compared without case.
pub fn pipe_supported(name: Utf16Le<'_>) -> bool {
    name.eq_ignore_ascii_case(b"srvsvc")
}

/// What a pipe read needs from the server.
pub struct PipeContext<'a> {
    pub backend: &'a mut dyn Backend,
    pub user: UserKind,
}

/// Result of a successful [`Pipe::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeRead {
    /// `length` bytes; the reply PDU is complete (STATUS_SUCCESS).
    Complete { length: usize },
    /// `length` bytes filled `output` and more bytes of the same message
    /// remain (STATUS_BUFFER_OVERFLOW for message-mode pipes).
    Partial { length: usize },
}

/// A request being received over one or more fragments.
#[derive(Debug, Clone, Copy)]
struct Assembly {
    call_id: CallId,
    context: ContextId,
    opnum: Opnum,
    maybe: bool,
    fault: Option<FaultStatus>,
}

#[derive(Debug, Clone, Copy)]
struct Association {
    limits: Limits,
    contexts: [Option<ContextId>; ACCEPTED_CONTEXTS],
}

impl Association {
    fn accepts(&self, context: ContextId) -> bool {
        self.contexts.contains(&Some(context))
    }

    /// Record an accepted context; `false` when no slot is free.
    fn accept(&mut self, context: ContextId) -> bool {
        if self.accepts(context) {
            return true;
        }
        match self.contexts.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(context);
                true
            }
            None => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ReplyBody {
    BindAck {
        alter: bool,
        limits: Limits,
        results: [ContextResult; BIND_CONTEXTS],
        count: u8,
    },
    BindNak {
        reason: RejectReason,
    },
    Response(Response),
    Fault {
        context: ContextId,
        status: FaultStatus,
    },
}

#[derive(Debug, Clone, Copy)]
struct Reply {
    call_id: CallId,
    body: ReplyBody,
}

#[derive(Debug, Clone, Copy)]
struct Response {
    context: ContextId,
    call: Call,
    /// Largest fragment the client receives.
    fragment: u16,
    /// The stub as first rendered, set by the first read.
    rendering: Option<Rendering>,
}

/// Length and truncated SHA-256 of a rendered response stub. A later
/// rendering that differs means the backend changed during the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rendering {
    length: u32,
    digest: [u8; ndr::DIGEST_LENGTH],
}

impl Rendering {
    fn of(writer: Writer<'_>) -> Self {
        Self {
            // The stub is a few KiB at most: share names are bounded and
            // the share list is short.
            length: writer.position() as u32,
            digest: writer.digest(),
        }
    }
}

/// One open of the srvsvc pipe.
pub struct Pipe {
    /// Header of the fragment being received.
    head: [u8; CALL_HEADER_LENGTH],
    /// Bytes of the current fragment received.
    received: u16,
    /// Stub of the request being received or answered, or a bind body.
    data: [u8; DATA_CAPACITY],
    data_length: u16,
    data_overflow: bool,
    assembly: Option<Assembly>,
    association: Option<Association>,
    reply: Option<Reply>,
    /// Bytes of the reply already read.
    offset: u32,
}

const _: () = assert!(core::mem::size_of::<Pipe>() <= 512);

impl Pipe {
    pub const fn new() -> Self {
        Self {
            head: [0; CALL_HEADER_LENGTH],
            received: 0,
            data: [0; DATA_CAPACITY],
            data_length: 0,
            data_overflow: false,
            assembly: None,
            association: None,
            reply: None,
            offset: 0,
        }
    }

    /// Bytes the client wrote to the pipe. Requests may arrive in several
    /// fragments/writes.
    pub fn write(&mut self, data: &[u8]) -> Result<(), PipeError> {
        let result = self.receive(data);
        if result.is_err() {
            self.received = 0;
            self.assembly = None;
        }
        result
    }

    /// Read pending reply bytes into `output`. An empty `output` fails and
    /// leaves the reply pending.
    pub fn read(
        &mut self,
        output: &mut [u8],
        context: &mut PipeContext<'_>,
    ) -> Result<PipeRead, PipeError> {
        let reply = self.reply.ok_or(PipeError::Empty)?;
        if output.is_empty() {
            return Err(PipeError::OutputEmpty);
        }
        let progress = match reply.body {
            ReplyBody::Response(mut response) => {
                let rendering = match response.rendering {
                    Some(rendering) => rendering,
                    None => self.measure(&response.call, context),
                };
                let Some(progress) =
                    self.read_response(reply.call_id, &response, rendering, output, context)
                else {
                    self.reply = None;
                    self.offset = 0;
                    return Err(PipeError::ReplyChanged);
                };
                response.rendering = Some(rendering);
                self.reply = Some(Reply {
                    call_id: reply.call_id,
                    body: ReplyBody::Response(response),
                });
                progress
            }
            _ => self.read_control(&reply, output),
        };
        if progress.reply_done {
            self.reply = None;
            self.offset = 0;
        } else {
            self.offset += progress.length as u32;
        }
        Ok(if progress.fragment_done {
            PipeRead::Complete {
                length: progress.length,
            }
        } else {
            PipeRead::Partial {
                length: progress.length,
            }
        })
    }

    fn fragment(&self) -> FragmentHeader {
        FragmentHeader::parse(&self.head)
    }

    #[inline(never)]
    fn receive(&mut self, mut data: &[u8]) -> Result<(), PipeError> {
        while !data.is_empty() {
            if self.reply.is_some() {
                return Err(PipeError::Busy);
            }
            let received = usize::from(self.received);
            let head_length = if received < COMMON_HEADER_LENGTH {
                COMMON_HEADER_LENGTH
            } else {
                self.fragment().head_length()
            };
            let taken = if received < head_length {
                let taken = (head_length - received).min(data.len());
                self.head[received..received + taken].copy_from_slice(&data[..taken]);
                taken
            } else {
                let fragment = self.fragment();
                let taken = (fragment.length - received).min(data.len());
                self.store_body(&fragment, received, &data[..taken]);
                taken
            };
            data = &data[taken..];
            let received = received + taken;
            self.received = received as u16;
            if received == COMMON_HEADER_LENGTH {
                self.begin_fragment()?;
            }
            let fragment = self.fragment();
            if received == CALL_HEADER_LENGTH && fragment.packet_type == PacketType::REQUEST {
                self.begin_request()?;
            }
            if received >= fragment.head_length() && received == fragment.length {
                self.received = 0;
                self.finish_fragment(&fragment);
            }
        }
        Ok(())
    }

    /// Validate a common header once its 16 bytes are in.
    fn begin_fragment(&mut self) -> Result<(), PduError> {
        let fragment = self.fragment();
        fragment.validate(&self.head)?;
        if matches!(
            fragment.packet_type,
            PacketType::BIND | PacketType::ALTER_CONTEXT
        ) {
            self.assembly = None;
            self.data_length = 0;
            self.data_overflow = false;
        }
        Ok(())
    }

    /// Start or continue a request once its 24-byte header is in.
    fn begin_request(&mut self) -> Result<(), PduError> {
        let fragment = self.fragment();
        let auth_fault = fragment.has_auth().then_some(FaultStatus::PROTOCOL_ERROR);
        if fragment.flags.contains(PduFlags::FIRST_FRAGMENT) {
            self.data_length = 0;
            self.data_overflow = false;
            self.assembly = Some(Assembly {
                call_id: fragment.call_id,
                context: ContextId(u16::from_le_bytes([self.head[20], self.head[21]])),
                opnum: Opnum(u16::from_le_bytes([self.head[22], self.head[23]])),
                maybe: fragment.flags.contains(PduFlags::MAYBE),
                fault: auth_fault,
            });
            return Ok(());
        }
        match &mut self.assembly {
            Some(assembly) if assembly.call_id == fragment.call_id => {
                assembly.fault = assembly.fault.or(auth_fault);
                Ok(())
            }
            _ => Err(PduError::UnexpectedContinuation {
                call_id: fragment.call_id,
            }),
        }
    }

    /// Keep the part of `bytes`, which start at fragment offset
    /// `received`, that belongs to the stub or bind body.
    fn store_body(&mut self, fragment: &FragmentHeader, received: usize, bytes: &[u8]) {
        let Some((body_start, body_end)) = fragment.body() else {
            return;
        };
        let from = received.max(body_start);
        let to = (received + bytes.len()).min(body_end);
        if from >= to {
            return;
        }
        let chunk = &bytes[from - received..to - received];
        let length = usize::from(self.data_length);
        match self.data.get_mut(length..length + chunk.len()) {
            Some(slot) => {
                slot.copy_from_slice(chunk);
                self.data_length = (length + chunk.len()) as u16;
            }
            None => self.data_overflow = true,
        }
    }

    fn finish_fragment(&mut self, fragment: &FragmentHeader) {
        self.offset = 0;
        match fragment.packet_type {
            PacketType::BIND => self.reply = Some(self.bind(fragment, false)),
            PacketType::ALTER_CONTEXT => self.reply = Some(self.bind(fragment, true)),
            PacketType::REQUEST if fragment.flags.contains(PduFlags::LAST_FRAGMENT) => {
                if let Some(assembly) = self.assembly.take()
                    && !assembly.maybe
                {
                    self.reply = Some(self.execute(&assembly));
                }
            }
            PacketType::ORPHANED => self.assembly = None,
            _ => {}
        }
    }

    /// Answer a bind, or an alter_context when `alter`.
    #[inline(never)]
    fn bind(&mut self, fragment: &FragmentHeader, alter: bool) -> Reply {
        let call_id = fragment.call_id;
        let reject = |reason| Reply {
            call_id,
            body: if alter {
                ReplyBody::Fault {
                    context: ContextId(0),
                    status: FaultStatus::PROTOCOL_ERROR,
                }
            } else {
                ReplyBody::BindNak { reason }
            },
        };
        if fragment.has_auth() {
            return reject(RejectReason::AUTHENTICATION_TYPE_NOT_RECOGNIZED);
        }
        if self.data_overflow {
            return reject(RejectReason::LOCAL_LIMIT_EXCEEDED);
        }
        let body = &self.data[..usize::from(self.data_length)];
        let Some(request) = BindRequest::parse(body) else {
            return reject(RejectReason::NOT_SPECIFIED);
        };
        if request.context_count > BIND_CONTEXTS {
            return reject(RejectReason::LOCAL_LIMIT_EXCEEDED);
        }
        let mut association = if alter {
            match self.association {
                Some(association) => association,
                None => return reject(RejectReason::NOT_SPECIFIED),
            }
        } else {
            match Limits::negotiate(&request) {
                Some(limits) => Association {
                    limits,
                    contexts: [None; ACCEPTED_CONTEXTS],
                },
                None => return reject(RejectReason::LOCAL_LIMIT_EXCEEDED),
            }
        };
        let mut results = [ContextResult::AbstractSyntaxNotSupported; BIND_CONTEXTS];
        let mut cursor = pdu::BIND_BODY_LENGTH;
        for result in &mut results[..request.context_count] {
            let Some(element) = ContextElement::parse(body, &mut cursor) else {
                return reject(RejectReason::NOT_SPECIFIED);
            };
            *result = ContextResult::evaluate(element.abstract_syntax, element.transfer_syntaxes);
            if *result == ContextResult::Accepted && !association.accept(element.id) {
                *result = ContextResult::LocalLimitExceeded;
            }
        }
        self.association = Some(association);
        Reply {
            call_id,
            body: ReplyBody::BindAck {
                alter,
                limits: association.limits,
                results,
                count: request.context_count as u8,
            },
        }
    }

    fn execute(&self, assembly: &Assembly) -> Reply {
        let fault = |status| Reply {
            call_id: assembly.call_id,
            body: ReplyBody::Fault {
                context: assembly.context,
                status,
            },
        };
        if let Some(status) = assembly.fault {
            return fault(status);
        }
        let Some(association) = self
            .association
            .filter(|association| association.accepts(assembly.context))
        else {
            return fault(FaultStatus::UNKNOWN_INTERFACE);
        };
        if self.data_overflow {
            return fault(FaultStatus::REMOTE_NO_MEMORY);
        }
        match srvsvc::parse(assembly.opnum, &self.data[..usize::from(self.data_length)]) {
            Ok(call) => Reply {
                call_id: assembly.call_id,
                body: ReplyBody::Response(Response {
                    context: assembly.context,
                    call,
                    fragment: association.limits.transmit,
                    rendering: None,
                }),
            },
            Err(status) => fault(status),
        }
    }

    /// Render a single-fragment reply PDU.
    fn put_control(reply: &Reply, fragment_length: usize, writer: &mut Writer<'_>) {
        match reply.body {
            ReplyBody::BindAck {
                alter,
                limits,
                results,
                count,
            } => pdu::put_bind_ack(
                writer,
                fragment_length,
                reply.call_id,
                alter,
                &limits,
                &results[..usize::from(count)],
            ),
            ReplyBody::BindNak { reason } => {
                pdu::put_bind_nak(writer, fragment_length, reply.call_id, reason)
            }
            ReplyBody::Fault { context, status } => {
                pdu::put_fault(writer, fragment_length, reply.call_id, context, status)
            }
            ReplyBody::Response(_) => {}
        }
    }

    fn read_control(&self, reply: &Reply, output: &mut [u8]) -> Progress {
        let mut counter = Writer::counter();
        Self::put_control(reply, 0, &mut counter);
        let total = counter.position();
        let offset = self.offset as usize;
        let length = total.saturating_sub(offset).min(output.len());
        Self::put_control(
            reply,
            total,
            &mut Writer::window(&mut output[..length], offset),
        );
        let done = offset + length == total;
        Progress {
            length,
            fragment_done: done,
            reply_done: done,
        }
    }

    /// Render the response stub to learn its length and digest.
    fn measure(&self, call: &Call, context: &mut PipeContext<'_>) -> Rendering {
        let stub = &self.data[..usize::from(self.data_length)];
        let mut counter = Writer::counter();
        srvsvc::render(call, stub, context, &mut counter);
        Rendering::of(counter)
    }

    /// Render the part of a response fragment at the read offset. Every
    /// fragment but the last carries the same multiple of 8 stub bytes.
    /// `None` when the stub no longer renders as `rendering`.
    #[inline(never)]
    fn read_response(
        &self,
        call_id: CallId,
        response: &Response,
        rendering: Rendering,
        output: &mut [u8],
        context: &mut PipeContext<'_>,
    ) -> Option<Progress> {
        let chunk = (usize::from(response.fragment) - CALL_HEADER_LENGTH) & !7;
        let span = CALL_HEADER_LENGTH + chunk;
        let offset = self.offset as usize;
        let index = offset / span;
        let within = offset % span;
        let stub_start = index * chunk;
        // With the length fixed by `rendering`, `within` stays below
        // `fragment_length`, so a nonempty output always receives bytes.
        let remaining = (rendering.length as usize).saturating_sub(stub_start);
        let last = remaining <= chunk;
        let fragment_length = CALL_HEADER_LENGTH + remaining.min(chunk);
        let length = fragment_length.saturating_sub(within).min(output.len());
        let output = &mut output[..length];

        let mut flags = PduFlags::NONE;
        if index == 0 {
            flags = flags.union(PduFlags::FIRST_FRAGMENT);
        }
        if last {
            flags = flags.union(PduFlags::LAST_FRAGMENT);
        }
        // The allocation hint is advisory; a stub beyond 4 GiB cannot occur.
        let allocation_hint = remaining as u32;
        pdu::put_response_header(
            &mut Writer::window(output, within),
            flags,
            fragment_length,
            call_id,
            allocation_hint,
            response.context,
        );
        // The whole stub is rendered even when the window holds none of it,
        // to check it against `rendering`.
        let header_part = CALL_HEADER_LENGTH.saturating_sub(within).min(length);
        let stub_offset = (stub_start + within + header_part).saturating_sub(CALL_HEADER_LENGTH);
        let stub = &self.data[..usize::from(self.data_length)];
        let mut writer = Writer::window(&mut output[header_part..], stub_offset);
        srvsvc::render(&response.call, stub, context, &mut writer);
        if Rendering::of(writer) != rendering {
            return None;
        }
        let fragment_done = within + length == fragment_length;
        Some(Progress {
            length,
            fragment_done,
            reply_done: fragment_done && last,
        })
    }
}

/// Outcome of one read.
struct Progress {
    length: usize,
    fragment_done: bool,
    reply_done: bool,
}
