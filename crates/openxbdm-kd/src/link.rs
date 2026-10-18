//! I/O-free connection state. Handling a datagram yields an [`Outbox`]
//! the caller transmits.

use std::path::Path;

use openxbdm_kd_core::debug_io;
use openxbdm_kd_core::debug_io::DebugIo;
use openxbdm_kd_core::file_io;
use openxbdm_kd_core::file_io::FileIoReply;
use openxbdm_kd_core::file_io::FileIoRequest;
use openxbdm_kd_core::file_io::HostPath;
use openxbdm_kd_core::file_io::MAX_READ_LEN;
use openxbdm_kd_core::manipulate::ContinueDisposition;
use openxbdm_kd_core::manipulate::Processor;
use openxbdm_kd_core::manipulate::Reply;
use openxbdm_kd_core::manipulate::Request;
use openxbdm_kd_core::message::Message;
use openxbdm_kd_core::packet::Beacon;
use openxbdm_kd_core::packet::HEADER_LEN;
use openxbdm_kd_core::packet::PacketType;
use openxbdm_kd_core::session::Event;
use openxbdm_kd_core::session::Session;
use openxbdm_kd_core::state_change::NewState;
use openxbdm_kd_core::state_change::StateBody;
use openxbdm_kd_core::state_change::StateChange;

use crate::error::KdError;
use crate::host_files::HostFiles;
use crate::stop::StopImage;
use crate::stop::StopReport;

pub type NotifyFn = Box<dyn FnMut(Notification<'_>) + Send>;

/// Traffic the clients handle without a caller request.
#[derive(Debug)]
pub enum Notification<'a> {
    Print(&'a [u8]),
    /// Answered with an empty reply.
    Prompt(&'a [u8]),
    /// Load- and unload-symbols stops are continued immediately unless
    /// the image is held (see [`Link::hold_loads`]).
    LoadSymbols {
        path: &'a [u8],
        base: u64,
        size: u32,
        unload: bool,
    },
    FileOpen {
        path: HostPath<'a>,
        answer: FileOpenAnswer<'a>,
    },
    FileClosed {
        console_path: &'a str,
        bytes_served: u64,
    },
    Beacon(Beacon),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileOpenAnswer<'a> {
    Served {
        local_path: &'a Path,
        size: u64,
    },
    /// Answered `STATUS_OBJECT_NAME_NOT_FOUND`; the kernel opens the file
    /// from its own devices.
    NotMapped,
    /// The mapped local file could not be opened; answered as `NotMapped`.
    Failed {
        local_path: &'a Path,
    },
}

/// A manipulate reply copied out of the receive buffer.
#[derive(Debug, Clone)]
pub struct OwnedReply {
    payload: Vec<u8>,
}

impl OwnedReply {
    fn new(payload: &[u8]) -> Result<Self, KdError> {
        Reply::decode(payload)?;

        Ok(Self {
            payload: payload.to_vec(),
        })
    }

    pub fn reply(&self) -> Reply<'_> {
        match Reply::decode(&self.payload) {
            Ok(reply) => reply,
            Err(error) => unreachable!("reply validated in OwnedReply::new: {error}"),
        }
    }
}

pub(crate) enum Incoming {
    Reply(OwnedReply),
    Stopped,
}

/// Datagrams to transmit after handling input, in order.
#[derive(Debug, Default)]
pub(crate) struct Outbox {
    pub(crate) control: Option<[u8; HEADER_LEN]>,
    /// Transmit the session's outstanding data packet.
    pub(crate) outstanding: bool,
}

pub(crate) struct Link {
    pub(crate) session: Session,
    pub(crate) stop: Option<StopReport>,
    pub(crate) synchronized: bool,

    pub(crate) notify: Option<NotifyFn>,

    pub(crate) files: HostFiles,
    /// Image names whose load-symbols stop is reported as a stop instead
    /// of being continued. Compared case-insensitively.
    pub(crate) hold_loads: Vec<String>,
    /// Held load stops reported since the last continue. The kernel
    /// repeats a stop after the reset that synchronizes a session and when a
    /// processor switch returns to the reporting processor; a repeat is not
    /// a new load. The repeat carries the registers of that moment, so only
    /// the processor, program counter and image identify it.
    pub(crate) held_reports: Vec<HeldLoad>,
    file_data: Box<[u8; MAX_READ_LEN]>,
}

impl Link {
    pub(crate) fn new() -> Self {
        Self {
            session: Session::new(),
            stop: None,
            synchronized: false,
            notify: None,
            files: HostFiles::default(),
            hold_loads: Vec::new(),
            held_reports: Vec::new(),
            file_data: Box::new([0; MAX_READ_LEN]),
        }
    }

    pub(crate) fn send_data(
        &mut self,
        packet_type: PacketType,
        parts: &[&[u8]],
        outbox: &mut Outbox,
    ) -> Result<(), KdError> {
        self.session.send(packet_type, parts)?;
        outbox.outstanding = true;

        Ok(())
    }

    pub(crate) fn send_request(
        &mut self,
        processor: Processor,
        request: Request,
        data: &[u8],
        outbox: &mut Outbox,
    ) -> Result<(), KdError> {
        let header = request.encode(processor);

        self.send_data(PacketType::MANIPULATE, &[&header, data], outbox)
    }

    fn notify(&mut self, notification: Notification<'_>) {
        emit(&mut self.notify, notification);
    }

    pub(crate) fn handle_datagram(
        &mut self,
        datagram: &[u8],
        outbox: &mut Outbox,
    ) -> Result<Option<Incoming>, KdError> {
        let received = match self.session.receive(datagram) {
            Ok(received) => received,
            Err(error) => {
                tracing::warn!(%error, length = datagram.len(), "undecodable datagram");
                return Ok(None);
            }
        };

        outbox.control = received.reply;

        match received.event {
            Event::Data(packet) => match Message::decode(&packet) {
                Ok(Message::Manipulate(_)) => {
                    Ok(Some(Incoming::Reply(OwnedReply::new(packet.payload())?)))
                }
                Ok(message) => self.handle_message(message, outbox),
                Err(error) => {
                    tracing::warn!(%error, packet_type = ?packet.packet_type(), "undecodable message");
                    Ok(None)
                }
            },
            Event::Duplicate(id) => {
                tracing::trace!(?id, "duplicate");
                Ok(None)
            }
            Event::Corrupt(error) => {
                tracing::warn!(%error, "corrupt packet, resend requested");
                Ok(None)
            }
            Event::Acknowledged(id) => {
                tracing::trace!(?id, "acknowledged");
                Ok(None)
            }
            Event::UnmatchedAcknowledge(id) => {
                tracing::trace!(?id, "acknowledge without outstanding packet");
                Ok(None)
            }
            Event::ResendRequested => {
                outbox.outstanding = self.session.outstanding().is_some();
                Ok(None)
            }
            Event::Reset { target_next_id } => {
                tracing::debug!(?target_next_id, "reset");
                self.synchronized = true;
                Ok(None)
            }
            Event::Beacon(beacon) => {
                self.notify(Notification::Beacon(beacon));
                Ok(None)
            }
        }
    }

    fn handle_message(
        &mut self,
        message: Message<'_>,
        outbox: &mut Outbox,
    ) -> Result<Option<Incoming>, KdError> {
        match message {
            Message::Manipulate(_) => unreachable!("handled by handle_datagram"),
            Message::StateChange(change) => self.handle_state_change(change, outbox),
            Message::DebugIo(DebugIo::Print { text, .. }) => {
                self.notify(Notification::Print(text));
                Ok(None)
            }
            Message::DebugIo(DebugIo::Prompt { text, .. }) => {
                self.notify(Notification::Prompt(text));
                let header = debug_io::encode_prompt_reply(0);
                self.send_data(PacketType::DEBUG_IO, &[&header], outbox)?;
                Ok(None)
            }
            Message::DebugIo(DebugIo::Other { api, .. }) => {
                tracing::warn!(api, "unknown debug I/O message");
                Ok(None)
            }
            Message::FileIo(request) => self.serve_file_io(request, outbox),
            Message::Other {
                packet_type,
                payload,
            } => {
                tracing::warn!(
                    ?packet_type,
                    length = payload.len(),
                    "unhandled packet type"
                );
                Ok(None)
            }
        }
    }

    fn handle_state_change(
        &mut self,
        change: StateChange<'_>,
        outbox: &mut Outbox,
    ) -> Result<Option<Incoming>, KdError> {
        let StateBody::LoadSymbols(symbols) = change.body else {
            if change.new_state != NewState::EXCEPTION {
                tracing::warn!(state = ?change.new_state, "unknown state change");
            }

            self.stop = Some(StopReport::from_state_change(&change));
            return Ok(Some(Incoming::Stopped));
        };

        let held = !symbols.unload && self.holds(change.path);
        let report = held.then(|| StopReport::from_state_change(&change));

        let held_load = report.as_ref().map(HeldLoad::of);
        let repeat = held_load
            .as_ref()
            .is_some_and(|held_load| self.held_reports.contains(held_load));
        if !repeat {
            self.notify(Notification::LoadSymbols {
                path: change.path,
                base: symbols.base,
                size: symbols.size_of_image,
                unload: symbols.unload,
            });
        }

        if let Some(report) = report {
            if let Some(held_load) = held_load
                && !repeat
            {
                self.held_reports.push(held_load);
            }
            self.stop = Some(report);
            return Ok(Some(Incoming::Stopped));
        }

        self.stop = None;
        let request = Request::Continue {
            disposition: ContinueDisposition::Handled,
        };
        self.send_request(change.processor, request, &[], outbox)?;

        Ok(None)
    }

    fn holds(&self, path: &[u8]) -> bool {
        self.hold_loads
            .iter()
            .any(|name| name.as_bytes().eq_ignore_ascii_case(path))
    }

    fn serve_file_io(
        &mut self,
        request: FileIoRequest<'_>,
        outbox: &mut Outbox,
    ) -> Result<Option<Incoming>, KdError> {
        // The kernel sends a new file request only after it consumed the
        // host's previous packet, so a packet still outstanding lost only
        // its acknowledgement. Retransmitting it would answer this request.
        if let Some(id) = self.session.outstanding() {
            tracing::debug!(?id, "outstanding packet consumed without acknowledgement");
            self.session.abandon();
        }

        let closing = match &request {
            FileIoRequest::Close(close) => self
                .files
                .describe(close.handle)
                .map(|file| (file.console_path.to_owned(), file.bytes_served)),
            _ => None,
        };

        let (reply, length) = file_io::respond(&request, &mut self.files, &mut self.file_data);

        match &request {
            FileIoRequest::Open(open) => {
                let answer = match (self.files.mapping(&open.path), reply) {
                    (None, _) => FileOpenAnswer::NotMapped,
                    (Some(mapping), FileIoReply::Opened(opened)) => FileOpenAnswer::Served {
                        local_path: &mapping.local_path,
                        size: opened.size,
                    },
                    (Some(mapping), _) => FileOpenAnswer::Failed {
                        local_path: &mapping.local_path,
                    },
                };
                emit(
                    &mut self.notify,
                    Notification::FileOpen {
                        path: open.path,
                        answer,
                    },
                );
            }
            FileIoRequest::Read(read) => {
                tracing::debug!(
                    handle = read.handle.0,
                    offset = read.offset,
                    length = read.length,
                    ?reply,
                    served = length,
                    "host file read"
                );
            }
            FileIoRequest::Close(close) => match closing {
                Some((console_path, bytes_served)) => {
                    emit(
                        &mut self.notify,
                        Notification::FileClosed {
                            console_path: &console_path,
                            bytes_served,
                        },
                    );
                }
                None => tracing::warn!(
                    handle = close.handle.0,
                    "close of an unknown host file handle"
                ),
            },
            FileIoRequest::Other { api, payload } => {
                tracing::warn!(?api, length = payload.len(), "unknown host file request");
            }
        }

        let header = reply.encode();
        self.session
            .send(PacketType::FILE_IO, &[&header, &self.file_data[..length]])?;
        outbox.outstanding = true;

        Ok(None)
    }
}

fn emit(notify: &mut Option<NotifyFn>, notification: Notification<'_>) {
    if let Some(notify) = notify.as_mut() {
        notify(notification);
    }
}

/// Identity of a held load stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldLoad {
    processor: Processor,
    program_counter: u64,
    image: Option<StopImage>,
}

impl HeldLoad {
    fn of(report: &StopReport) -> Self {
        Self {
            processor: report.processor,
            program_counter: report.program_counter,
            image: report.image.clone(),
        }
    }
}
