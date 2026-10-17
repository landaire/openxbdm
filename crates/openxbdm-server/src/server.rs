//! Connection engine: accept, line framing, dispatch, and transfers.
//!
//! The engine performs no I/O of its own. The platform reports socket
//! readiness and the engine calls back into [`Network`]. It follows the
//! monitor's framing: one command line is taken per receive, a line ends at
//! CR followed by any byte, and the receive buffer holds 0x200 bytes.
// Abandoned transfer blocks are freed through the unsafe
// `TransferBlocks::abandon`.
#![allow(unsafe_code)]

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

use crate::access::Access;
use crate::backend::Backend;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::continuation;
use crate::continuation::Continuation;
use crate::continuation::ContinuationContext;
use crate::invocation::ConnectionIndex;
use crate::invocation::DedicateTarget;
use crate::invocation::Invocation;
use crate::invocation::Session;
use crate::invocation::SessionRequest;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_all;
use crate::network::send_line;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::processors::ExternalContinuation;
use crate::processors::ProcessorCall;
use crate::processors::ProcessorFlags;
use crate::processors::ProcessorProgress;
use crate::processors::ProcessorThread;
use crate::registry;
use crate::registry::DispatchFlags;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::LineText;
use crate::text::ResponseText;
use crate::text::Text;

pub const MAX_CONNECTIONS: usize = 8;
/// Receive buffer of a connection; a command line plus CR LF must fit.
pub const RECEIVE_CAPACITY: usize = 0x200;
/// Scratch receive size while discarding an overlong line.
const OVERFLOW_SCRATCH: usize = 0x40;
/// Buffer of 203 output, raw 202 output, and 204 input.
pub const TRANSFER_CAPACITY: usize = 0x1000;

/// Transfer in progress on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    Idle,
    Multiline,
    BinarySend,
    BinaryReceive,
}

/// Context that services a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The main server context.
    Main,
    /// A context dedicated to the command processor in this slot.
    Processor(u8),
    /// The title command context.
    Title,
    /// No context services the connection. The monitor leaves a connection
    /// in this state when it is dedicated to a processor registered without
    /// either threading flag.
    Unserviced,
}

#[derive(Debug)]
struct Connection {
    session: Session,
    received: [u8; RECEIVE_CAPACITY],
    count: usize,
    overflow: bool,
    transfer: Transfer,
    owner: Owner,
    /// Processor the connection is dedicated to.
    processor: Option<u8>,
    /// Serviced by a thread of the title process (monitor connection flag
    /// 0x40000000); such connections close when the title ends.
    title_process: bool,
    /// Processor call that runs on another thread.
    processor_call: Option<PendingCall>,
}

/// Step of a connection that waits for a processor call to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCall {
    /// The handler of a command line.
    Command { call: ProcessorCall, processor: u8 },
    /// The continuation of a 202 or 203 transfer.
    Send,
    /// The continuation of a 204 upload; `closed` when the receive failed.
    Receive { closed: bool },
}

/// What the platform does after a socket event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Keep servicing the connection.
    Open,
    /// The connection slot was released; the platform stops servicing it.
    /// The socket was closed unless it now belongs to the notification
    /// subsystem.
    Released,
}

/// The XBDM server.
pub struct Server {
    connections: [Option<Connection>; MAX_CONNECTIONS],
    pub state: ServerState,
    line: [u8; RECEIVE_CAPACITY],
    text: ResponseText,
    line_text: LineText,
    transfer: [u8; TRANSFER_CAPACITY],
    shutting_down: bool,
    /// Last lock-mode challenge of each slot. The monitor keeps it in the
    /// connection slot, so unlocked connections inherit it.
    nonces: [[u32; 2]; MAX_CONNECTIONS],
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub const fn new() -> Self {
        Self {
            connections: [const { None }; MAX_CONNECTIONS],
            state: ServerState::new(),
            line: [0; RECEIVE_CAPACITY],
            text: ResponseText::new(),
            line_text: LineText::new(),
            transfer: [0; TRANSFER_CAPACITY],
            shutting_down: false,
            nonces: [[0; 2]; MAX_CONNECTIONS],
        }
    }

    /// Stop accepting connections.
    pub fn shut_down(&mut self) {
        self.shutting_down = true;
    }

    /// Indices of open connections and the contexts servicing them.
    pub fn connections(&self) -> impl Iterator<Item = (ConnectionIndex, SocketId, Owner)> + '_ {
        self.connections
            .iter()
            .enumerate()
            .filter_map(|(index, connection)| {
                connection
                    .as_ref()
                    .map(|c| (ConnectionIndex(index as u8), c.session.socket, c.owner))
            })
    }

    /// Whether the connection waits to send (202 or 203 output); otherwise it
    /// waits to receive.
    pub fn wants_write(&self, index: ConnectionIndex) -> bool {
        self.connection(index).is_some_and(|connection| {
            matches!(
                connection.transfer,
                Transfer::Multiline | Transfer::BinarySend
            )
        })
    }

    fn connection(&self, index: ConnectionIndex) -> Option<&Connection> {
        self.connections
            .get(index.0 as usize)
            .and_then(Option::as_ref)
    }

    // The socket event entry points stay out of line so the platform's
    // service loop does not hold their frames while it handles other events.

    /// Accept a new socket. When every slot is in use the peer receives
    /// `401- max number of connections exceeded` and the socket is closed.
    #[inline(never)]
    pub fn accept(
        &mut self,
        socket: SocketId,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Option<ConnectionIndex> {
        let slot = if self.shutting_down {
            None
        } else {
            self.connections.iter().position(Option::is_none)
        };
        let Some(slot) = slot else {
            let _ = send_line(network, socket, b"401- max number of connections exceeded");
            network.close(socket);
            return None;
        };

        let lock = self.state.lock;
        let mut banner = Text::<64>::new();
        let (access, nonce) = if lock.is_locked() {
            let time = backend.system_time();
            let timebase = backend.timebase();
            // The FILETIME is stored high dword first; each dword is mixed
            // with the opposite half of the time base.
            let nonce = [
                ((time >> 32) as u32) ^ (timebase as u32),
                (time as u32) ^ ((timebase >> 32) as u32),
            ];
            self.nonces[slot] = nonce;
            // The banner always fits.
            let _ = banner.push_bytes(b"201- boxid=0q");
            let _ = banner.push_hex32(lock.box_id[0]);
            let _ = banner.push_hex32(lock.box_id[1]);
            let _ = banner.push_bytes(b" nonce=0q");
            let _ = banner.push_hex32(nonce[0]);
            let _ = banner.push_hex32(nonce[1]);
            (Access::empty(), nonce)
        } else {
            let _ = banner.push_bytes(b"201- connected");
            (Access::UNRESTRICTED, self.nonces[slot])
        };
        if send_line(network, socket, banner.as_bytes()).is_err() {
            network.close(socket);
            return None;
        }

        let index = ConnectionIndex(slot as u8);
        self.connections[slot] = Some(Connection {
            session: Session::new(index, socket, access, nonce),
            received: [0; RECEIVE_CAPACITY],
            count: 0,
            overflow: false,
            transfer: Transfer::Idle,
            owner: Owner::Main,
            processor: None,
            title_process: false,
            processor_call: None,
        });
        Some(index)
    }

    /// Close a connection and release its slot.
    pub fn close(&mut self, index: ConnectionIndex, network: &mut dyn Network) {
        if let Some(connection) = self
            .connections
            .get_mut(index.0 as usize)
            .and_then(Option::take)
        {
            let socket = connection.session.socket;
            crate::commands::debugger::connection_closed(&mut self.state, socket);
            // SAFETY: the connection, with its continuation, was taken out
            // of its slot above and is dropped here.
            unsafe { self.state.transfer_blocks.abandon(socket) };
            network.close(connection.session.socket);
        }
    }

    /// Deliver an event to the notification channels. Returns whether any
    /// channel accepted it.
    pub fn deliver(&mut self, event: &Event<'_>, network: &mut dyn Network) -> bool {
        self.state.notifications.deliver(event, network)
    }

    /// Process the debug events the platform has queued.
    #[inline(never)]
    pub fn poll_debug_events(&mut self, backend: &mut dyn Backend, network: &mut dyn Network) {
        crate::commands::debugger::process_events(&mut self.state, backend, network);
    }

    /// Periodic work: end the wait for reverse persistent notification
    /// targets and drive the lab server registration. The platform calls
    /// this on every pass of its loop and at least once per second; the
    /// result is the milliseconds until a timer needs it again.
    #[inline(never)]
    pub fn poll_timers(&mut self, backend: &mut dyn Backend) -> Option<u32> {
        crate::commands::session::expire_reverse_targets(&mut self.state, backend);
        let registration = crate::commands::console::poll_registration(&mut self.state, backend);
        self.save_settings_if_dirty(backend);
        Some(registration)
    }

    /// Sockets of open `fastpipe` pipes. The platform reports when they are
    /// readable to [`Server::on_fast_pipe_readable`].
    pub fn fast_pipe_sockets(&self) -> impl Iterator<Item = SocketId> + '_ {
        self.state.session.fast_pipes.sockets()
    }

    /// A `fastpipe` socket is readable.
    #[inline(never)]
    pub fn on_fast_pipe_readable(
        &mut self,
        socket: SocketId,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) {
        crate::commands::session::on_fast_pipe_readable(&mut self.state, backend, network, socket);
    }

    /// Send the notification texts other threads have posted.
    pub fn drain_posted_notifications(
        &mut self,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) {
        crate::commands::session::send_posted_notifications(&mut self.state, backend, network);
    }

    /// The title process ended: remove its processors, close connections
    /// serviced in it, and release title network state.
    pub fn title_terminated(&mut self, backend: &mut dyn Backend, network: &mut dyn Network) {
        backend.remove_title_processors();
        crate::commands::network::title_exited(&mut self.state, backend);
        crate::commands::console::title_terminated(&mut self.state, backend);
        for index in 0..MAX_CONNECTIONS {
            if matches!(&self.connections[index], Some(c) if c.title_process) {
                self.close(ConnectionIndex(index as u8), network);
            }
        }
    }

    /// Run a settings-file line with all privileges and no output. The
    /// line is not limited to the receive buffer size.
    pub fn execute_settings_line(
        &mut self,
        line: &[u8],
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) {
        console::trace_text(
            self.state.console.trace_mask,
            backend,
            TraceMask::SETTINGS,
            |message| {
                let _ = message.write_str("XBDM: DoIniLine '");
                let _ = message.push_bytes(console::c_string(line));
                let _ = message.write_str("'\n");
            },
        );
        self.text.clear();
        let command = CommandLine::new(line);
        let entry = registry::lookup(command.command());
        let mut invocation = Invocation {
            line: command,
            buffer: line,
            text: &mut self.text,
            session: None,
            state: &mut self.state,
            backend,
            network,
        };
        if !crate::commands::system::settings_keyword(&mut invocation)
            && !command.command().is_empty()
        {
            trace_thread(
                invocation.state,
                invocation.backend,
                TraceMask::REPLIES,
                format_args!("-1:"),
                &[line],
            );
            if let Some(entry) = entry
                && !(entry.flags().contains(DispatchFlags::DEVKIT_ONLY)
                    && invocation.backend.is_test_kit())
            {
                // Settings lines send no reply.
                let _ = (entry.handler)(&mut invocation);
            }
        }
        self.save_settings_if_dirty(backend);
    }

    /// Write the settings file when a change marked it dirty.
    pub fn save_settings_if_dirty(&mut self, backend: &mut dyn Backend) {
        if core::mem::take(&mut self.state.settings_dirty) {
            crate::commands::system::save_settings(&self.state, backend);
        }
    }

    /// The connection socket is readable.
    #[inline(never)]
    pub fn on_readable(
        &mut self,
        index: ConnectionIndex,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        let Some(connection) = self.connections.get_mut(slot).and_then(Option::as_mut) else {
            return Outcome::Released;
        };
        if connection.owner == Owner::Unserviced || connection.processor_call.is_some() {
            return Outcome::Open;
        }
        if connection.transfer == Transfer::BinaryReceive {
            return self.pump_receive(index, backend, network);
        }

        let socket = connection.session.socket;
        let terminator = if connection.overflow {
            let mut scratch = [0u8; OVERFLOW_SCRATCH];
            let Ok(received @ 1..) = network.receive(socket, &mut scratch) else {
                self.close(index, network);
                return Outcome::Released;
            };
            find_terminator(&scratch[..received], 0).map(|_| 0)
        } else {
            let start = connection.count;
            let Ok(received @ 1..) = network.receive(socket, &mut connection.received[start..])
            else {
                self.close(index, network);
                return Outcome::Released;
            };
            connection.count += received;
            if connection.count >= RECEIVE_CAPACITY {
                connection.overflow = true;
            }
            find_terminator(
                &connection.received[..connection.count],
                start.saturating_sub(1),
            )
        };
        let Some(terminator) = terminator else {
            return Outcome::Open;
        };

        if connection.overflow {
            connection.count = 0;
            connection.overflow = false;
            trace_thread(
                &self.state,
                backend,
                TraceMask::REPLIES,
                format_args!("R="),
                &[b"446- line too long"],
            );
            if send_line(network, socket, b"446- line too long").is_err() {
                self.close(index, network);
                return Outcome::Released;
            }
            return Outcome::Open;
        }

        // The monitor ends the line in place; later reads past a short line
        // see this NUL and the bytes after it.
        connection.received[terminator] = 0;
        self.line.copy_from_slice(&connection.received);
        let outcome = self.dispatch(index, terminator, backend, network);
        if outcome == Outcome::Open
            && let Some(connection) = self.connections[slot].as_mut()
        {
            let consumed = (terminator + 2).min(connection.count);
            connection
                .received
                .copy_within(consumed..connection.count, 0);
            connection.count -= consumed;
        }
        outcome
    }

    /// The connection socket is writable while a 202 or 203 transfer runs.
    #[inline(never)]
    pub fn on_writable(
        &mut self,
        index: ConnectionIndex,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        let Some(connection) = self.connections.get_mut(slot).and_then(Option::as_mut) else {
            return Outcome::Released;
        };
        if connection.processor_call.is_some() {
            return Outcome::Open;
        }
        let transfer = connection.transfer;
        let socket = connection.session.socket;
        let mut continuation = core::mem::take(&mut connection.session.continuation);
        self.line_text.clear();
        let mut cx = ContinuationContext {
            line: &mut self.line_text,
            binary: &mut self.transfer,
            binary_len: 0,
            no_output: false,
            processor_running: false,
            received: &[],
            aborted: false,
            session: &mut connection.session,
            state: &mut self.state,
            backend,
            network,
        };
        let result = continuation::resume(&mut continuation, &mut cx);
        let binary_len = cx.binary_len.min(TRANSFER_CAPACITY);
        let no_output = cx.no_output;
        if cx.processor_running {
            connection.processor_call = Some(PendingCall::Send);
            restore_continuation(connection, continuation);
            return Outcome::Open;
        }

        match transfer {
            Transfer::Multiline => {
                if result == Err(CommandError::EndOfData) {
                    let sent = send_line(network, socket, b".");
                    finish_transfer(connection);
                    if sent.is_err() {
                        self.close(index, network);
                        return Outcome::Released;
                    }
                } else if result.is_err() {
                    self.close(index, network);
                    return Outcome::Released;
                } else {
                    let _ = if no_output {
                        Ok(())
                    } else if binary_len > 0 {
                        send_all(network, socket, &self.transfer[..binary_len])
                    } else {
                        send_line(network, socket, self.line_text.as_bytes())
                    };
                    restore_continuation(connection, continuation);
                }
            }
            Transfer::BinarySend => {
                if result == Err(CommandError::EndOfData) {
                    finish_transfer(connection);
                } else if result.is_err() {
                    self.close(index, network);
                    return Outcome::Released;
                } else if send_all(network, socket, &self.transfer[..binary_len]).is_err() {
                    connection.session.receive_remaining = Some(0);
                    let mut cx = ContinuationContext {
                        line: &mut self.line_text,
                        binary: &mut self.transfer,
                        binary_len: 0,
                        no_output: false,
                        processor_running: false,
                        received: &[],
                        aborted: true,
                        session: &mut connection.session,
                        state: &mut self.state,
                        backend,
                        network,
                    };
                    // The connection closes; the final call's result is not sent.
                    let _ = continuation::resume(&mut continuation, &mut cx);
                    self.close(index, network);
                    return Outcome::Released;
                } else {
                    restore_continuation(connection, continuation);
                }
            }
            Transfer::Idle | Transfer::BinaryReceive => {
                restore_continuation(connection, continuation)
            }
        }
        self.save_settings_if_dirty(backend);
        Outcome::Open
    }

    fn pump_receive(
        &mut self,
        index: ConnectionIndex,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        let Some(connection) = self.connections[slot].as_mut() else {
            return Outcome::Released;
        };
        let socket = connection.session.socket;
        let remaining = connection.session.receive_remaining.unwrap_or(0) as usize;
        let mut closed = false;
        let limit = match &connection.session.continuation {
            Continuation::External(external) => backend
                .processor_receive_limit(external)
                .min(TRANSFER_CAPACITY),
            _ => TRANSFER_CAPACITY,
        };
        let count = if connection.count != 0 {
            // The monitor cuts a buffered piece larger than the receiver's
            // buffer to the buffer size, even past the remaining count.
            let count = if connection.count > limit {
                limit
            } else {
                connection.count.min(remaining)
            };
            if count != 0 {
                trace_thread(
                    &self.state,
                    backend,
                    TraceMask::BINARY_RECEIVE,
                    format_args!("BR(buffer): {} of {} bytes", count as i32, remaining as i32),
                    &[],
                );
            }
            self.transfer[..count].copy_from_slice(&connection.received[..count]);
            connection.received.copy_within(count..connection.count, 0);
            connection.count -= count;
            count
        } else {
            let wanted = remaining.min(limit);
            if wanted == 0 {
                0
            } else {
                let received = match network.receive(socket, &mut self.transfer[..wanted]) {
                    Ok(received @ 1..) => received,
                    _ => {
                        closed = true;
                        0
                    }
                };
                trace_thread(
                    &self.state,
                    backend,
                    TraceMask::BINARY_RECEIVE,
                    format_args!(
                        "BR(recv): {} of {} bytes",
                        received as i32, remaining as i32
                    ),
                    &[],
                );
                received
            }
        };
        self.continue_receive(index, count, closed, backend, network)
    }

    /// Pass `self.transfer[..count]` of a 204 upload to the continuation;
    /// `closed` when the receive failed and the connection closes after
    /// the call.
    fn continue_receive(
        &mut self,
        index: ConnectionIndex,
        count: usize,
        closed: bool,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let Some(connection) = self.connections[index.0 as usize].as_mut() else {
            return Outcome::Released;
        };
        let mut continuation = core::mem::take(&mut connection.session.continuation);
        self.line_text.clear();
        let (received, binary) = self.transfer.split_at_mut(count);
        let mut cx = ContinuationContext {
            line: &mut self.line_text,
            binary,
            binary_len: 0,
            no_output: false,
            processor_running: false,
            received,
            aborted: false,
            session: &mut connection.session,
            state: &mut self.state,
            backend,
            network,
        };
        let result = continuation::resume(&mut continuation, &mut cx);
        let running = cx.processor_running;
        restore_continuation(connection, continuation);
        if running {
            connection.processor_call = Some(PendingCall::Receive { closed });
            return Outcome::Open;
        }
        if closed {
            self.close(index, network);
            return Outcome::Released;
        }
        if connection.session.receive_remaining != Some(0) {
            return Outcome::Open;
        }
        self.finish_receive(index, result, backend, network)
    }

    /// A 204 upload is complete; select the next step from `result`.
    fn finish_receive(
        &mut self,
        index: ConnectionIndex,
        mut result: CommandResult,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let Some(connection) = self.connections[index.0 as usize].as_mut() else {
            return Outcome::Released;
        };
        connection.session.receive_remaining = None;
        connection.transfer = Transfer::Idle;
        if result == Ok(Reply::Multiline) {
            connection.transfer = Transfer::Multiline;
        } else if result == Ok(Reply::Binary) {
            connection.transfer = Transfer::BinarySend;
        } else if result != Ok(Reply::FastPipe) {
            connection.session.continuation = Continuation::None;
        }
        if connection.transfer != Transfer::Idle && connection.session.continuation.is_none() {
            connection.transfer = Transfer::Idle;
            // The monitor picks the text before it replaces the result.
            if self.line_text.is_empty() {
                self.line_text
                    .set_bytes(reply::hresult(result).default_message().as_bytes());
            }
            result = Err(CommandError::Unexpected);
        }
        let socket = connection.session.socket;
        let sent = send_status(
            &self.state,
            backend,
            network,
            socket,
            result,
            self.line_text.as_bytes(),
        );
        self.save_settings_if_dirty(backend);
        if sent.is_err() {
            self.close(index, network);
            return Outcome::Released;
        }
        Outcome::Open
    }

    /// Execute the command line in `self.line[..length]` for a connection.
    fn dispatch(
        &mut self,
        index: ConnectionIndex,
        length: usize,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        let line = &self.line[..length];
        trace_thread(
            &self.state,
            backend,
            TraceMask::REPLIES,
            format_args!("{}:", i32::from(index.0)),
            &[line],
        );
        let Some(connection) = self.connections[slot].as_mut() else {
            return Outcome::Released;
        };
        connection.session.continuation = Continuation::None;
        // SAFETY: the continuation was cleared above.
        unsafe {
            self.state
                .transfer_blocks
                .abandon(connection.session.socket)
        };
        connection.session.receive_remaining = None;
        connection.session.request = None;
        connection.transfer = Transfer::Idle;
        self.text.clear();

        let line = CommandLine::new(&self.line[..length]);
        let word = line.command();
        let access = connection.session.access;
        let mut external = None;

        let result = if let Some(bang) = word.iter().position(|&byte| byte == b'!') {
            match backend.find_processor(&word[..bang]) {
                None => Err(ErrorCode::UnknownCommand.into()),
                Some(_) if !access.intersects(Access::CONTROL) => {
                    Err(ErrorCode::AccessDenied.into())
                }
                Some((processor_index, processor)) => {
                    let previous = (connection.owner, connection.title_process);
                    let allowed = if connection.processor == Some(processor_index) {
                        true
                    } else if processor.flags.contains(ProcessorFlags::DEDICATED_THREAD)
                        || connection.processor.is_some()
                    {
                        false
                    } else if processor.flags.contains(ProcessorFlags::TITLE) {
                        // The monitor hands the line to the title command
                        // thread, which dispatches and traces it again.
                        if connection.owner != Owner::Title {
                            let line = &self.line[..length];
                            let slot = i32::from(index.0);
                            trace_thread(
                                &self.state,
                                backend,
                                TraceMask::REPLIES,
                                format_args!("{slot}:"),
                                &[line],
                            );
                        }
                        connection.owner = Owner::Title;
                        connection.title_process = true;
                        true
                    } else {
                        connection.owner != Owner::Title
                    };
                    if allowed {
                        let thread = match connection.owner {
                            Owner::Title => ProcessorThread::Title,
                            Owner::Processor(_) => ProcessorThread::Dedicated {
                                title: connection.title_process,
                            },
                            Owner::Main | Owner::Unserviced => ProcessorThread::Server,
                        };
                        let call = ProcessorCall {
                            handle: processor.handle,
                            connection: index,
                            thread,
                        };
                        match backend.call_processor(
                            call,
                            &self.line[..length],
                            &mut self.text,
                            &mut external,
                            &mut connection.session.receive_remaining,
                        ) {
                            ProcessorProgress::Complete(result) => processor_result(
                                &mut connection.session,
                                backend,
                                processor_index,
                                result,
                            ),
                            ProcessorProgress::Running => {
                                connection.processor_call = Some(PendingCall::Command {
                                    call,
                                    processor: processor_index,
                                });
                                return Outcome::Open;
                            }
                            ProcessorProgress::Unavailable => {
                                (connection.owner, connection.title_process) = previous;
                                Err(ErrorCode::DedicatedConnectionRequired.into())
                            }
                        }
                    } else {
                        Err(ErrorCode::DedicatedConnectionRequired.into())
                    }
                }
            }
        } else {
            match registry::lookup(word) {
                None => Err(ErrorCode::UnknownCommand.into()),
                Some(entry)
                    if entry.flags().contains(DispatchFlags::DEVKIT_ONLY)
                        && backend.is_test_kit() =>
                {
                    Err(ErrorCode::UnknownCommand.into())
                }
                Some(entry) if !entry.permits(access) => Err(ErrorCode::AccessDenied.into()),
                // Handlers that run on their own thread skip the context check.
                Some(entry)
                    if connection.owner != Owner::Main
                        && !entry.flags().contains(DispatchFlags::ANY_CONTEXT)
                        && !entry.flags().contains(DispatchFlags::OWN_THREAD) =>
                {
                    Err(ErrorCode::DedicatedConnectionRequired.into())
                }
                Some(entry) => {
                    let mut invocation = Invocation {
                        line,
                        buffer: &self.line,
                        text: &mut self.text,
                        session: Some(&mut connection.session),
                        state: &mut self.state,
                        backend,
                        network,
                    };
                    (entry.handler)(&mut invocation)
                }
            }
        };
        self.reply(index, result, external, backend, network)
    }

    /// Send the result of a command and apply what it requested.
    fn reply(
        &mut self,
        index: ConnectionIndex,
        mut result: CommandResult,
        external: Option<ExternalContinuation>,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        let Some(connection) = self.connections[slot].as_mut() else {
            return Outcome::Released;
        };
        let socket = connection.session.socket;
        if let Some(external) = external {
            connection.session.continuation = Continuation::External(external);
        }

        let request = connection.session.request.take();
        if result != Ok(Reply::Sent) {
            if result == Ok(Reply::Multiline) {
                connection.transfer = Transfer::Multiline;
            } else if result == Ok(Reply::Binary) {
                connection.transfer = Transfer::BinarySend;
            } else if result == Ok(Reply::SendBinary) {
                connection.transfer = Transfer::BinaryReceive;
            }
            if connection.transfer != Transfer::Idle && connection.session.continuation.is_none() {
                connection.transfer = Transfer::Idle;
                // The monitor picks the text before it replaces the result.
                if self.text.is_empty() {
                    self.text
                        .set_bytes(reply::hresult(result).default_message().as_bytes());
                }
                result = Err(CommandError::Unexpected);
            }
            if send_status(
                &self.state,
                backend,
                network,
                socket,
                result,
                self.text.as_bytes(),
            )
            .is_err()
            {
                self.close(index, network);
                return Outcome::Released;
            }
        }
        let outcome = self.apply_request(index, request, backend, network);
        self.save_settings_if_dirty(backend);
        if outcome == Outcome::Released {
            return outcome;
        }

        if result == Ok(Reply::SendBinary)
            && self.connections[slot]
                .as_ref()
                .is_some_and(|c| c.session.receive_remaining == Some(0))
        {
            return self.pump_receive(index, backend, network);
        }
        Outcome::Open
    }

    /// Whether a processor call of the connection runs on another thread.
    /// The platform does not service the socket until it reports the end
    /// of the call with [`Server::complete_processor_call`].
    pub fn awaits_processor(&self, index: ConnectionIndex) -> bool {
        self.connection(index)
            .is_some_and(|connection| connection.processor_call.is_some())
    }

    /// A processor call that reported [`ProcessorProgress::Running`] ended:
    /// the server repeats the call, which now returns its results, and
    /// continues the connection. A connection closed meanwhile is ignored.
    pub fn complete_processor_call(
        &mut self,
        index: ConnectionIndex,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let Some(connection) = self
            .connections
            .get_mut(index.0 as usize)
            .and_then(Option::as_mut)
        else {
            return Outcome::Released;
        };
        match connection.processor_call.take() {
            None => Outcome::Open,
            Some(PendingCall::Command { call, processor }) => {
                self.text.clear();
                let mut external = None;
                let session = &mut connection.session;
                let progress = backend.call_processor(
                    call,
                    &[],
                    &mut self.text,
                    &mut external,
                    &mut session.receive_remaining,
                );
                let result = match progress {
                    ProcessorProgress::Complete(result) => {
                        processor_result(session, backend, processor, result)
                    }
                    ProcessorProgress::Running => {
                        connection.processor_call = Some(PendingCall::Command { call, processor });
                        return Outcome::Open;
                    }
                    ProcessorProgress::Unavailable => {
                        Err(ErrorCode::DedicatedConnectionRequired.into())
                    }
                };
                self.reply(index, result, external, backend, network)
            }
            Some(PendingCall::Send) => self.on_writable(index, backend, network),
            Some(PendingCall::Receive { closed }) => {
                self.continue_receive(index, 0, closed, backend, network)
            }
        }
    }

    fn apply_request(
        &mut self,
        index: ConnectionIndex,
        request: Option<SessionRequest>,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Outcome {
        let slot = index.0 as usize;
        match request {
            None => Outcome::Open,
            Some(SessionRequest::Reboot(kind)) => {
                self.save_settings_if_dirty(backend);
                self.state
                    .notifications
                    .deliver(&Event::Execution(ExecutionState::Rebooting), network);
                for index in 0..MAX_CONNECTIONS {
                    self.close(ConnectionIndex(index as u8), network);
                }
                self.state.notifications.close_all(network);
                backend.reboot(kind);
                Outcome::Released
            }
            Some(SessionRequest::Close) => {
                self.close(index, network);
                Outcome::Released
            }
            Some(SessionRequest::ReleaseSocket) => {
                self.connections[slot] = None;
                Outcome::Released
            }
            Some(SessionRequest::Dedicate(target)) => {
                let flags = match target {
                    DedicateTarget::Main => ProcessorFlags::empty(),
                    DedicateTarget::Processor(processor_index) => backend
                        .processor(processor_index)
                        .map_or(ProcessorFlags::empty(), |p| p.flags),
                };
                let Some(connection) = self.connections[slot].as_mut() else {
                    return Outcome::Released;
                };
                if send_line(
                    network,
                    connection.session.socket,
                    b"205- connection dedicated",
                )
                .is_err()
                {
                    self.close(index, network);
                    return Outcome::Released;
                }
                match target {
                    DedicateTarget::Main => {
                        connection.owner = Owner::Main;
                        connection.processor = None;
                        connection.title_process = false;
                    }
                    DedicateTarget::Processor(processor_index) => {
                        connection.processor = Some(processor_index);
                        connection.title_process = flags.contains(ProcessorFlags::TITLE);
                        connection.owner = if flags.contains(ProcessorFlags::DEDICATED_THREAD) {
                            Owner::Processor(processor_index)
                        } else if flags.contains(ProcessorFlags::TITLE) {
                            Owner::Title
                        } else {
                            Owner::Unserviced
                        };
                    }
                }
                Outcome::Open
            }
        }
    }
}

/// Map a processor's result: 0 reports success, and 205 dedicates the
/// connection to the processor.
fn processor_result(
    session: &mut Session,
    backend: &mut dyn Backend,
    processor: u8,
    result: Hresult,
) -> CommandResult {
    if result == Hresult::NO_REPLY {
        Ok(Reply::Ok)
    } else if result == Hresult::DEDICATED {
        // The dedicate routine fails for a processor unregistered meanwhile.
        if backend.processor(processor).is_none() {
            return Err(CommandError::Fail);
        }
        session.request(SessionRequest::Dedicate(DedicateTarget::Processor(
            processor,
        )));
        Ok(Reply::Sent)
    } else {
        reply::from_processor(result)
    }
}

fn finish_transfer(connection: &mut Connection) {
    connection.transfer = Transfer::Idle;
    connection.session.continuation = Continuation::None;
    connection.session.receive_remaining = None;
}

/// Put a continuation back unless the call replaced it or ended the transfer.
fn restore_continuation(connection: &mut Connection, continuation: Continuation) {
    if connection.transfer != Transfer::Idle && connection.session.continuation.is_none() {
        connection.session.continuation = continuation;
    }
}

/// Position of the first CR at or after `from` that is followed by at
/// least one more byte.
fn find_terminator(bytes: &[u8], from: usize) -> Option<usize> {
    (from..bytes.len().saturating_sub(1)).find(|&index| bytes[index] == b'\r')
}

/// Send `NNN- text`, using the default text for `result` when `text` is
/// empty. The digits follow the monitor's line builder (0x91f42028), which
/// also traces the line.
pub(crate) fn send_status(
    state: &ServerState,
    backend: &mut dyn Backend,
    network: &mut dyn Network,
    socket: SocketId,
    result: CommandResult,
    text: &[u8],
) -> Result<(), crate::network::NetError> {
    let result = reply::hresult(result);
    let [first, second, third] = result.status_digits();
    let head = [first, second, third, b'-', b' '];
    let message = if text.is_empty() {
        result.default_message().as_bytes()
    } else {
        text
    };
    trace_thread(
        state,
        backend,
        TraceMask::REPLIES,
        format_args!("R="),
        &[&head, message],
    );
    send_all(network, socket, &head)?;
    send_line(network, socket, message)
}

/// DbgPrint `XBDM(thr=0x%0.8x): ` followed by `head` and `parts` up to the
/// first NUL, as the `%s` arguments of the monitor's texts print them.
fn trace_thread(
    state: &ServerState,
    backend: &mut dyn Backend,
    bits: TraceMask,
    head: core::fmt::Arguments<'_>,
    parts: &[&[u8]],
) {
    let mask = state.console.trace_mask;
    if !mask.contains(bits) {
        return;
    }
    let thread = console::Backend::current_thread(backend);
    console::trace_text(mask, backend, bits, |message| {
        let _ = write!(message, "XBDM(thr=0x{thread:08x}): {head}");
        for part in parts {
            let text = console::c_string(part);
            let _ = message.push_bytes(text);
            if text.len() != part.len() {
                break;
            }
        }
        let _ = message.write_str("\n");
    });
}
