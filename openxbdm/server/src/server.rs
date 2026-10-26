//! Connection engine: accept, line framing, dispatch, and transfers.
//!
//! The engine performs no I/O of its own. The platform reports socket
//! readiness and the engine calls back into [`Network`]. It follows the
//! monitor's framing: one command line is taken per receive, a line ends at
//! CR followed by any byte, and the receive buffer holds 0x200 bytes.
// Abandoned transfer blocks are freed through the unsafe
// `TransferBlocks::abandon`.
#![allow(unsafe_code)]

mod dispatch;
mod transfer;

use core::fmt::Write as _;

use openxbdm_core::status::XbdmHresult;

use crate::access::Access;
use crate::backend::Backend;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::invocation::ConnectionIndex;
use crate::invocation::Session;
use crate::network::NetError;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_all;
use crate::network::send_line;
use crate::notify::Event;
use crate::processors::ProcessorCall;
use crate::reply;
use crate::reply::CommandResult;
use crate::state::ServerState;
use crate::text::LineText;
use crate::text::ResponseText;
use crate::text::Text;

pub const MAX_CONNECTIONS: usize = 8;
/// Receive buffer of a connection; a command line plus CR LF must fit.
pub const RECEIVE_CAPACITY: usize = 0x200;
/// Buffer of 203 output, raw 202 output, and 204 input.
pub const TRANSFER_CAPACITY: usize = 0x1000;

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
                connection.as_ref().map(|connection| {
                    (
                        ConnectionIndex(index as u8),
                        connection.session.socket,
                        connection.owner,
                    )
                })
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

    /// Periodic work: discard notification channel input every 120 seconds,
    /// end the wait for reverse persistent notification targets and drive
    /// the lab server registration. The platform calls this on every pass
    /// of its loop and at least once per second; the result is the
    /// milliseconds until a timer needs it again.
    #[inline(never)]
    pub fn poll_timers(
        &mut self,
        backend: &mut dyn Backend,
        network: &mut dyn Network,
    ) -> Option<u32> {
        let now = crate::commands::console::Backend::tick_milliseconds(backend);
        self.state.notifications.drain_input(now, network);
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
            if matches!(&self.connections[index], Some(connection) if connection.title_process) {
                self.close(ConnectionIndex(index as u8), network);
            }
        }
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
        // Scratch receive size while discarding an overlong line.
        const OVERFLOW_SCRATCH: usize = 0x40;

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
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// Transfer in progress on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    Idle,
    Multiline,
    BinarySend,
    BinaryReceive,
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
) -> Result<(), NetError> {
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
