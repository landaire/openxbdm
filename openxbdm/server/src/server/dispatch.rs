//! Command dispatch: built-in handlers, external processors, and the
//! requests handlers make of their connection.

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

use super::MAX_CONNECTIONS;
use super::Outcome;
use super::Owner;
use super::PendingCall;
use super::Server;
use super::Transfer;
use super::send_status;
use super::trace_thread;
use crate::access::Access;
use crate::backend::Backend;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::continuation::Continuation;
use crate::invocation::ConnectionIndex;
use crate::invocation::DedicateTarget;
use crate::invocation::Invocation;
use crate::invocation::Session;
use crate::invocation::SessionRequest;
use crate::network::Network;
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

impl Server {
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
                let _ = call_handler(entry, &mut invocation);
            }
        }

        self.save_settings_if_dirty(backend);
    }

    /// Execute the command line in `self.line[..length]` for a connection.
    pub(super) fn dispatch(
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

                    call_handler(entry, &mut invocation)
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
                .is_some_and(|connection| connection.session.receive_remaining == Some(0))
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
                        .map_or(ProcessorFlags::empty(), |processor| processor.flags),
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

/// Call the handler of `entry`. A handler with dispatch flag 0x4 runs on a
/// thread of its own (stock 0x91f421c8). Stock zeroes the result slot
/// before it creates the thread, so a thread that ends without returning
/// from the handler gives result 0, which sends no status line.
fn call_handler(entry: &registry::CommandEntry, invocation: &mut Invocation<'_>) -> CommandResult {
    if !entry.flags().contains(DispatchFlags::OWN_THREAD) {
        return (entry.handler)(invocation);
    }

    let Invocation {
        line,
        buffer,
        text,
        session,
        state,
        backend,
        network,
    } = invocation;
    let mut result = None;
    let ran = backend.run_command_thread(&mut |backend| {
        let mut invocation = Invocation {
            line: *line,
            buffer,
            text,
            session: session.as_deref_mut(),
            state,
            backend,
            network: &mut **network,
        };
        result = Some((entry.handler)(&mut invocation));
    });

    match ran {
        Ok(()) => result.unwrap_or(Ok(Reply::Sent)),
        Err(status) => Err(CommandError::CommandThread(status)),
    }
}
