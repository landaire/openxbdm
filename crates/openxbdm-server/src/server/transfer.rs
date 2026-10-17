//! 202, 203, and 204 transfers after the reply line.

use openxbdm_core::status::XbdmHresult;

use super::Connection;
use super::Outcome;
use super::PendingCall;
use super::Server;
use super::TRANSFER_CAPACITY;
use super::Transfer;
use super::send_status;
use super::trace_thread;
use crate::backend::Backend;
use crate::commands::console::TraceMask;
use crate::continuation;
use crate::continuation::Continuation;
use crate::continuation::ContinuationContext;
use crate::invocation::ConnectionIndex;
use crate::network::Network;
use crate::network::send_all;
use crate::network::send_line;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

impl Server {
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

    pub(super) fn pump_receive(
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
    pub(super) fn continue_receive(
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
        let transfer = match result {
            Ok(Reply::Multiline) => Transfer::Multiline,
            Ok(Reply::Binary) => Transfer::BinarySend,
            _ => Transfer::Idle,
        };
        connection.transfer = transfer;
        if transfer == Transfer::Idle && result != Ok(Reply::FastPipe) {
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
