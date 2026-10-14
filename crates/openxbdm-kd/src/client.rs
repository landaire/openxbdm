//! Blocking kernel debugger client.

use std::time::Duration;
use std::time::Instant;

use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::context::CONTEXT_LEN;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::context_chunks;
use openxbdm_kd_core::manipulate::BreakpointHandle;
use openxbdm_kd_core::manipulate::ContinueDisposition;
use openxbdm_kd_core::manipulate::Processor;
use openxbdm_kd_core::manipulate::Request;
use openxbdm_kd_core::manipulate::Version;
use openxbdm_kd_core::packet::BREAK_IN;
use openxbdm_kd_core::packet::MAX_DATAGRAM_LEN;

use crate::error::KdError;
use crate::host_files::HostFiles;
use crate::link::Incoming;
use crate::link::Link;
use crate::link::NotifyFn;
use crate::link::Outbox;
use crate::link::OwnedReply;
use crate::ops;
use crate::step;
use crate::stop::StopReport;
use crate::transport::DatagramTransport;

/// Kernel retransmission interval; the host uses the same.
pub const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const RESET_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

pub type TraceFn = Box<dyn FnMut(Direction, &[u8]) + Send>;

pub struct KdClient<T: DatagramTransport> {
    transport: T,
    link: Link,
    trace: Option<TraceFn>,
    buffer: Box<[u8; MAX_DATAGRAM_LEN]>,
}

impl<T: DatagramTransport> KdClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            link: Link::new(),
            trace: None,
            buffer: Box::new([0; MAX_DATAGRAM_LEN]),
        }
    }

    pub fn set_notify(&mut self, notify: NotifyFn) {
        self.link.notify = Some(notify);
    }

    /// Serves the kernel's host file requests from `files`. Without it
    /// every request is answered as not found.
    pub fn set_host_files(&mut self, files: HostFiles) {
        self.link.files = files;
    }

    /// Image names whose load-symbols event is kept as a stop, so the image
    /// can be inspected and patched before it runs.
    pub fn set_hold_loads(&mut self, names: Vec<String>) {
        self.link.hold_loads = names;
    }

    pub fn set_trace(&mut self, trace: TraceFn) {
        self.trace = Some(trace);
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The stop the kernel is waiting in, if any.
    pub fn stop(&self) -> Option<&StopReport> {
        self.link.stop.as_ref()
    }

    fn transmit(&mut self, datagram: &[u8]) -> Result<(), KdError> {
        if let Some(trace) = self.trace.as_mut() {
            trace(Direction::Sent, datagram);
        }
        self.transport.send(datagram)?;
        Ok(())
    }

    fn flush(&mut self, outbox: Outbox) -> Result<(), KdError> {
        if let Some(control) = outbox.control {
            self.transmit(&control)?;
        }
        if outbox.outstanding {
            self.retransmit()?;
        }
        Ok(())
    }

    fn retransmit(&mut self) -> Result<(), KdError> {
        let Self {
            transport,
            link,
            trace,
            ..
        } = self;
        if let Some(datagram) = link.session.retransmission() {
            if let Some(trace) = trace.as_mut() {
                trace(Direction::Sent, datagram);
            }
            transport.send(datagram)?;
        }
        Ok(())
    }

    /// Requests a break-in. The kernel stops at its next poll and sends an
    /// exception state change.
    pub fn break_in(&mut self) -> Result<(), KdError> {
        self.transmit(&BREAK_IN)
    }

    /// Receives and handles one datagram.
    fn pump(&mut self, timeout: Duration) -> Result<Option<Incoming>, KdError> {
        let Some(length) = self.transport.recv(&mut self.buffer[..], timeout)? else {
            return Ok(None);
        };
        if let Some(trace) = self.trace.as_mut() {
            trace(Direction::Received, &self.buffer[..length]);
        }
        let mut outbox = Outbox::default();
        let incoming = self
            .link
            .handle_datagram(&self.buffer[..length], &mut outbox)?;
        self.flush(outbox)?;
        Ok(incoming)
    }

    /// Pumps for one interval and retransmits the outstanding packet when
    /// it is due.
    fn pump_retransmitting(
        &mut self,
        deadline: Instant,
        last_send: &mut Instant,
    ) -> Result<Option<Incoming>, KdError> {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(RETRANSMIT_INTERVAL);
        let incoming = self.pump(slice)?;
        if self.link.session.outstanding().is_some() && last_send.elapsed() >= RETRANSMIT_INTERVAL {
            self.retransmit()?;
            *last_send = Instant::now();
        }
        Ok(incoming)
    }

    /// Handles traffic for up to `timeout` while the target runs. Returns
    /// `true` once the kernel waits in a stop.
    pub fn wait_for_stop(&mut self, timeout: Duration) -> Result<bool, KdError> {
        let deadline = Instant::now() + timeout;
        let mut last_send = Instant::now();
        while self.link.stop.is_none() {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            self.pump_retransmitting(deadline, &mut last_send)?;
        }
        if !self.link.synchronized {
            self.synchronize()?;
        }
        Ok(true)
    }

    /// Handles traffic for `timeout` without waiting for a stop, for
    /// example while the kernel waits in a stop for the next request.
    pub fn service(&mut self, timeout: Duration) -> Result<(), KdError> {
        let deadline = Instant::now() + timeout;
        let mut last_send = Instant::now();
        while Instant::now() < deadline {
            self.pump_retransmitting(deadline, &mut last_send)?;
        }
        Ok(())
    }

    /// Resets packet numbering so the kernel's expected id matches the
    /// session. The kernel answers with a reset and repeats its stop.
    fn synchronize(&mut self) -> Result<(), KdError> {
        let deadline = Instant::now() + RESET_TIMEOUT;
        let reset = self.link.session.reset();
        self.transmit(&reset)?;
        let mut last_send = Instant::now();
        while !self.link.synchronized {
            if Instant::now() >= deadline {
                return Err(KdError::Timeout {
                    waiting_for: "reset reply",
                    seconds: RESET_TIMEOUT.as_secs(),
                });
            }
            self.pump(RETRANSMIT_INTERVAL)?;
            if !self.link.synchronized && last_send.elapsed() >= RETRANSMIT_INTERVAL {
                self.transmit(&reset)?;
                last_send = Instant::now();
            }
        }
        Ok(())
    }

    /// Sends a manipulate request for the stopped processor and waits for
    /// its reply.
    pub fn request(&mut self, request: Request, data: &[u8]) -> Result<OwnedReply, KdError> {
        let processor = self
            .link
            .stop
            .as_ref()
            .ok_or(KdError::NotStopped)?
            .processor;
        self.request_on(processor, request, data)
    }

    pub fn request_on(
        &mut self,
        processor: Processor,
        request: Request,
        data: &[u8],
    ) -> Result<OwnedReply, KdError> {
        if self.link.stop.is_none() {
            return Err(KdError::NotStopped);
        }
        let mut outbox = Outbox::default();
        self.link
            .send_request(processor, request, data, &mut outbox)?;
        self.flush(outbox)?;
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut last_send = Instant::now();
        loop {
            if Instant::now() >= deadline {
                self.link.session.abandon();
                return Err(KdError::Timeout {
                    waiting_for: "manipulate reply",
                    seconds: REQUEST_TIMEOUT.as_secs(),
                });
            }
            if let Some(Incoming::Reply(reply)) =
                self.pump_retransmitting(deadline, &mut last_send)?
            {
                return ops::matching_reply(request, reply);
            }
        }
    }

    fn await_acknowledge(&mut self, waiting_for: &'static str) -> Result<(), KdError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut last_send = Instant::now();
        while self.link.session.outstanding().is_some() {
            if Instant::now() >= deadline {
                self.link.session.abandon();
                return Err(KdError::Timeout {
                    waiting_for,
                    seconds: REQUEST_TIMEOUT.as_secs(),
                });
            }
            self.pump_retransmitting(deadline, &mut last_send)?;
        }
        Ok(())
    }

    /// Ends the stop and lets the kernel run.
    pub fn resume(&mut self, disposition: ContinueDisposition) -> Result<(), KdError> {
        let stop = self.link.stop.take().ok_or(KdError::NotStopped)?;
        let mut outbox = Outbox::default();
        self.link.send_request(
            stop.processor,
            Request::Continue { disposition },
            &[],
            &mut outbox,
        )?;
        self.flush(outbox)?;
        self.await_acknowledge("continue acknowledgement")
    }

    /// Resumes from the current stop the way a debugger user expects: a
    /// trap instruction at the program counter is stepped over, and other
    /// exceptions go to the kernel's exception dispatch.
    pub fn continue_from_stop(&mut self) -> Result<(), KdError> {
        let stop = self.link.stop.as_ref().ok_or(KdError::NotStopped)?;
        let processor = stop.processor;
        let pc = stop.pc();
        let code = stop.exception.map(|exception| exception.record.code);
        let disposition = match code {
            Some(NtStatus::BREAKPOINT) => {
                let mut word = [0u8; 4];
                let read = self.read_memory(u64::from(pc), &mut word)?;
                if read == 4 && step::is_unconditional_trap(u32::from_be_bytes(word)) {
                    let mut context = self.read_context(processor)?;
                    context.set_iar(pc.wrapping_add(4));
                    self.write_context(processor, &context)?;
                }
                ContinueDisposition::Handled
            }
            Some(NtStatus::SINGLE_STEP) | None => ContinueDisposition::Handled,
            Some(_) => ContinueDisposition::NotHandled,
        };
        self.resume(disposition)
    }

    pub fn reboot(&mut self) -> Result<(), KdError> {
        let stop = self.link.stop.take().ok_or(KdError::NotStopped)?;
        let mut outbox = Outbox::default();
        self.link
            .send_request(stop.processor, Request::Reboot, &[], &mut outbox)?;
        self.flush(outbox)?;
        self.await_acknowledge("reboot acknowledgement")
    }

    pub fn version(&mut self) -> Result<Version, KdError> {
        let reply = self.request(Request::GetVersion, &[])?;
        ops::version(&reply)
    }

    /// Reads up to `buffer.len()` bytes. Returns the number read, which is
    /// short when the range reaches unmapped memory.
    pub fn read_memory(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize, KdError> {
        let mut done = 0;
        while let Some(request) = ops::read_memory_request(address, buffer.len(), done) {
            let reply = self.request(request, &[])?;
            let copied = ops::copy_read_memory(&reply, request, &mut buffer[done..])?;
            done += copied;
            if !ops::read_complete(request, copied) {
                break;
            }
        }
        Ok(done)
    }

    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), KdError> {
        for (request, chunk) in ops::write_memory_requests(address, bytes) {
            let reply = self.request(request, chunk)?;
            ops::check_write_memory(&reply, chunk.len())?;
        }
        Ok(())
    }

    pub fn read_context(&mut self, processor: Processor) -> Result<Context, KdError> {
        let mut bytes = [0u8; CONTEXT_LEN];
        for chunk in context_chunks() {
            let request = Request::ReadContextRange {
                offset: chunk.offset,
                length: chunk.length,
            };
            let reply = self.request_on(processor, request, &[])?;
            ops::copy_context_range(&reply, chunk, &mut bytes)?;
        }
        Ok(Context::from_bytes(bytes))
    }

    /// Writes the whole context. The kernel commits it when the final
    /// range arrives.
    pub fn write_context(
        &mut self,
        processor: Processor,
        context: &Context,
    ) -> Result<(), KdError> {
        for chunk in context_chunks() {
            let (request, data) = ops::write_context_request(context, chunk);
            let reply = self.request_on(processor, request, data)?;
            ops::check_status(&reply.reply())?;
        }
        Ok(())
    }

    pub fn add_breakpoint(&mut self, address: u64) -> Result<BreakpointHandle, KdError> {
        ops::check_breakpoint_address(address)?;
        let reply = self.request(Request::WriteBreakpoint { address }, &[])?;
        ops::breakpoint_handle(&reply, address)
    }

    pub fn remove_breakpoint(&mut self, handle: BreakpointHandle) -> Result<(), KdError> {
        let reply = self.request(Request::RestoreBreakpoint { handle }, &[])?;
        ops::check_status(&reply.reply())
    }
}
