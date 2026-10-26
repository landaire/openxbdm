//! GDB remote serial protocol server backed by the kernel debugger.
//!
//! Every processor (hardware thread) is a GDB thread whose id is the
//! processor number plus one. A stop freezes all processors, and the kernel
//! serves requests on one of them; reading the registers of another
//! processor makes the kernel switch to it. The processor that reported
//! the stop resumes the console, so the server switches back to it first.
//!
//! While the console runs, its debug output and module loads reach the
//! debugger console as `O` packets.

mod arch;

use std::io;
use std::io::Write;
use std::marker::PhantomData;
use std::net::TcpStream;
use std::num::NonZeroUsize;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use gdbstub::common::Signal;
use gdbstub::common::Tid;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::DisconnectReason;
use gdbstub::stub::GdbStub;
use gdbstub::stub::GdbStubError;
use gdbstub::stub::MultiThreadStopReason;
use gdbstub::stub::run_blocking;
use gdbstub::target::Target;
use gdbstub::target::TargetError;
use gdbstub::target::TargetResult;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::multithread::MultiThreadBase;
use gdbstub::target::ext::base::multithread::MultiThreadResume;
use gdbstub::target::ext::base::multithread::MultiThreadResumeOps;
use gdbstub::target::ext::base::multithread::MultiThreadSchedulerLocking;
use gdbstub::target::ext::base::multithread::MultiThreadSchedulerLockingOps;
use gdbstub::target::ext::base::multithread::MultiThreadSingleStep;
use gdbstub::target::ext::base::multithread::MultiThreadSingleStepOps;
use gdbstub::target::ext::breakpoints::Breakpoints;
use gdbstub::target::ext::breakpoints::BreakpointsOps;
use gdbstub::target::ext::breakpoints::SwBreakpoint;
use gdbstub::target::ext::breakpoints::SwBreakpointOps;
use gdbstub::target::ext::thread_extra_info::ThreadExtraInfo;
use gdbstub::target::ext::thread_extra_info::ThreadExtraInfoOps;
use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::manipulate::ApiNumber;
use openxbdm_kd_core::manipulate::BreakpointHandle;
use openxbdm_kd_core::manipulate::ContinueDisposition;
use openxbdm_kd_core::manipulate::MAX_PROCESSORS;
use openxbdm_kd_core::manipulate::Processor;

use crate::client::KdClient;
use crate::error::KdError;
use crate::step;
use crate::step::StepPlan;
use crate::stop::StopReport;
use crate::transport::DatagramTransport;

pub use self::arch::ContextRegisters;
pub use self::arch::Registers32;
pub use self::arch::Registers64;
pub use self::arch::Xenon32;
pub use self::arch::Xenon64;
pub use self::arch::XenonArch;

/// Text for the debugger console.
pub type ConsoleText = Vec<u8>;

pub struct KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    client: KdClient<T>,
    /// Processors the kernel reports.
    processors: u16,
    /// The processor whose stop the debugger was told about.
    home: Processor,

    /// Context of the processor the kernel serves requests on.
    context: Option<CachedContext>,

    breakpoints: Vec<InsertedBreakpoint>,
    step_breakpoints: Vec<InsertedBreakpoint>,

    /// Resume request collected from the debugger's actions.
    step_request: Option<Processor>,
    resume_signal: Option<Signal>,
    pending: Pending,

    console: Receiver<ConsoleText>,
    arch: PhantomData<A>,
}

struct CachedContext {
    processor: Processor,
    context: Context,
    dirty: bool,
}

impl<T, A> KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    /// `client` must be stopped. `console` carries text for the debugger
    /// console.
    pub fn new(client: KdClient<T>, console: Receiver<ConsoleText>) -> Result<Self, KdError> {
        let stop = client.stop().ok_or(KdError::NotStopped)?;
        let home = stop.processor;
        let processors = u16::try_from(stop.number_processors)
            .ok()
            .filter(|processors| (1..=MAX_PROCESSORS).contains(processors))
            .ok_or(KdError::ProcessorCount {
                reported: stop.number_processors,
            })?;

        Ok(Self {
            client,
            processors,
            home,
            context: None,
            breakpoints: Vec::new(),
            step_breakpoints: Vec::new(),
            step_request: None,
            resume_signal: None,
            pending: Pending::Stopped,
            console,
            arch: PhantomData,
        })
    }

    pub fn into_client(self) -> KdClient<T> {
        self.client
    }

    fn stop(&self) -> Result<&StopReport, KdError> {
        self.client.stop().ok_or(KdError::NotStopped)
    }

    /// Makes the kernel serve requests on `processor`, writing back the
    /// registers changed on the processor it leaves.
    fn switch_to(&mut self, processor: Processor) -> Result<(), KdError> {
        if self.stop()?.processor == processor {
            return Ok(());
        }

        self.flush_context()?;
        self.context = None;
        self.client.switch_processor(processor)?;
        self.note_kernel_removed()
    }

    fn context(&mut self, processor: Processor) -> Result<&mut Context, KdError> {
        self.switch_to(processor)?;

        if self.context.is_none() {
            let context = self.client.read_context(processor)?;
            self.context = Some(CachedContext {
                processor,
                context,
                dirty: false,
            });
        }

        match self.context.as_mut() {
            Some(cached) => Ok(&mut cached.context),
            None => unreachable!("context loaded above"),
        }
    }

    fn mark_context_dirty(&mut self) {
        if let Some(cached) = self.context.as_mut() {
            cached.dirty = true;
        }
    }

    fn flush_context(&mut self) -> Result<(), KdError> {
        let Some(cached) = self.context.as_mut() else {
            return Ok(());
        };
        if !cached.dirty {
            return Ok(());
        }

        self.client
            .write_context(cached.processor, &cached.context)?;
        cached.dirty = false;

        Ok(())
    }

    fn read_word(&mut self, address: u32) -> Result<Option<u32>, KdError> {
        let mut word = [0u8; 4];
        let read = self.client.read_memory(u64::from(address), &mut word)?;

        Ok((read == 4).then(|| u32::from_be_bytes(word)))
    }

    fn is_inserted(&self, address: u32) -> bool {
        self.breakpoints
            .iter()
            .any(|inserted| inserted.address == address)
    }

    /// The current stop is a trap instruction the session did not insert.
    fn stopped_on_foreign_trap(&mut self) -> Result<bool, KdError> {
        let stop = self.stop()?;
        let is_breakpoint = stop
            .exception
            .is_some_and(|exception| exception.record.code == NtStatus::BREAKPOINT);
        let pc = stop.pc();

        if !is_breakpoint || self.is_inserted(pc) {
            return Ok(false);
        }

        Ok(self.read_word(pc)?.is_some_and(step::is_unconditional_trap))
    }

    /// Marks breakpoints inside the instruction bytes of the current stop
    /// report as removed: building a report (0x801b6618) removes them.
    fn note_kernel_removed(&mut self) -> Result<(), KdError> {
        /// Bytes at the program counter whose breakpoints a stop report removes.
        const REPORTED_INSTRUCTION_BYTES: u32 = 16;

        let pc = self.stop()?.pc();
        let reported = pc..pc.wrapping_add(REPORTED_INSTRUCTION_BYTES);

        for inserted in self
            .breakpoints
            .iter_mut()
            .chain(self.step_breakpoints.iter_mut())
        {
            if reported.contains(&inserted.address) {
                inserted.handle = None;
            }
        }

        Ok(())
    }

    /// Where the processor the kernel serves resumes: the cached context's
    /// IAR, which a register write may have moved, else the reported
    /// program counter. The cache always belongs to that processor.
    fn resume_pc(&self) -> Result<u32, KdError> {
        match &self.context {
            Some(cached) => Ok(cached.context.iar()),
            None => Ok(self.stop()?.pc()),
        }
    }

    /// Restores breakpoints the kernel removed, except where the processor
    /// resumes, which would stop again at once.
    fn reinsert_breakpoints(&mut self) -> Result<(), KdError> {
        let pc = self.resume_pc()?;

        for idx in 0..self.breakpoints.len() + self.step_breakpoints.len() {
            let inserted = match idx.checked_sub(self.breakpoints.len()) {
                None => &self.breakpoints[idx],
                Some(step_idx) => &self.step_breakpoints[step_idx],
            };
            if inserted.handle.is_some() || inserted.address == pc {
                continue;
            }

            let address = inserted.address;
            let handle = Some(self.client.add_breakpoint(u64::from(address))?);
            match idx.checked_sub(self.breakpoints.len()) {
                None => self.breakpoints[idx].handle = handle,
                Some(step_idx) => self.step_breakpoints[step_idx].handle = handle,
            }
        }

        Ok(())
    }

    /// Returns to the processor that reported the stop and lets the console
    /// run. A trap instruction the session did not insert is stepped over
    /// unless the processor already resumes elsewhere: the kernel resumes at
    /// the trap otherwise.
    fn resume_from_home(&mut self, disposition: ContinueDisposition) -> Result<(), KdError> {
        self.switch_to(self.home)?;

        let at_report = self.resume_pc()? == self.stop()?.pc();
        if at_report && self.stopped_on_foreign_trap()? {
            let home = self.home;
            let context = self.context(home)?;
            let next = context.iar().wrapping_add(4);
            context.set_iar(next);
            self.mark_context_dirty();
        }

        self.reinsert_breakpoints()?;
        self.flush_context()?;
        self.context = None;

        self.client.resume(disposition)
    }

    fn begin_step(
        &mut self,
        processor: Processor,
        disposition: ContinueDisposition,
    ) -> Result<(), KdError> {
        let context = self.context(processor)?;
        let pc = context.iar();
        let lr = context.lr();
        let ctr = context.ctr() as u32;

        let Some(instruction) = self.read_word(pc)? else {
            return Err(KdError::ShortTransfer {
                api: ApiNumber::READ_VIRTUAL_MEMORY,
                requested: 4,
                actual: 0,
            });
        };

        match step::plan(pc, instruction, lr, ctr) {
            StepPlan::SkipTrap { next } => {
                self.context(processor)?.set_iar(next);
                self.mark_context_dirty();
                self.pending = Pending::StepDone(processor);
            }
            plan @ StepPlan::Run { .. } => {
                for &address in plan.successors() {
                    if self.is_inserted(address) {
                        continue;
                    }

                    let handle = self.client.add_breakpoint(u64::from(address))?;
                    self.step_breakpoints.push(InsertedBreakpoint {
                        address,
                        handle: Some(handle),
                    });
                }

                self.resume_from_home(disposition)?;
                self.pending = Pending::Running;
            }
        }

        Ok(())
    }

    fn remove_step_breakpoints(&mut self) -> Result<(), KdError> {
        for inserted in std::mem::take(&mut self.step_breakpoints) {
            if let Some(handle) = inserted.handle {
                self.client.remove_breakpoint(handle)?;
            }
        }

        Ok(())
    }

    /// Translates the kernel's new stop into a GDB stop reason.
    fn stop_reason(&mut self) -> Result<MultiThreadStopReason<u64>, KdError> {
        let pending = std::mem::replace(&mut self.pending, Pending::Stopped);
        self.context = None;
        self.note_kernel_removed()?;

        let stop = self.stop()?.clone();
        self.home = stop.processor;
        let tid = thread_id(stop.processor);
        let pc = stop.pc();
        self.remove_step_breakpoints()?;

        let signal = |signal| MultiThreadStopReason::SignalWithThread { tid, signal };
        let code = stop.exception.map(|exception| exception.record.code);
        let reason = match code {
            Some(NtStatus::BREAKPOINT) if self.is_inserted(pc) => {
                MultiThreadStopReason::SwBreak(tid)
            }
            // Every other trap, including a step target that any processor
            // reaches, is a trap of the thread that stopped; the debugger
            // tells a completed step by the thread and the program counter.
            Some(NtStatus::BREAKPOINT) if pending == Pending::Interrupted => signal(Signal::SIGINT),
            Some(NtStatus::BREAKPOINT) => signal(Signal::SIGTRAP),
            Some(NtStatus::ACCESS_VIOLATION) => signal(Signal::SIGSEGV),
            Some(NtStatus::ILLEGAL_INSTRUCTION) => signal(Signal::SIGILL),
            _ => signal(Signal::SIGTRAP),
        };

        Ok(reason)
    }

    /// Removes session breakpoints and lets the console run. Called when
    /// the debugger detaches or the connection ends.
    pub fn release(&mut self) -> Result<(), KdError> {
        // A stop that arrives while the debugger goes away, or that this
        // waits for, was never translated; it decides where the console
        // resumes.
        let unreported = matches!(self.pending, Pending::Running | Pending::Interrupted);

        if self.client.stop().is_none() {
            // A break-in request that reaches a stopped kernel is latched and
            // stops it again after the continue, so wait for a pending stop
            // first.
            if !self.client.wait_for_stop(Duration::from_millis(1200))? {
                self.client.break_in()?;

                if !self.client.wait_for_stop(Duration::from_secs(5))? {
                    return Err(KdError::Timeout {
                        waiting_for: "stop for detach",
                        seconds: 5,
                    });
                }
            }
        }

        if unreported {
            self.pending = Pending::Stopped;
            self.context = None;
            self.home = self.stop()?.processor;
            self.note_kernel_removed()?;
        }

        let step_breakpoints = std::mem::take(&mut self.step_breakpoints);
        let breakpoints = std::mem::take(&mut self.breakpoints);
        for inserted in step_breakpoints.into_iter().chain(breakpoints) {
            let Some(handle) = inserted.handle else {
                continue;
            };

            if let Err(error) = self.client.remove_breakpoint(handle) {
                tracing::warn!(%error, address = inserted.address, "breakpoint removal failed");
            }
        }

        self.resume_from_home(ContinueDisposition::Handled)
    }

    /// Sends pending console text to the debugger. gdbstub leaves the socket
    /// non-blocking after a peek; a packet must not be cut short.
    fn forward_console(&mut self, conn: &mut TcpStream) -> io::Result<()> {
        conn.set_nonblocking(false)?;
        while let Ok(text) = self.console.try_recv() {
            write_console_packets(conn, &text)?;
        }

        Ok(())
    }
}

impl<T, A> Target for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    type Arch = A;
    type Error = KdError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl<T, A> MultiThreadBase for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn read_registers(&mut self, regs: &mut A::Registers, tid: Tid) -> TargetResult<(), Self> {
        let processor = self.processor_of(tid)?;
        let context = self.context(processor).map_err(fatal::<T, A>)?;
        regs.load(context);

        Ok(())
    }

    fn write_registers(&mut self, regs: &A::Registers, tid: Tid) -> TargetResult<(), Self> {
        let processor = self.processor_of(tid)?;
        let context = self.context(processor).map_err(fatal::<T, A>)?;
        regs.store(context);
        self.mark_context_dirty();

        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        match self.client.read_memory(start_addr, data) {
            Ok(0) => Err(TargetError::NonFatal),
            Ok(read) => Ok(read),
            Err(error) => Err(fatal::<T, A>(error)),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        match self.client.write_memory(start_addr, data) {
            Ok(()) => Ok(()),
            Err(KdError::ShortTransfer { .. }) => Err(TargetError::NonFatal),
            Err(error) => Err(fatal::<T, A>(error)),
        }
    }

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        // The first thread answers the debugger's first stop query.
        thread_is_active(thread_id(self.home));
        for processor in (0..self.processors).filter(|processor| *processor != self.home.0) {
            thread_is_active(thread_id(Processor(processor)));
        }

        Ok(())
    }

    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }

    fn support_thread_extra_info(&mut self) -> Option<ThreadExtraInfoOps<'_, Self>> {
        Some(self)
    }
}

impl<T, A> KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn processor_of(&self, tid: Tid) -> TargetResult<Processor, Self> {
        u16::try_from(tid.get() - 1)
            .ok()
            .filter(|processor| *processor < self.processors)
            .map(Processor)
            .ok_or(TargetError::NonFatal)
    }
}

impl<T, A> ThreadExtraInfo for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let text = format!("processor {}", tid.get() - 1);
        let length = text.len().min(buf.len());
        buf[..length].copy_from_slice(&text.as_bytes()[..length]);

        Ok(length)
    }
}

impl<T, A> MultiThreadResume for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn resume(&mut self) -> Result<(), Self::Error> {
        // A signal the debugger passes back is an exception left to the
        // kernel's exception dispatch.
        let disposition = match self.resume_signal.take() {
            None | Some(Signal::SIGTRAP) | Some(Signal::SIGINT) => ContinueDisposition::Handled,
            Some(_) => ContinueDisposition::NotHandled,
        };

        if let Some(processor) = self.step_request.take() {
            return self.begin_step(processor, disposition);
        }

        self.resume_from_home(disposition)?;
        self.pending = Pending::Running;

        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        self.step_request = None;
        self.resume_signal = None;

        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        self.note_resume_signal(tid, signal);

        Ok(())
    }

    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}

/// The kernel resumes every processor on a continue, so a step the
/// debugger asks to run alone still runs with the other processors. They
/// do not stop at a breakpoint the debugger removed for the step.
impl<T, A> MultiThreadSchedulerLocking for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<T, A> KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    /// Only the processor that reported the stop holds an exception, so
    /// only its signal decides the continue disposition.
    fn note_resume_signal(&mut self, tid: Tid, signal: Option<Signal>) {
        if tid == thread_id(self.home) {
            self.resume_signal = signal;
        }
    }
}

impl<T, A> MultiThreadSingleStep for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        let processor = u16::try_from(tid.get() - 1)
            .ok()
            .filter(|processor| *processor < self.processors)
            .map(Processor)
            .ok_or(KdError::NoSuchProcessor { thread: tid.get() })?;

        self.note_resume_signal(tid, signal);
        self.step_request = Some(processor);

        Ok(())
    }
}

impl<T, A> Breakpoints for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<T, A> SwBreakpoint for KdTarget<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let address = instruction_address(addr);
        if self.is_inserted(address) {
            return Ok(true);
        }

        match self.client.add_breakpoint(u64::from(address)) {
            Ok(handle) => {
                self.breakpoints.push(InsertedBreakpoint {
                    address,
                    handle: Some(handle),
                });
                Ok(true)
            }
            Err(KdError::BreakpointRejected { .. } | KdError::UnalignedBreakpoint { .. }) => {
                Ok(false)
            }
            Err(error) => Err(fatal::<T, A>(error)),
        }
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let address = instruction_address(addr);
        let Some(position) = self
            .breakpoints
            .iter()
            .position(|inserted| inserted.address == address)
        else {
            return Ok(false);
        };

        let inserted = self.breakpoints.remove(position);
        if let Some(handle) = inserted.handle {
            self.client
                .remove_breakpoint(handle)
                .map_err(fatal::<T, A>)?;
        }

        Ok(true)
    }
}

pub enum KdEventLoop<T, A> {
    #[doc(hidden)]
    Unused(std::convert::Infallible, PhantomData<(T, A)>),
}

impl<T, A> run_blocking::BlockingEventLoop for KdEventLoop<T, A>
where
    T: DatagramTransport,
    A: XenonArch,
{
    type Target = KdTarget<T, A>;
    type Connection = TcpStream;
    type StopReason = MultiThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut KdTarget<T, A>,
        conn: &mut TcpStream,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<KdError, io::Error>,
    > {
        use run_blocking::WaitForStopReasonError as WaitError;

        /// How long one wait for a stop blocks before checking the GDB connection.
        const POLL_SLICE: Duration = Duration::from_millis(50);

        loop {
            match target.pending {
                Pending::StepDone(processor) => {
                    target.pending = Pending::Stopped;
                    return Ok(run_blocking::Event::TargetStopped(
                        MultiThreadStopReason::SignalWithThread {
                            tid: thread_id(processor),
                            signal: Signal::SIGTRAP,
                        },
                    ));
                }
                Pending::Stopped => {
                    let reason = target.stop_reason().map_err(WaitError::Target)?;
                    return Ok(run_blocking::Event::TargetStopped(reason));
                }
                // The target runs; poll the kernel and the connection below.
                Pending::Running | Pending::Interrupted => {}
            }

            let stopped = target
                .client
                .wait_for_stop(POLL_SLICE)
                .map_err(WaitError::Target)?;

            // The stop is translated before anything can fail on the
            // connection, so that release resumes from the right processor.
            let reason = if stopped {
                Some(target.stop_reason().map_err(WaitError::Target)?)
            } else {
                None
            };
            target
                .forward_console(conn)
                .map_err(WaitError::Connection)?;

            if let Some(reason) = reason {
                return Ok(run_blocking::Event::TargetStopped(reason));
            }

            if conn.peek().map_err(WaitError::Connection)?.is_some() {
                let byte = conn.read().map_err(WaitError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(target: &mut KdTarget<T, A>) -> Result<Option<Self::StopReason>, KdError> {
        // A break-in that reaches a stopped kernel is latched and stops it
        // again after the next continue, so a stop already on its way is
        // awaited first. Longer than the kernel retransmission interval.
        const PENDING_STOP_WAIT: Duration = Duration::from_millis(1200);

        if target.client.stop().is_none() && !target.client.wait_for_stop(PENDING_STOP_WAIT)? {
            target.client.break_in()?;
            target.pending = Pending::Interrupted;
        }

        Ok(None)
    }
}

/// What the target does when gdbstub next waits for a stop.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Pending {
    /// The kernel is stopped; nothing to wait for.
    Stopped,
    Running,
    /// Running after a break-in request.
    Interrupted,
    /// A step of this processor that completed without running.
    StepDone(Processor),
}

#[derive(Debug)]
struct InsertedBreakpoint {
    address: u32,
    /// `None` once the kernel removed the breakpoint itself: building a
    /// stop report (0x801b6618) removes every breakpoint in the reported
    /// instruction bytes.
    handle: Option<BreakpointHandle>,
}

/// Serves one debugger on `stream`. The caller releases the console
/// afterwards ([`KdTarget::release`]).
pub fn serve<T, A>(
    target: &mut KdTarget<T, A>,
    stream: TcpStream,
) -> Result<DisconnectReason, GdbStubError<KdError, io::Error>>
where
    T: DatagramTransport,
    A: XenonArch,
{
    let gdb = GdbStub::new(stream);

    gdb.run_blocking::<KdEventLoop<T, A>>(target)
}

fn thread_id(processor: Processor) -> Tid {
    match NonZeroUsize::new(usize::from(processor.0) + 1) {
        Some(tid) => tid,
        None => unreachable!("a processor number plus one is nonzero"),
    }
}

/// Instruction addresses are 32-bit effective addresses; the kernel
/// reports them sign-extended and a 64-bit debugger may pass either form.
fn instruction_address(address: u64) -> u32 {
    address as u32
}

/// Writes `text` as console output packets (`O` followed by hex digits).
fn write_console_packets(conn: &mut TcpStream, text: &[u8]) -> io::Result<()> {
    /// Text bytes per packet; well below the packet size the stub reports.
    const CHUNK: usize = 256;
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for chunk in text.chunks(CHUNK) {
        let mut packet = Vec::with_capacity(chunk.len() * 2 + 5);
        packet.extend_from_slice(b"$O");
        for &byte in chunk {
            packet.push(HEX[usize::from(byte >> 4)]);
            packet.push(HEX[usize::from(byte & 0xf)]);
        }

        let checksum = packet[1..]
            .iter()
            .fold(0u8, |sum, &byte| sum.wrapping_add(byte));
        packet.push(b'#');
        packet.push(HEX[usize::from(checksum >> 4)]);
        packet.push(HEX[usize::from(checksum & 0xf)]);

        conn.write_all(&packet)?;
    }

    conn.flush()
}

fn fatal<T, A>(error: KdError) -> TargetError<<KdTarget<T, A> as Target>::Error>
where
    T: DatagramTransport,
    A: XenonArch,
{
    TargetError::Fatal(error)
}
