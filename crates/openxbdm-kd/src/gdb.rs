//! GDB remote serial protocol server backed by the kernel debugger.
//!
//! The target is presented as one 64-bit big-endian PowerPC thread: the
//! processor that reported the stop. Register numbering follows the
//! target description: r0-r31, f0-f31, pc, msr, cr, lr, ctr, xer, fpscr.

mod arch;

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use gdbstub::common::Signal;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::DisconnectReason;
use gdbstub::stub::GdbStub;
use gdbstub::stub::GdbStubError;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::stub::run_blocking;
use gdbstub::target::Target;
use gdbstub::target::TargetError;
use gdbstub::target::TargetResult;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::singlethread::SingleThreadBase;
use gdbstub::target::ext::base::singlethread::SingleThreadResume;
use gdbstub::target::ext::base::singlethread::SingleThreadResumeOps;
use gdbstub::target::ext::base::singlethread::SingleThreadSingleStep;
use gdbstub::target::ext::base::singlethread::SingleThreadSingleStepOps;
use gdbstub::target::ext::breakpoints::Breakpoints;
use gdbstub::target::ext::breakpoints::BreakpointsOps;
use gdbstub::target::ext::breakpoints::SwBreakpoint;
use gdbstub::target::ext::breakpoints::SwBreakpointOps;
use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::Fpr;
use openxbdm_kd_core::context::Gpr;
use openxbdm_kd_core::manipulate::ApiNumber;
use openxbdm_kd_core::manipulate::BreakpointHandle;
use openxbdm_kd_core::manipulate::ContinueDisposition;

use crate::client::KdClient;
use crate::error::KdError;
use crate::step;
use crate::step::StepPlan;
use crate::stop::StopReport;
use crate::transport::DatagramTransport;

pub use self::arch::Xenon;
pub use self::arch::XenonRegisters;

pub struct KdTarget<T>
where
    T: DatagramTransport,
{
    client: KdClient<T>,

    context: Option<Context>,
    context_dirty: bool,

    breakpoints: Vec<InsertedBreakpoint>,
    step_breakpoints: Vec<InsertedBreakpoint>,
    pending: Pending,
}

impl<T> KdTarget<T>
where
    T: DatagramTransport,
{
    /// `client` must be stopped.
    pub fn new(client: KdClient<T>) -> Result<Self, KdError> {
        if client.stop().is_none() {
            return Err(KdError::NotStopped);
        }

        Ok(Self {
            client,
            context: None,
            context_dirty: false,
            breakpoints: Vec::new(),
            step_breakpoints: Vec::new(),
            pending: Pending::Stopped,
        })
    }

    pub fn into_client(self) -> KdClient<T> {
        self.client
    }

    fn stop(&self) -> Result<&StopReport, KdError> {
        self.client.stop().ok_or(KdError::NotStopped)
    }

    fn context(&mut self) -> Result<&mut Context, KdError> {
        if self.context.is_none() {
            let processor = self.stop()?.processor;
            self.context = Some(self.client.read_context(processor)?);
            self.context_dirty = false;
        }

        match self.context.as_mut() {
            Some(context) => Ok(context),
            None => unreachable!("context loaded above"),
        }
    }

    fn flush_context(&mut self) -> Result<(), KdError> {
        if !self.context_dirty {
            return Ok(());
        }

        let Some(context) = self.context.as_ref() else {
            return Ok(());
        };

        let processor = self.stop()?.processor;
        self.client.write_context(processor, context)?;
        self.context_dirty = false;

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

    /// The stop is a trap instruction the session did not insert.
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

    fn advance_pc(&mut self) -> Result<(), KdError> {
        let context = self.context()?;
        let next = context.iar().wrapping_add(4);
        context.set_iar(next);
        self.context_dirty = true;

        Ok(())
    }

    fn resume_kernel(&mut self, disposition: ContinueDisposition) -> Result<(), KdError> {
        if self.stopped_on_foreign_trap()? {
            self.advance_pc()?;
        }

        self.reinsert_breakpoints()?;
        self.flush_context()?;
        self.context = None;

        self.client.resume(disposition)
    }

    /// Marks breakpoints inside the reported instruction bytes as removed.
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

    /// Restores breakpoints the kernel removed, except at the program
    /// counter, which would stop again at once.
    fn reinsert_breakpoints(&mut self) -> Result<(), KdError> {
        let pc = self.context()?.iar();

        for idx in 0..self.breakpoints.len() {
            let address = self.breakpoints[idx].address;
            if self.breakpoints[idx].handle.is_some() || address == pc {
                continue;
            }

            self.breakpoints[idx].handle = Some(self.client.add_breakpoint(u64::from(address))?);
        }

        Ok(())
    }

    fn begin_step(&mut self) -> Result<(), KdError> {
        let context = self.context()?;
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
                self.context()?.set_iar(next);
                self.context_dirty = true;
                self.pending = Pending::StepDone;
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

                self.flush_context()?;
                self.context = None;
                self.client.resume(ContinueDisposition::Handled)?;
                self.pending = Pending::Stepping;
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

    /// Translates the kernel's stop into a GDB stop reason.
    fn stop_reason(&mut self) -> Result<SingleThreadStopReason<u64>, KdError> {
        let pending = std::mem::replace(&mut self.pending, Pending::Stopped);
        self.note_kernel_removed()?;

        let stop = self.stop()?.clone();
        let pc = stop.pc();
        let was_step_target = self
            .step_breakpoints
            .iter()
            .any(|inserted| inserted.address == pc);
        self.remove_step_breakpoints()?;

        let code = stop.exception.map(|exception| exception.record.code);
        let reason = match code {
            Some(NtStatus::BREAKPOINT) if self.is_inserted(pc) => {
                SingleThreadStopReason::SwBreak(())
            }
            Some(NtStatus::BREAKPOINT) if pending == Pending::Stepping && was_step_target => {
                SingleThreadStopReason::DoneStep
            }
            Some(NtStatus::BREAKPOINT) if pending == Pending::Interrupted => {
                SingleThreadStopReason::Signal(Signal::SIGINT)
            }
            Some(NtStatus::BREAKPOINT) => SingleThreadStopReason::Signal(Signal::SIGTRAP),
            Some(NtStatus::ACCESS_VIOLATION) => SingleThreadStopReason::Signal(Signal::SIGSEGV),
            Some(NtStatus::ILLEGAL_INSTRUCTION) => SingleThreadStopReason::Signal(Signal::SIGILL),
            _ => SingleThreadStopReason::Signal(Signal::SIGTRAP),
        };

        Ok(reason)
    }

    /// Removes session breakpoints and lets the console run. Called when
    /// the GDB client detaches or the connection ends.
    pub fn release(&mut self) -> Result<(), KdError> {
        // A break-in request that reaches a stopped kernel is latched and
        // stops it again after the continue, so wait for a pending stop first.
        if !self.client.wait_for_stop(Duration::from_millis(1200))? {
            self.client.break_in()?;

            if !self.client.wait_for_stop(Duration::from_secs(5))? {
                return Err(KdError::Timeout {
                    waiting_for: "stop for detach",
                    seconds: 5,
                });
            }
        }

        self.pending = Pending::Stopped;
        self.note_kernel_removed()?;

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

        self.resume_kernel(ContinueDisposition::Handled)
    }
}

impl<T> Target for KdTarget<T>
where
    T: DatagramTransport,
{
    type Arch = Xenon;
    type Error = KdError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl<T> SingleThreadBase for KdTarget<T>
where
    T: DatagramTransport,
{
    fn read_registers(&mut self, regs: &mut XenonRegisters) -> TargetResult<(), Self> {
        let context = self.context().map_err(fatal::<T>)?;

        for idx in 0..32u8 {
            let Some(gpr) = Gpr::new(idx) else {
                unreachable!("index below 32")
            };
            let Some(fpr) = Fpr::new(idx) else {
                unreachable!("index below 32")
            };

            regs.gpr[usize::from(idx)] = context.gpr(gpr);
            regs.fpr[usize::from(idx)] = context.fpr(fpr);
        }

        regs.pc = u64::from(context.iar());
        regs.msr = u64::from(context.msr());
        regs.cr = context.cr();
        regs.lr = u64::from(context.lr());
        regs.ctr = context.ctr();
        regs.xer = context.xer();
        regs.fpscr = context.fpscr();

        Ok(())
    }

    fn write_registers(&mut self, regs: &XenonRegisters) -> TargetResult<(), Self> {
        let context = self.context().map_err(fatal::<T>)?;

        for idx in 0..32u8 {
            let Some(gpr) = Gpr::new(idx) else {
                unreachable!("index below 32")
            };
            let Some(fpr) = Fpr::new(idx) else {
                unreachable!("index below 32")
            };

            context.set_gpr(gpr, regs.gpr[usize::from(idx)]);
            context.set_fpr(fpr, regs.fpr[usize::from(idx)]);
        }

        // IAR, MSR and LR are 32-bit fields of the context record.
        context.set_iar(regs.pc as u32);
        context.set_msr(regs.msr as u32);
        context.set_cr(regs.cr);
        context.set_lr(regs.lr as u32);
        context.set_ctr(regs.ctr);
        context.set_xer(regs.xer);
        context.set_fpscr(regs.fpscr);
        self.context_dirty = true;

        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
        match self.client.read_memory(start_addr, data) {
            Ok(0) => Err(TargetError::NonFatal),
            Ok(read) => Ok(read),
            Err(error) => Err(fatal::<T>(error)),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
        match self.client.write_memory(start_addr, data) {
            Ok(()) => Ok(()),
            Err(KdError::ShortTransfer { .. }) => Err(TargetError::NonFatal),
            Err(error) => Err(fatal::<T>(error)),
        }
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<T> SingleThreadResume for KdTarget<T>
where
    T: DatagramTransport,
{
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        // A signal GDB passes back is an exception left to the kernel's
        // exception dispatch.
        let disposition = match signal {
            None | Some(Signal::SIGTRAP) | Some(Signal::SIGINT) => ContinueDisposition::Handled,
            Some(_) => ContinueDisposition::NotHandled,
        };

        self.resume_kernel(disposition)?;
        self.pending = Pending::Running;

        Ok(())
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl<T> SingleThreadSingleStep for KdTarget<T>
where
    T: DatagramTransport,
{
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        if self.stopped_on_foreign_trap()? {
            // The trap at the program counter is the instruction to step.
            self.advance_pc()?;
            self.pending = Pending::StepDone;
            return Ok(());
        }

        self.begin_step()
    }
}

impl<T> Breakpoints for KdTarget<T>
where
    T: DatagramTransport,
{
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<T> SwBreakpoint for KdTarget<T>
where
    T: DatagramTransport,
{
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let address = addr as u32;
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
            Err(error) => Err(fatal::<T>(error)),
        }
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let address = addr as u32;
        let Some(position) = self
            .breakpoints
            .iter()
            .position(|inserted| inserted.address == address)
        else {
            return Ok(false);
        };

        let inserted = self.breakpoints.remove(position);
        if let Some(handle) = inserted.handle {
            self.client.remove_breakpoint(handle).map_err(fatal::<T>)?;
        }

        Ok(true)
    }
}

pub enum KdEventLoop<T> {
    #[doc(hidden)]
    Unused(std::convert::Infallible, std::marker::PhantomData<T>),
}

impl<T> run_blocking::BlockingEventLoop for KdEventLoop<T>
where
    T: DatagramTransport,
{
    type Target = KdTarget<T>;
    type Connection = TcpStream;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut KdTarget<T>,
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
                Pending::StepDone => {
                    target.pending = Pending::Stopped;
                    return Ok(run_blocking::Event::TargetStopped(
                        SingleThreadStopReason::DoneStep,
                    ));
                }
                Pending::Stopped => {
                    let reason = target.stop_reason().map_err(WaitError::Target)?;
                    return Ok(run_blocking::Event::TargetStopped(reason));
                }
                // The target runs; poll the kernel and the connection below.
                Pending::Running | Pending::Interrupted | Pending::Stepping => {}
            }

            if target
                .client
                .wait_for_stop(POLL_SLICE)
                .map_err(WaitError::Target)?
            {
                let reason = target.stop_reason().map_err(WaitError::Target)?;
                return Ok(run_blocking::Event::TargetStopped(reason));
            }

            if conn.peek().map_err(WaitError::Connection)?.is_some() {
                let byte = conn.read().map_err(WaitError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(target: &mut KdTarget<T>) -> Result<Option<Self::StopReason>, KdError> {
        if target.client.stop().is_none() {
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
    /// Running to the step breakpoints.
    Stepping,
    /// A step that completed without running.
    StepDone,
}

#[derive(Debug)]
struct InsertedBreakpoint {
    address: u32,
    /// `None` once the kernel removed the breakpoint itself: building a
    /// stop report (0x801b6618) removes every breakpoint in the reported
    /// instruction bytes.
    handle: Option<BreakpointHandle>,
}

/// Serves one GDB client on `stream`, then detaches from the console.
pub fn serve<T>(
    target: &mut KdTarget<T>,
    stream: TcpStream,
) -> Result<DisconnectReason, GdbStubError<KdError, io::Error>>
where
    T: DatagramTransport,
{
    let gdb = GdbStub::new(stream);

    gdb.run_blocking::<KdEventLoop<T>>(target)
}

fn fatal<T>(error: KdError) -> TargetError<<KdTarget<T> as Target>::Error>
where
    T: DatagramTransport,
{
    TargetError::Fatal(error)
}
