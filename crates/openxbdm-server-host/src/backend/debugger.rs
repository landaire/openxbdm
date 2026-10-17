//! Simulated threads, debug events, and debugger extensions.
//!
//! Tests raise events with [`Mock::raise_exception`] and friends, then let
//! the server process them; a raised thread stays inside the simulated
//! monitor until the server completes its event.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::Context;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::DebugEvent;
use openxbdm_server::commands::debugger::Delivery;
use openxbdm_server::commands::debugger::DirectException;
use openxbdm_server::commands::debugger::DirectNotice;
use openxbdm_server::commands::debugger::DirectNotification;
use openxbdm_server::commands::debugger::DirectOutcome;
use openxbdm_server::commands::debugger::DirectPolicy;
use openxbdm_server::commands::debugger::DirectRegisters;
use openxbdm_server::commands::debugger::DirectStep;
use openxbdm_server::commands::debugger::Disposition;
use openxbdm_server::commands::debugger::ExceptionRecord;
use openxbdm_server::commands::debugger::ExitStatus;
use openxbdm_server::commands::debugger::ExtensionHandle;
use openxbdm_server::commands::debugger::ModuleEvent;
use openxbdm_server::commands::debugger::Msr;
use openxbdm_server::commands::debugger::NOTICE_TEXT_CAPACITY;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::StoppedThreadError;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::ThreadInfo;
use openxbdm_server::commands::debugger::ThreadName;
use openxbdm_server::commands::debugger::dispatch_direct;
use openxbdm_server::commands::services::ThreadHandle;
use openxbdm_server::notify::ExecutionState;

use super::MockBackend;

/// A simulated kernel thread.
#[derive(Debug, Clone)]
pub struct MockThread {
    pub id: ThreadId,
    pub process: ProcessKind,
    /// Monitor record exists.
    pub has_record: bool,
    /// Monitor record debuggable flag; only these threads are listed,
    /// stopped, and resumed.
    pub debuggable: bool,
    /// Exempt from suspension when execution stops.
    pub exempt: bool,
    pub info: ThreadInfo,
    pub monitor_suspended: bool,
    /// Switch frame of the thread while it is not in the monitor.
    pub frame: Context,
    pub name: Option<Vec<u8>>,
}

impl MockThread {
    pub fn new(id: u32, process: ProcessKind) -> Self {
        let mut frame = Context {
            iar: 0x8200_0000 | (id & 0xfff0),
            lr: 0x8200_1000,
            cr: 0x2400_0042,
            ..Context::default()
        };
        frame.gpr[1] = 0x7006_f000;
        for n in 14..32 {
            frame.gpr[n] = 0x1400 + n as u64;
        }
        Self {
            id: ThreadId(id),
            process,
            has_record: true,
            debuggable: true,
            exempt: false,
            info: ThreadInfo {
                suspend_count: 0,
                monitor_suspended: false,
                priority: 9,
                tls_base: 0x7006_f800,
                start_address: 0x8200_4000,
                stack_base: 0x7007_0000,
                stack_limit: 0x7006_0000,
                create_time: 0x01d9_1234_5678_9abc,
                name: None,
                processor: 1,
                last_error: 0,
            },
            monitor_suspended: false,
            frame,
            name: None,
        }
    }
}

/// Address where the simulated kernel stores copied thread names.
const THREAD_NAME_BASE: u32 = 0x9000_1000;
/// Thread that runs commands; `break now` traps on it.
pub const COMMAND_THREAD: u32 = 0xf900_0004;
/// Address of the `break now` trap instruction.
pub const BREAK_NOW_TRAP: u32 = 0x91f4_8a60;

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub threads: Vec<MockThread>,
    /// Events not yet taken by the server.
    pub events: VecDeque<DebugEvent>,
    /// Exception context of each thread inside the monitor.
    pub in_monitor: BTreeMap<u32, Context>,
    /// Completed events, in order.
    pub completed: Vec<(ThreadId, Disposition)>,
    pub data_breakpoint_register: u32,
    pub crash_dumps: u32,
    pub kernel_build: u16,
    /// Exit status per thread handle.
    pub thread_handles: BTreeMap<ThreadHandle, Result<ExitStatus, KernelError>>,
    /// Module descriptions keyed by (name string, entry) addresses.
    pub modules: BTreeMap<(u32, u32), ModuleEvent>,
    /// Extension paths the loader accepts, with their handles.
    pub extension_images: BTreeMap<Vec<u8>, u32>,
    pub loaded_extensions: Vec<u32>,
    pub unloaded_extensions: Vec<u32>,
    /// State the server last published for direct exceptions.
    pub policy: DirectPolicy,
    pub direct_step: Option<DirectStep>,
    /// Notifications queued by direct exceptions, with captured text.
    pub direct: VecDeque<(DirectNotification, Vec<u8>)>,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            threads: vec![
                MockThread::new(0xfb00_0058, ProcessKind::Title),
                MockThread::new(0xfb00_0060, ProcessKind::Title),
                MockThread::new(0xf900_0010, ProcessKind::System),
            ],
            events: VecDeque::new(),
            in_monitor: BTreeMap::new(),
            completed: Vec::new(),
            data_breakpoint_register: 0,
            crash_dumps: 0,
            kernel_build: 21256,
            thread_handles: BTreeMap::new(),
            modules: BTreeMap::new(),
            extension_images: BTreeMap::new(),
            loaded_extensions: Vec::new(),
            unloaded_extensions: Vec::new(),
            policy: DirectPolicy::default(),
            direct_step: None,
            direct: VecDeque::new(),
        }
    }
}

impl Mock {
    fn thread(&self, id: ThreadId) -> Option<&MockThread> {
        self.threads.iter().find(|thread| thread.id == id)
    }

    fn thread_mut(&mut self, id: ThreadId) -> Option<&mut MockThread> {
        self.threads.iter_mut().find(|thread| thread.id == id)
    }

    /// Enter the monitor with an exception on `thread`.
    pub fn raise_exception(
        &mut self,
        thread: u32,
        record: ExceptionRecord,
        context: Context,
        second_chance: bool,
    ) {
        let found = self.thread(ThreadId(thread));
        let process = found.map_or(ProcessKind::Title, |found| found.process);
        let has_record = found.is_some_and(|found| found.has_record);
        let debuggable = found.is_some_and(|found| found.has_record && found.debuggable);
        self.in_monitor.insert(
            thread,
            Context {
                flags: ContextFlags::FULL,
                ..context
            },
        );
        self.events.push_back(DebugEvent::Exception {
            thread: ThreadId(thread),
            process,
            record,
            second_chance,
            has_record,
            debuggable,
        });
    }

    /// Hit the breakpoint trap at `address` on `thread`.
    pub fn raise_breakpoint(&mut self, thread: u32, address: u32) {
        let context = self.exception_context(thread, address);
        let record = ExceptionRecord {
            code: NtStatus::BREAKPOINT,
            address,
            parameter_count: 1,
            parameters: [u32::from(debugger::trap::BREAKPOINT), 0, 0, 0],
            record_address: 0x7006_e000,
            ..ExceptionRecord::default()
        };
        self.raise_exception(thread, record, context, false);
    }

    /// Complete a trace step on `thread` at `address`.
    pub fn raise_single_step(&mut self, thread: u32, address: u32) {
        let mut context = self.exception_context(thread, address);
        if let Some(previous) = self.in_monitor.get(&thread) {
            context.msr = previous.msr;
        }
        let record = ExceptionRecord {
            code: NtStatus::SINGLE_STEP,
            address,
            parameter_count: 1,
            parameters: [1, 0, 0, 0],
            record_address: 0x7006_e000,
            ..ExceptionRecord::default()
        };
        self.raise_exception(thread, record, context, false);
    }

    /// Typical exception context: interrupts enabled, Iar at `address`.
    pub fn exception_context(&self, thread: u32, address: u32) -> Context {
        let mut context = self
            .thread(ThreadId(thread))
            .map(|found| found.frame.clone())
            .unwrap_or_default();
        context.flags = ContextFlags::FULL;
        context.msr = Msr::from_bits_retain(0x0000_9032);
        context.iar = address;
        context.ctr = 0x10;
        context.xer = 0x2000_0000;
        context.fpscr = 0x8000_0000_0000_0000;
        context
    }

    pub fn raise_thread_create(&mut self, thread: MockThread, title_entry: bool) {
        let event = DebugEvent::ThreadCreate {
            thread: thread.id,
            process: thread.process,
            start: thread.info.start_address,
            title_entry,
        };
        self.threads.push(thread);
        self.events.push_back(event);
    }

    /// Disposition of the last completed event of `thread`.
    pub fn disposition(&self, thread: u32) -> Option<Disposition> {
        self.completed
            .iter()
            .rev()
            .find(|(id, _)| id.0 == thread)
            .map(|(_, disposition)| *disposition)
    }
}

fn copy_groups(source: &Context, target: &mut Context, flags: ContextFlags) {
    if flags.contains(ContextFlags::CONTROL) {
        target.msr = source.msr;
        target.iar = source.iar;
        target.lr = source.lr;
        target.ctr = source.ctr;
    }
    if flags.contains(ContextFlags::INTEGER) {
        target.gpr = source.gpr;
        target.cr = source.cr;
        target.xer = source.xer;
    }
    if flags.contains(ContextFlags::FLOATING_POINT) {
        target.fpscr = source.fpscr;
        target.fpr = source.fpr;
    }
    if flags.contains(ContextFlags::VECTOR) {
        target.vscr = source.vscr;
        target.vr = source.vr;
    }
}

impl MockBackend {
    fn region_offset(&self, address: u32, length: usize) -> Option<(usize, usize)> {
        self.memory
            .regions
            .iter()
            .enumerate()
            .find_map(|(index, region)| {
                let offset = address.checked_sub(region.base)? as usize;
                (offset + length <= region.bytes.len()).then_some((index, offset))
            })
    }

    fn thread_list(&self, process: ProcessKind) -> Vec<ThreadId> {
        self.debugger
            .threads
            .iter()
            .filter(|thread| thread.process == process)
            .map(|thread| thread.id)
            .collect()
    }

    /// Raise an exception on a thread that cannot wait for the server and
    /// dispatch it on the raising thread with the published policy, as
    /// the console does above passive level and on its server thread.
    /// `context` is updated in place; a notification is queued for the
    /// server.
    pub fn raise_direct_exception(
        &mut self,
        thread: u32,
        record: ExceptionRecord,
        context: &mut Context,
        delivery: Delivery,
    ) -> DirectOutcome {
        use openxbdm_server::commands::system::Backend as _;
        let has_record = self
            .debugger
            .thread(ThreadId(thread))
            .is_some_and(|found| found.has_record);
        let event = DirectException {
            thread: ThreadId(thread),
            record,
            second_chance: false,
            has_record,
            hardware_flags: self.hardware_flags(),
            delivery,
        };
        let iar = context.iar;
        let instruction = self.region_offset(iar, 4).map(|(index, offset)| {
            let bytes = &self.memory.regions[index].bytes[offset..offset + 4];
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        });
        let policy = self.debugger.policy;
        let mut registers = DirectRegisters {
            msr: context.msr,
            iar,
            gpr3: context.gpr[3],
            gpr4: context.gpr[4],
        };
        let outcome = dispatch_direct(
            &policy,
            &event,
            &mut registers,
            instruction,
            &mut self.debugger.direct_step,
        );
        context.msr = registers.msr;
        context.iar = registers.iar;
        context.gpr[3] = registers.gpr3;
        context.gpr[4] = registers.gpr4;
        if let Some(value) = outcome.data_breakpoint_register {
            self.debugger.data_breakpoint_register = value;
        }
        let Some(notice) = outcome.notice else {
            return outcome;
        };
        let (text, module) = match notice {
            DirectNotice::DebugString { address, length }
            | DirectNotice::Rip { address, length } => {
                let text = self
                    .region_offset(address, usize::from(length))
                    .map_or_else(Vec::new, |(index, offset)| {
                        self.memory.regions[index].bytes[offset..offset + usize::from(length)]
                            .to_vec()
                    });
                (text, None)
            }
            DirectNotice::ModuleLoad { name_string, entry }
            | DirectNotice::ModuleUnload {
                name_string, entry, ..
            } => (
                Vec::new(),
                self.debugger.modules.get(&(name_string, entry)).copied(),
            ),
            _ => (Vec::new(), None),
        };
        let notification = DirectNotification {
            thread: ThreadId(thread),
            iar,
            record: outcome.record,
            notice,
            module,
            text_length: text.len(),
        };
        self.debugger.direct.push_back((notification, text));
        outcome
    }
}

impl debugger::Backend for MockBackend {
    fn set_execution_state(&mut self, state: ExecutionState) {
        self.execution_state = state;
    }

    fn suspend_threads(&mut self, process: ProcessKind) {
        for id in self.thread_list(process) {
            let in_monitor = self.debugger.in_monitor.contains_key(&id.0);
            let Some(thread) = self.debugger.thread_mut(id) else {
                continue;
            };
            if thread.has_record
                && thread.debuggable
                && !thread.exempt
                && !in_monitor
                && !thread.monitor_suspended
            {
                thread.monitor_suspended = true;
                thread.info.suspend_count += 1;
            }
        }
    }

    fn resume_threads(&mut self, process: ProcessKind) {
        for id in self.thread_list(process) {
            let Some(thread) = self.debugger.thread_mut(id) else {
                continue;
            };
            if thread.has_record && thread.debuggable && thread.monitor_suspended {
                thread.monitor_suspended = false;
                thread.info.suspend_count -= 1;
            }
        }
    }

    fn monitor_suspend(&mut self, thread: ThreadId) {
        if let Some(thread) = self.debugger.thread_mut(thread)
            && !thread.monitor_suspended
        {
            thread.monitor_suspended = true;
            thread.info.suspend_count += 1;
        }
    }

    fn thread_ids(&mut self, ids: &mut [ThreadId]) -> Option<usize> {
        let mut count = 0;
        for process in [ProcessKind::Title, ProcessKind::System] {
            for thread in self
                .debugger
                .threads
                .iter()
                .filter(|thread| thread.process == process)
            {
                if !(thread.has_record && thread.debuggable) {
                    continue;
                }
                *ids.get_mut(count)? = thread.id;
                count += 1;
            }
        }
        Some(count)
    }

    fn thread_info(&mut self, thread: ThreadId) -> Result<ThreadInfo, NoSuchThread> {
        let thread = self.debugger.thread(thread).ok_or(NoSuchThread)?;
        let mut info = thread.info;
        info.monitor_suspended = thread.has_record && thread.monitor_suspended;
        if !thread.has_record {
            info.name = None;
        }
        Ok(info)
    }

    fn has_monitor_record(&mut self, thread: ThreadId) -> Result<bool, NoSuchThread> {
        self.debugger
            .thread(thread)
            .map(|thread| thread.has_record)
            .ok_or(NoSuchThread)
    }

    fn suspend_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        let thread = self.debugger.thread_mut(thread).ok_or(NoSuchThread)?;
        thread.info.suspend_count += 1;
        Ok(())
    }

    fn resume_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        let thread = self.debugger.thread_mut(thread).ok_or(NoSuchThread)?;
        if thread.info.suspend_count > 0 {
            thread.info.suspend_count -= 1;
        }
        Ok(())
    }

    fn thread_context(
        &mut self,
        thread: ThreadId,
        context: &mut Context,
    ) -> Result<(), NoSuchThread> {
        let requested = context.flags;
        let found = self
            .debugger
            .thread(thread)
            .filter(|thread| thread.has_record)
            .ok_or(NoSuchThread)?;
        if let Some(saved) = self.debugger.in_monitor.get(&thread.0) {
            copy_groups(saved, context, requested);
            context.flags = requested;
            return Ok(());
        }
        let frame = &found.frame;
        let mut flags = ContextFlags::empty();
        if requested.contains(ContextFlags::INTEGER) {
            flags = flags.union(ContextFlags::INTEGER);
            context.gpr = [u64::MAX; 32];
            context.gpr[14..].copy_from_slice(&frame.gpr[14..]);
            context.gpr[1] = frame.gpr[1] & 0xffff_ffff;
            context.cr = frame.cr;
            context.xer = u32::MAX;
        }
        if requested.contains(ContextFlags::CONTROL) {
            flags = flags.union(ContextFlags::CONTROL);
            context.msr = Msr::from_bits_retain(u32::MAX);
            context.iar = frame.iar;
            context.lr = frame.lr;
            context.ctr = u64::MAX;
        }
        context.flags = flags;
        Ok(())
    }

    fn set_thread_context(
        &mut self,
        thread: ThreadId,
        context: &Context,
    ) -> Result<(), StoppedThreadError> {
        let found = self
            .debugger
            .thread(thread)
            .filter(|thread| thread.has_record);
        if found.is_none() {
            return Err(StoppedThreadError::NoSuchThread);
        }
        let saved = self
            .debugger
            .in_monitor
            .get_mut(&thread.0)
            .ok_or(StoppedThreadError::NotStopped)?;
        copy_groups(context, saved, context.flags);
        Ok(())
    }

    unsafe fn set_thread_name(&mut self, thread: ThreadId, address: u32) {
        let mut name = Vec::new();
        let mut cursor = address;
        while let Some((index, offset)) = self.region_offset(cursor, 1) {
            let byte = self.memory.regions[index].bytes[offset];
            if byte == 0 {
                break;
            }
            name.push(byte);
            cursor = cursor.wrapping_add(1);
        }
        if let Some(thread) = self.debugger.thread_mut(thread)
            && thread.has_record
        {
            thread.info.name = Some(ThreadName {
                address: THREAD_NAME_BASE,
                length: name.len() as u32 + 1,
            });
            thread.name = Some(name);
        }
    }

    fn thread_exit_status(&mut self, handle: ThreadHandle) -> Result<ExitStatus, KernelError> {
        // Handles the simulated table lacks are invalid, as for the kernel.
        self.debugger
            .thread_handles
            .get(&handle)
            .copied()
            .unwrap_or(Err(KernelError::InvalidHandle))
    }

    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
        let (index, offset) = self.region_offset(address, 4)?;
        let bytes = &mut self.memory.regions[index].bytes[offset..offset + 4];
        let previous = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        bytes.copy_from_slice(&value.to_be_bytes());
        Some(previous)
    }

    fn target_bytes(&mut self, address: u32, length: usize) -> Option<&[u8]> {
        let (index, offset) = self.region_offset(address, length)?;
        Some(&self.memory.regions[index].bytes[offset..offset + length])
    }

    fn set_data_breakpoint_register(&mut self, value: u32) {
        self.debugger.data_breakpoint_register = value;
    }

    unsafe fn module_event(
        &mut self,
        name_string: u32,
        entry: u32,
        _thread: ThreadId,
    ) -> Option<ModuleEvent> {
        self.debugger.modules.get(&(name_string, entry)).copied()
    }

    fn next_event(&mut self) -> Option<DebugEvent> {
        self.debugger.events.pop_front()
    }

    fn complete_event(&mut self, thread: ThreadId, disposition: Disposition) {
        self.debugger.in_monitor.remove(&thread.0);
        self.debugger.completed.push((thread, disposition));
    }

    fn publish_direct_policy(&mut self, policy: &DirectPolicy) {
        self.debugger.policy = *policy;
    }

    fn next_direct_notification(
        &mut self,
        text: &mut [u8; NOTICE_TEXT_CAPACITY],
    ) -> Option<DirectNotification> {
        let (mut notification, captured) = self.debugger.direct.pop_front()?;
        let length = captured.len().min(NOTICE_TEXT_CAPACITY);
        text[..length].copy_from_slice(&captured[..length]);
        notification.text_length = length;
        Some(notification)
    }

    fn break_now(&mut self) -> Option<DebugEvent> {
        let id = ThreadId(COMMAND_THREAD);
        if self.debugger.thread(id).is_none() {
            let mut thread = MockThread::new(COMMAND_THREAD, ProcessKind::System);
            thread.debuggable = false;
            self.debugger.threads.push(thread);
        }
        let context = self
            .debugger
            .exception_context(COMMAND_THREAD, BREAK_NOW_TRAP);
        self.debugger.in_monitor.insert(COMMAND_THREAD, context);
        let record = ExceptionRecord {
            code: NtStatus::BREAKPOINT,
            address: BREAK_NOW_TRAP,
            parameter_count: 1,
            parameters: [u32::from(debugger::trap::BREAKPOINT), 0, 0, 0],
            record_address: 0x7005_e000,
            ..ExceptionRecord::default()
        };
        Some(DebugEvent::Exception {
            thread: id,
            process: ProcessKind::System,
            record,
            second_chance: false,
            has_record: true,
            debuggable: false,
        })
    }

    fn crash_dump(&mut self) {
        self.debugger.crash_dumps += 1;
    }

    fn kernel_build(&mut self) -> u16 {
        self.debugger.kernel_build
    }

    fn load_extension(&mut self, path: &[u8]) -> Result<ExtensionHandle, KernelError> {
        let handle = self
            .debugger
            .extension_images
            .get(path)
            .copied()
            .ok_or(KernelError::ObjectNameNotFound)?;
        self.debugger.loaded_extensions.push(handle);
        // SAFETY: the simulated loader has loaded the image; the server
        // holds one extension and loads again only after unloading it.
        Ok(unsafe { ExtensionHandle::from_raw(handle) })
    }

    fn unload_extension(&mut self, handle: ExtensionHandle) -> Result<(), KernelError> {
        self.debugger.unloaded_extensions.push(handle.raw());
        Ok(())
    }
}
