//! Debug monitor services: the kernel debug routine hook, thread
//! notifications, monitor thread records, thread control, breakpoints in
//! code memory, and debugger extensions.
//!
//! The kernel calls the debug routine and the thread notification on the
//! thread concerned. While the server thread takes events, that thread
//! posts its event to a slot and waits; the server thread takes the event,
//! decides, and completes the slot. Otherwise the thread takes the
//! monitor's default disposition without waiting.

mod context;
mod direct;
mod dump;
mod execution;
mod exports;
mod extension;
mod hook;
mod memory;
mod module;
mod policy;
mod slot;
mod thread;

use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::Context;
use openxbdm_server::commands::debugger::DebugEvent;
use openxbdm_server::commands::debugger::DirectNotification;
use openxbdm_server::commands::debugger::DirectPolicy;
use openxbdm_server::commands::debugger::Disposition;
use openxbdm_server::commands::debugger::ExitStatus;
use openxbdm_server::commands::debugger::ExtensionHandle;
use openxbdm_server::commands::debugger::ModuleEvent;
use openxbdm_server::commands::debugger::NOTICE_TEXT_CAPACITY;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::StoppedThreadError;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::ThreadInfo;
use openxbdm_server::commands::services::ThreadHandle;
use openxbdm_server::notify::ExecutionState;
use xbox360::console::kernel_version;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;

use self::execution::EXECUTION_STATE;
use self::hook::set_data_breakpoint_entry;
use self::memory::readable;
use self::memory::target_u8;
use self::module::describe_module;
use self::policy::store_policy;
use self::thread::ThreadRef;
use self::thread::has_record;
use super::Console;

pub(crate) use self::context::context_from_memory;
pub(crate) use self::context::context_to_memory;
pub(crate) use self::context::read_thread_context;
pub(crate) use self::context::write_thread_context;
pub(crate) use self::dump::DumpKind;
pub(crate) use self::dump::dump_calling_thread;
pub(crate) use self::execution::execution_code;
pub(crate) use self::execution::execution_state;
pub(crate) use self::execution::report_pogo_module_start;
pub(crate) use self::execution::request_execution;
pub(crate) use self::execution::stop_at_pending_title;
pub(crate) use self::exports::apply_pending_stop_on;
pub(crate) use self::extension::tell_extension;
pub(crate) use self::hook::install;
pub(crate) use self::hook::uninstall;
pub(crate) use self::module::ansi_string_length;
pub(crate) use self::slot::begin_event_service;
pub(crate) use self::slot::end_event_service;
pub(crate) use self::slot::wait_for_event_waiters;
pub(crate) use self::thread::MonitorRecordFlags;
pub(crate) use self::thread::collect_thread_ids;
pub(crate) use self::thread::current_debug_data;
pub(crate) use self::thread::debuggable_thread_ids;
pub(crate) use self::thread::exchange_record_flags;
pub(crate) use self::thread::name_thread;
pub(crate) use self::thread::resume;
pub(crate) use self::thread::server_thread;
pub(crate) use self::thread::set_server_thread;
pub(crate) use self::thread::suspend;
pub(crate) use self::thread::thread_information;
pub(crate) use self::thread::thread_name;

/// Platform state of this domain.
pub struct Data {
    /// Name of the module under `target_bytes`, copied for the event.
    scratch: [u8; 0x800],
}

impl Data {
    pub const fn new() -> Self {
        Self {
            scratch: [0; 0x800],
        }
    }
}

impl debugger::Backend for Console {
    fn set_execution_state(&mut self, state: ExecutionState) {
        EXECUTION_STATE.store(execution_code(state), Ordering::Release);
    }

    fn suspend_threads(&mut self, process: ProcessKind) {
        thread::suspend_threads(process)
    }

    fn resume_threads(&mut self, process: ProcessKind) {
        thread::resume_threads(process)
    }

    fn monitor_suspend(&mut self, thread: ThreadId) {
        thread::monitor_suspend(thread)
    }

    fn thread_ids(&mut self, ids: &mut [ThreadId]) -> Option<usize> {
        debuggable_thread_ids(ids)
    }

    fn thread_info(&mut self, id: ThreadId) -> Result<ThreadInfo, NoSuchThread> {
        thread_information(id)
    }

    fn has_monitor_record(&mut self, thread: ThreadId) -> Result<bool, NoSuchThread> {
        let reference = ThreadRef::lookup(thread)?;

        Ok(has_record(reference.thread()))
    }

    fn suspend_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        suspend(thread)
    }

    fn resume_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        resume(thread)
    }

    fn thread_context(&mut self, thread: ThreadId, out: &mut Context) -> Result<(), NoSuchThread> {
        read_thread_context(thread, out)
    }

    fn set_thread_context(
        &mut self,
        thread: ThreadId,
        source: &Context,
    ) -> Result<(), StoppedThreadError> {
        write_thread_context(thread, source)
    }

    unsafe fn set_thread_name(&mut self, thread: ThreadId, address: u32) {
        // SAFETY: the server passes the name parameter of the thread-name
        // exception of a thread that waits in its slot for the call. The
        // named thread may be another one that ends during the call; stock
        // names it without the process lock and the monitor keeps that
        // race.
        unsafe { name_thread(Some(thread), address) };
    }

    fn thread_exit_status(&mut self, handle: ThreadHandle) -> Result<ExitStatus, KernelError> {
        let reference = ThreadRef::by_handle(handle)?;
        let thread = reference.thread();
        // The low byte of the signal state is set once the thread ended.
        Ok(if thread.signal_state.load(Ordering::Relaxed) as u8 == 0 {
            ExitStatus::STILL_ACTIVE
        } else {
            ExitStatus(thread.exit_status.load(Ordering::Relaxed))
        })
    }

    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
        memory::replace_code_word(address, value)
    }

    fn target_bytes(&mut self, address: u32, length: usize) -> Option<&[u8]> {
        let length = length.min(self.debugger.scratch.len());

        for (offset, byte) in self.debugger.scratch[..length].iter_mut().enumerate() {
            let source = address.wrapping_add(offset as u32);
            if offset == 0 || source & 0xfff == 0 {
                if !readable(source) {
                    return None;
                }
            }
            // SAFETY: `readable` checked the page of `source` above.
            *byte = unsafe { target_u8(source) };
        }

        Some(&self.debugger.scratch[..length])
    }

    fn set_data_breakpoint_register(&mut self, value: u32) {
        // SAFETY: the routine is this module's IPI entry, which takes the
        // register value as its argument.
        unsafe {
            KeIpiGenericCall(
                set_data_breakpoint_entry as *const () as usize as u32,
                value,
            )
        };
    }

    unsafe fn module_event(
        &mut self,
        name_string: u32,
        entry: u32,
        _thread: ThreadId,
    ) -> Option<ModuleEvent> {
        // SAFETY: the caller upholds the same contract.
        unsafe { describe_module(name_string, entry) }
    }

    fn next_event(&mut self) -> Option<DebugEvent> {
        slot::next_event()
    }

    fn complete_event(&mut self, thread: ThreadId, disposition: Disposition) {
        slot::complete_event(thread, disposition)
    }

    fn publish_direct_policy(&mut self, policy: &DirectPolicy) {
        store_policy(policy);
    }

    fn next_direct_notification(
        &mut self,
        text: &mut [u8; NOTICE_TEXT_CAPACITY],
    ) -> Option<DirectNotification> {
        direct::next_direct_notification(text)
    }

    fn break_now(&mut self) -> Option<DebugEvent> {
        hook::break_now()
    }

    fn crash_dump(&mut self) {
        sleep(Duration::from_millis(200));
        dump_calling_thread(DumpKind::Default);
    }

    fn kernel_build(&mut self) -> u16 {
        kernel_version().build
    }

    fn load_extension(&mut self, path: &[u8]) -> Result<ExtensionHandle, KernelError> {
        extension::load_extension(path)
    }

    fn unload_extension(&mut self, handle: ExtensionHandle) -> Result<(), KernelError> {
        extension::unload_extension(handle)
    }
}
