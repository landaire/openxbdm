//! Execution state and requests to run the execution state machine.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::notify::ExecutionState;
use xbox360_sys::processor::current_irql;
use xbox360_sys::xboxkrnl::Irql;

use super::policy::load_policy;
use super::slot::EXECUTION_NOTIFY;
use super::slot::SlotDisposition;
use super::slot::SlotEventKind;
use super::slot::post_and_wait;
use super::thread::OwnThread;
use super::thread::is_server;

/// Execution state in the monitor's numbering (0 stopped .. 5
/// pending_title).
pub(super) static EXECUTION_STATE: AtomicU32 = AtomicU32::new(1);

pub(crate) const fn execution_code(state: ExecutionState) -> u32 {
    match state {
        ExecutionState::Stopped => 0,
        ExecutionState::Started => 1,
        ExecutionState::Rebooting => 2,
        ExecutionState::Pending => 3,
        ExecutionState::RebootTitle => 4,
        ExecutionState::PendingTitle => 5,
    }
}

pub(super) const fn execution_from_code(code: u32) -> ExecutionState {
    match code {
        0 => ExecutionState::Stopped,
        2 => ExecutionState::Rebooting,
        3 => ExecutionState::Pending,
        4 => ExecutionState::RebootTitle,
        5 => ExecutionState::PendingTitle,
        _ => ExecutionState::Started,
    }
}

/// Current execution state.
pub(crate) fn execution_state() -> ExecutionState {
    execution_from_code(EXECUTION_STATE.load(Ordering::Acquire))
}

fn caller_can_wait() -> Option<OwnThread> {
    let own = OwnThread::current();

    (!is_server(own.kthread()) && current_irql() == Irql::PASSIVE).then_some(own)
}

/// Run the monitor's execution state machine (stock 0x91f2da88 without
/// its wait flag) on the server thread; the caller waits until it ran. A
/// pending_title request while stopped waits for the state to change.
/// Does nothing on the server thread, above passive level, or while the
/// server does not take events.
pub(crate) fn request_execution(target: ExecutionState, notify: bool) {
    if let Some(thread) = caller_can_wait() {
        let notify = if notify { EXECUTION_NOTIFY } else { 0 };
        post_and_wait(
            SlotEventKind::Execution,
            thread,
            0,
            0,
            execution_code(target) | notify,
        );
    }
}

/// Stop the calling thread with `execution pending_title stop` until
/// execution starts (stock 0x91f523a0). Without `forever` the wait ends
/// after 15 s and the caller starts execution itself. Returns whether the
/// thread was released before that; false on the server thread, above
/// passive level, or while the server does not take events.
pub(crate) fn stop_at_pending_title(forever: bool) -> bool {
    caller_can_wait().is_some_and(|thread| {
        post_and_wait(SlotEventKind::TitleStop, thread, 0, 0, u32::from(forever))
            .is_some_and(|disposition| disposition.contains(SlotDisposition::HANDLED))
    })
}

/// A profile-guided module registered (stock export 107): with
/// `stopon pogomodstart` the calling thread stops with a `pogomodstartup`
/// line until it is continued. `name` is the address of the module path.
pub(crate) fn report_pogo_module_start(name: u32, module: u32) {
    if !load_policy().stop_on.contains(StopOn::POGO_MODULE_START) {
        return;
    }

    if let Some(thread) = caller_can_wait() {
        post_and_wait(SlotEventKind::Pogo, thread, name, module, 0);
    }
}
