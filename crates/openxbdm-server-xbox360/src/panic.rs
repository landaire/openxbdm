use core::panic::PanicInfo;
use core::time::Duration;

use xbox360::time::sleep;
use xbox360_sys::processor;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::Irql;

use crate::kernel;
use crate::thread::THREAD_EXIT_CODE;
use crate::thread::stop_server_services;

/// Above passive level nothing may wait, so the console stops with a
/// bug check. The server thread releases every waiter and exits; other
/// threads break into the debugger and then stay parked.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    /// Bug check code of a panic above passive level ('OXDP').
    const BUG_CHECK_PANIC: BugCheckCode = BugCheckCode(0x4f58_4450);
    /// Sleep of a thread parked after a panic.
    const PARKED_SLEEP: Duration = Duration::from_secs(1);

    if processor::current_irql() != Irql::PASSIVE {
        xboxkrnl::KeBugCheckEx(BUG_CHECK_PANIC, 0, 0, 0, 0);
    }

    kernel::debug_print(c"openxbdm: panic\n");
    if crate::backend::debugger::server_thread()
        .is_some_and(|server| server.get() == processor::current_thread())
    {
        stop_server_services();
        // SAFETY: the server thread has released every waiter above.
        unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) };
    }

    xboxkrnl::DbgBreakPoint();
    loop {
        sleep(PARKED_SLEEP);
    }
}
