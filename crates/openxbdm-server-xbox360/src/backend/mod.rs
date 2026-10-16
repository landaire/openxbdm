//! Console services for the server, one module per command domain.

pub mod console;
pub mod debugger;
pub mod dispatcher;
pub mod dvd_hotplug;
pub mod filesystem;
pub mod hardware;
pub mod image_device;
pub mod memory;
pub mod network;
pub mod performance;
pub mod security;
pub mod services;
pub mod session;
pub mod system;

use openxbdm_server::Platform;
use openxbdm_server::notify::ExecutionState;
use xbox360::console::hardware_flags;
use xbox360::time::FileTime;
use xbox360::time::Timebase;

use crate::kernel;
use crate::net;

/// Hardware flag: the console is not debug capable.
pub const HARDWARE_NOT_DEBUGGABLE: u32 = 0x0200_0000;

/// Console services. Each domain keeps its platform state in its own field.
pub struct Console {
    pub session: session::Data,
    pub security: security::Data,
    pub console: console::Data,
    pub system: system::Data,
    pub filesystem: filesystem::Data,
    pub debugger: debugger::Data,
    pub network: network::Data,
    pub performance: performance::Data,
    pub hardware: hardware::Data,
}

impl Console {
    pub const fn new() -> Self {
        Self {
            session: session::Data::new(),
            security: security::Data::new(),
            console: console::Data::new(),
            system: system::Data::new(),
            filesystem: filesystem::Data::new(),
            debugger: debugger::Data::new(),
            network: network::Data::new(),
            performance: performance::Data::new(),
            hardware: hardware::Data::new(),
        }
    }
}

impl Platform for Console {
    fn system_time(&mut self) -> u64 {
        FileTime::now().intervals()
    }

    fn timebase(&mut self) -> u64 {
        Timebase::now().ticks()
    }

    fn is_test_kit(&self) -> bool {
        hardware_flags().bits() & HARDWARE_NOT_DEBUGGABLE != 0 || console::test_kit_marked()
    }

    fn execution_state(&mut self) -> ExecutionState {
        debugger::execution_state()
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        net::random_bytes(output);
    }

    fn debug_print(&mut self, text: &[u8]) {
        kernel::debug_print_bytes(text);
    }
}
