//! Simulated input system behind controller automation.

use openxbdm_server::commands::hardware::automation;
use openxbdm_server::commands::hardware::automation::Automation;
use openxbdm_server::commands::hardware::automation::Controllers;
use openxbdm_server::commands::hardware::automation::DebuggerMessage;
use openxbdm_server::commands::hardware::automation::InputPlatform;
use openxbdm_server::commands::hardware::automation::Poll;
use openxbdm_server::commands::hardware::automation::QueueEntry;

use super::Mock;

/// Simulated input system.
#[derive(Debug, Default)]
pub struct Input {
    /// Millisecond tick count.
    pub now: u32,

    /// The input system refuses to bind controllers.
    pub refuse_bind: bool,
    /// The input system refuses to unbind controllers.
    pub refuse_unbind: bool,

    /// Users bound, in request order.
    pub binds: Vec<u32>,
    /// Users unbound, in request order.
    pub unbinds: Vec<u32>,
    /// Users whose guide button press was reported.
    pub guide_presses: Vec<u32>,
    /// Messages for the debugger extension.
    pub debugger_messages: Vec<DebuggerMessage>,
}

impl InputPlatform for Input {
    fn tick(&mut self) -> u32 {
        self.now
    }

    fn press_guide(&mut self, user: u32) {
        self.guide_presses.push(user);
    }
}

impl Mock {
    /// Input system poll of a user slot.
    pub fn poll(&mut self, user: u32) -> Option<Poll> {
        self.automation.poll(user, &mut self.input)
    }
}

impl Controllers for Mock {
    type Storage = Vec<QueueEntry>;

    fn locked<R>(
        &mut self,
        operation: impl FnOnce(&mut Automation<Vec<QueueEntry>>, &mut dyn InputPlatform) -> R,
    ) -> R {
        operation(&mut self.automation, &mut self.input)
    }

    fn allocate(&mut self, queue_length: u32) -> Option<Vec<QueueEntry>> {
        pool_allows(automation::allocation_size(queue_length))
            .then(|| vec![QueueEntry::default(); automation::storage_entries(queue_length)])
    }

    fn bind_controller(&mut self, user: u32) -> bool {
        self.input.binds.push(user);

        !self.input.refuse_bind
    }

    fn unbind_controller(&mut self, user: u32) -> bool {
        self.input.unbinds.push(user);

        !self.input.refuse_unbind
    }

    fn tell_debugger(&mut self, message: DebuggerMessage) {
        self.input.debugger_messages.push(message);
    }
}

/// Simulated pool allocation of `bytes`.
pub(super) fn pool_allows(bytes: u64) -> bool {
    /// Pool bytes available to simulated allocations.
    const POOL_BYTES: u64 = 0x10_0000;

    bytes <= POOL_BYTES
}
