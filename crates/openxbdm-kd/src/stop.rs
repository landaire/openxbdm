//! Owned copy of an exception state change.

use openxbdm_kd_core::manipulate::Processor;
use openxbdm_kd_core::state_change::ControlReport;
use openxbdm_kd_core::state_change::ExceptionRecord;
use openxbdm_kd_core::state_change::NewState;
use openxbdm_kd_core::state_change::StateBody;
use openxbdm_kd_core::state_change::StateChange;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    pub new_state: NewState,
    pub processor: Processor,
    pub number_processors: u32,
    pub thread: u64,
    pub program_counter: u64,
    pub exception: Option<StopException>,
    /// The image of a held load-symbols stop.
    pub image: Option<StopImage>,
    pub control_report: ControlReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopImage {
    pub name: Vec<u8>,
    pub base: u64,
    pub size: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StopException {
    pub record: ExceptionRecord,
    pub first_chance: bool,
}

impl StopReport {
    pub fn from_state_change(change: &StateChange<'_>) -> Self {
        let exception = match change.body {
            StateBody::Exception {
                record,
                first_chance,
            } => Some(StopException {
                record,
                first_chance,
            }),
            StateBody::LoadSymbols(_) | StateBody::Other => None,
        };
        let image = match change.body {
            StateBody::LoadSymbols(symbols) => Some(StopImage {
                name: change.path.to_vec(),
                base: symbols.base,
                size: symbols.size_of_image,
            }),
            StateBody::Exception { .. } | StateBody::Other => None,
        };
        Self {
            new_state: change.new_state,
            processor: change.processor,
            number_processors: change.number_processors,
            thread: change.thread,
            program_counter: change.program_counter,
            exception,
            image,
            control_report: change.control_report,
        }
    }

    /// Program counter as a 32-bit effective address.
    pub fn pc(&self) -> u32 {
        // The kernel sign-extends 32-bit addresses.
        self.program_counter as u32
    }
}
