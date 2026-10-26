//! Services domain errors.

use openxbdm_core::status::KernelError;

use super::civ::DetectionRoutine;

/// A detection routine could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionRoutineMissing {
    pub routine: DetectionRoutine,
    pub error: KernelError,
}
