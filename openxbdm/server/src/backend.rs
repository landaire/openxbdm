//! Platform services the server requires.

use crate::commands;
use crate::notify::ExecutionState;
use crate::processors::ProcessorBackend;

/// Services used by the server core.
pub trait Platform {
    /// System time as a FILETIME (100 ns units since 1601).
    fn system_time(&mut self) -> u64;
    /// Processor time base counter.
    fn timebase(&mut self) -> u64;
    /// Whether the console is a test kit rather than a development kit.
    fn is_test_kit(&self) -> bool;
    /// Current execution state of the title.
    fn execution_state(&mut self) -> ExecutionState;
    /// Fill `output` with random bytes.
    fn random_bytes(&mut self, output: &mut [u8]);
    /// Write a diagnostic string to the debug output.
    fn debug_print(&mut self, text: &[u8]);
}

/// Everything the server requires from a platform.
pub trait Backend:
    Platform
    + ProcessorBackend
    + commands::session::Backend
    + commands::security::Backend
    + commands::console::Backend
    + commands::system::Backend
    + commands::filesystem::Backend
    + commands::filesystem::PathServices
    + commands::memory::Backend
    + commands::debugger::Backend
    + commands::network::Backend
    + commands::performance::Backend
    + commands::hardware::Backend
    + commands::services::Backend
{
}

impl<T> Backend for T where
    T: Platform
        + ProcessorBackend
        + commands::session::Backend
        + commands::security::Backend
        + commands::console::Backend
        + commands::system::Backend
        + commands::filesystem::Backend
        + commands::filesystem::PathServices
        + commands::memory::Backend
        + commands::debugger::Backend
        + commands::network::Backend
        + commands::performance::Backend
        + commands::hardware::Backend
        + commands::services::Backend
{
}
