//! Command processors registered by other modules (`NAME!command`). The
//! platform owns the registry: other modules register at any time, from
//! any thread.

use openxbdm_core::status::Hresult;

use crate::invocation::ConnectionIndex;
use crate::text::LineText;
use crate::text::ResponseText;

pub const MAX_PROCESSORS: usize = 16;
/// Longest accepted processor name.
pub const PROCESSOR_NAME_CAPACITY: usize = 63;

/// Platform token identifying an external processor handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessorHandle(pub u32);

/// Registration flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessorFlags(u32);

impl ProcessorFlags {
    pub const NONE: Self = Self(0);
    /// Registered from the title process.
    pub const TITLE: Self = Self(0x1);
    /// Commands run on a connection dedicated to this processor.
    pub const DEDICATED_THREAD: Self = Self(0x2);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Processor {
    name: [u8; PROCESSOR_NAME_CAPACITY],
    name_len: u8,
    pub handle: ProcessorHandle,
    pub flags: ProcessorFlags,
}

impl Processor {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Why a processor could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// Every registry slot is taken.
    RegistryFull,
    /// The name is longer than [`PROCESSOR_NAME_CAPACITY`].
    NameTooLong,
}

impl From<RegisterError> for Hresult {
    fn from(error: RegisterError) -> Self {
        match error {
            RegisterError::RegistryFull => Hresult::OUT_OF_MEMORY,
            RegisterError::NameTooLong => Hresult::INVALID_ARGUMENT,
        }
    }
}

/// Processor registry.
#[derive(Debug, Default)]
pub struct Processors {
    slots: [Option<Processor>; MAX_PROCESSORS],
}

impl Processors {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_PROCESSORS],
        }
    }

    /// Register `handle` under `name`, or unregister every processor named
    /// `name` when `handle` is `None`. No duplicate-name check is made.
    pub fn register(
        &mut self,
        name: &[u8],
        handle: Option<ProcessorHandle>,
        flags: ProcessorFlags,
    ) -> Result<(), RegisterError> {
        let Some(handle) = handle else {
            for slot in &mut self.slots {
                if matches!(slot, Some(p) if p.name().eq_ignore_ascii_case(name)) {
                    *slot = None;
                }
            }
            return Ok(());
        };
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return Err(RegisterError::RegistryFull);
        };
        if name.len() > PROCESSOR_NAME_CAPACITY {
            return Err(RegisterError::NameTooLong);
        }
        let mut stored = [0u8; PROCESSOR_NAME_CAPACITY];
        stored[..name.len()].copy_from_slice(name);
        self.slots[index] = Some(Processor {
            name: stored,
            name_len: name.len() as u8,
            handle,
            flags,
        });
        Ok(())
    }

    /// Find a processor by name, ignoring ASCII case.
    pub fn find(&self, name: &[u8]) -> Option<(u8, Processor)> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            slot.filter(|p| p.name().eq_ignore_ascii_case(name))
                .map(|p| (index as u8, p))
        })
    }

    pub fn get(&self, index: u8) -> Option<Processor> {
        self.slots.get(index as usize).copied().flatten()
    }

    /// Remove every processor registered from the title process.
    pub fn remove_title_processors(&mut self) {
        for slot in &mut self.slots {
            if matches!(slot, Some(p) if p.flags.contains(ProcessorFlags::TITLE)) {
                *slot = None;
            }
        }
    }
}

/// Thread a processor call runs on: the thread that services the
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorThread {
    /// The main server thread.
    Server,
    /// The shared title command thread, in the title process.
    Title,
    /// The thread dedicated to the connection, in the title process when
    /// `title`.
    Dedicated { title: bool },
}

/// One call of an external processor on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorCall {
    pub handle: ProcessorHandle,
    pub connection: ConnectionIndex,
    pub thread: ProcessorThread,
}

/// Continuation state of an external processor transfer; the platform
/// keeps the processor's own transfer state per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalContinuation {
    pub call: ProcessorCall,
}

/// Buffers of one external continuation call.
pub struct ExternalTransfer<'a> {
    pub line: &'a mut LineText,
    pub binary: &'a mut [u8],
    pub binary_len: &'a mut usize,
    /// Set when a 202 call produced no line; nothing is sent.
    pub no_output: &'a mut bool,
    pub received: &'a [u8],
    pub receive_remaining: &'a mut Option<u32>,
    pub aborted: bool,
}

/// State of a processor call after the platform started it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorProgress {
    /// The call returned this result.
    Complete(Hresult),
    /// The call runs on another thread. The platform reports its end with
    /// [`crate::Server::complete_processor_call`]; the server then repeats
    /// the same method, which returns the finished call's results.
    Running,
    /// No thread could take the call (the monitor's failed hand-off). The
    /// server answers `422- dedicated connection required` and leaves the
    /// connection with the context it had; a continuation fails.
    Unavailable,
}

pub trait ProcessorBackend {
    /// Find a registered processor by name, ignoring ASCII case.
    fn find_processor(&mut self, name: &[u8]) -> Option<(u8, Processor)>;

    /// The processor in registry slot `index`.
    fn processor(&mut self, index: u8) -> Option<Processor>;

    /// The title process ended: remove the processors it registered and
    /// release the threads that ran in it.
    fn remove_title_processors(&mut self);

    /// Call an external processor with the full line. When the result
    /// starts a transfer, the platform stores its continuation in
    /// `continuation`. A repeated call after [`ProcessorProgress::Running`]
    /// passes an empty line.
    fn call_processor(
        &mut self,
        call: ProcessorCall,
        line: &[u8],
        text: &mut ResponseText,
        continuation: &mut Option<ExternalContinuation>,
        receive_remaining: &mut Option<u32>,
    ) -> ProcessorProgress;

    /// Call the continuation of an external processor transfer. A repeated
    /// call after [`ProcessorProgress::Running`] receives no new data.
    fn resume_processor(
        &mut self,
        continuation: &mut ExternalContinuation,
        transfer: ExternalTransfer<'_>,
    ) -> ProcessorProgress;

    /// Most bytes one call of the continuation receives during a 204
    /// upload (its data buffer size).
    fn processor_receive_limit(&mut self, continuation: &ExternalContinuation) -> usize;
}
