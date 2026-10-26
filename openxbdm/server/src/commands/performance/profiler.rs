//! CPU sampling profiler control (stock 0x91f32c90, 0x91f33010, 0x91f32e30,
//! 0x91f33090; exports 149-151) and the buffer sizing of the sampling
//! engine (0x91f8f058).
//!
//! `lopctrl` and the exports share one [`Control`]; every stock caller
//! passes owner 1, so the owner check of 0x91f33010 never fails.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::CpuProfilerInfo;

pub use super::error::ProfilerError;

/// Bytes of one sample block.
pub const BLOCK_SIZE: u32 = 0x1_0000;
/// Blocks a processor holds at most.
pub const MAX_BLOCKS: u32 = 18;

/// `lopctrl` flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfilerFlags(pub u32);

impl ProfilerFlags {
    /// Processors to sample, one bit each.
    pub fn processors(self) -> u32 {
        self.0 & 0x3f
    }

    /// Processor that runs the buffer writer thread.
    pub fn writer_processor(self) -> u32 {
        (self.0 >> 6) & 7
    }

    /// Requested buffer size in MiB; without one the engine sizes the
    /// buffers from the processor count in system memory.
    pub fn buffer_megabytes(self) -> Option<u32> {
        match (self.0 >> 9) & 0xf {
            0 => None,
            megabytes => Some(megabytes),
        }
    }
}

/// Memory the sample buffers come from (`NtAllocateVirtualMemory` option).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMemory {
    /// A requested size: title memory, then system memory as a fallback.
    Title,
    System,
}

/// Sample buffer layout: `blocks` blocks per sampled processor and as many
/// for the writer's staging area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferLayout {
    pub blocks: u32,
    pub processors: u32,
    pub memory: BufferMemory,
}

impl BufferLayout {
    pub fn bytes(self) -> u32 {
        (self.processors + 1) * self.blocks * BLOCK_SIZE
    }
}

/// The sampled processor count is 0; stock reports it as an invalid thread
/// count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoProcessors;

/// The sampling engine; every method is a stock routine.
pub trait Engine {
    /// Size the buffers, write the header, and hook the sampling interrupt
    /// (0x91f90768).
    fn initialize(&mut self, flags: ProfilerFlags) -> Result<(), ProfilerError>;
    /// Undo a failed initialization (0x91f90220).
    fn abandon(&mut self);
    /// Create the directories above `path` (0x91f64448).
    fn create_directories(&mut self, path: &[u8]);
    /// Open the capture file and start sampling every `interval` timer
    /// ticks (0x91f90258). `path` is `None` when the name has no object
    /// name; stock would hang waiting for its writer thread.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Result<(), ProfilerError>;
    /// Stop sampling, flush, and close the file (0x91f90310).
    fn stop(&mut self) -> Result<(), ProfilerError>;
    /// Elapsed seconds and the interrupt counters (0x91f90370).
    fn info(&mut self) -> CpuProfilerInfo;
}

/// Profiler state shared by `lopctrl`, the exports, and the title
/// terminate notification (stock 0x91fadd80..0x91fadd8c).
#[derive(Debug)]
pub struct Control {
    running: AtomicBool,
    initialized: AtomicBool,
    suspended: AtomicBool,
}

impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}

impl Control {
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
        }
    }

    /// Stock 0x91f32ff8.
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Start profiling into `path`, the object name of the requested file
    /// (stock 0x91f32c90).
    pub fn start(
        &self,
        engine: &mut dyn Engine,
        path: Option<&[u8]>,
        interval: u32,
        flags: ProfilerFlags,
    ) -> Result<(), ProfilerError> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Err(ProfilerError::AlreadyRunning);
        }

        if !self.initialized.swap(true, Ordering::AcqRel)
            && let Err(error) = engine.initialize(flags)
        {
            engine.abandon();
            self.initialized.store(false, Ordering::Release);
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        if let Some(path) = path {
            engine.create_directories(path);
        }

        if let Err(error) = engine.start(path, interval) {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        self.suspended.store(false, Ordering::Release);

        Ok(())
    }

    /// Stop profiling and write the file (stock 0x91f33010).
    pub fn stop(&self, engine: &mut dyn Engine) -> Result<(), ProfilerError> {
        if !self.running() {
            return Err(ProfilerError::NotRunning);
        }

        let result = engine.stop();
        self.running.store(false, Ordering::Release);
        self.initialized.store(false, Ordering::Release);

        result
    }

    /// Stock 0x91f32e30.
    pub fn info(&self, engine: &mut dyn Engine) -> Result<CpuProfilerInfo, ProfilerError> {
        if self.suspended.load(Ordering::Acquire) {
            return Err(ProfilerError::Suspended);
        }

        if !self.running() {
            return Err(ProfilerError::NotRunning);
        }

        Ok(engine.info())
    }

    /// The title ended: stop and report later queries as suspended (stock
    /// 0x91f33090).
    pub fn title_terminated(&self, engine: &mut dyn Engine) {
        let _ = self.stop(engine);
        self.suspended.store(true, Ordering::Release);
    }
}

/// Size the sample buffers (stock 0x91f8f058).
pub fn buffer_layout(flags: ProfilerFlags) -> Result<BufferLayout, NoProcessors> {
    let processors = flags.processors().count_ones();
    let default = match processors {
        1 => 8,
        2 => 6,
        3 | 4 => 5,
        5 | 6 => 4,
        _ => return Err(NoProcessors),
    };

    Ok(match flags.buffer_megabytes() {
        None => BufferLayout {
            blocks: default,
            processors,
            memory: BufferMemory::System,
        },
        Some(megabytes) => BufferLayout {
            blocks: ((megabytes << 20) / ((processors + 1) * BLOCK_SIZE)).min(MAX_BLOCKS),
            processors,
            memory: BufferMemory::Title,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        initializations: u32,
        abandoned: u32,
        stops: u32,
        initialize_error: Option<ProfilerError>,
    }

    impl Engine for Recorder {
        fn initialize(&mut self, _flags: ProfilerFlags) -> Result<(), ProfilerError> {
            self.initializations += 1;
            self.initialize_error.map_or(Ok(()), Err)
        }

        fn abandon(&mut self) {
            self.abandoned += 1;
        }

        fn create_directories(&mut self, _path: &[u8]) {}

        fn start(&mut self, _path: Option<&[u8]>, _interval: u32) -> Result<(), ProfilerError> {
            Ok(())
        }

        fn stop(&mut self) -> Result<(), ProfilerError> {
            self.stops += 1;
            Ok(())
        }

        fn info(&mut self) -> CpuProfilerInfo {
            CpuProfilerInfo {
                elapsed_time: 1,
                total_samples: 2,
                overhead_interrupts: 3,
            }
        }
    }

    #[test]
    fn title_termination_stops_and_suspends_until_the_next_start() {
        let control = Control::new();
        let mut engine = Recorder::default();
        assert_eq!(
            control.start(&mut engine, Some(b"\\Device\\a"), 0, ProfilerFlags(1)),
            Ok(())
        );
        control.title_terminated(&mut engine);
        assert_eq!(engine.stops, 1);
        assert_eq!(control.info(&mut engine), Err(ProfilerError::Suspended));
        assert_eq!(control.stop(&mut engine), Err(ProfilerError::NotRunning));
        assert_eq!(
            control.start(&mut engine, Some(b"\\Device\\a"), 0, ProfilerFlags(1)),
            Ok(())
        );
        assert_eq!(engine.initializations, 2);
        assert_eq!(
            control.info(&mut engine).map(|info| info.total_samples),
            Ok(2)
        );
    }

    #[test]
    fn failed_initialization_is_abandoned_and_retried() {
        let control = Control::new();
        let mut engine = Recorder {
            initialize_error: Some(ProfilerError::NoBuffers),
            ..Recorder::default()
        };
        assert_eq!(
            control.start(&mut engine, None, 0, ProfilerFlags(0)),
            Err(ProfilerError::NoBuffers)
        );
        assert_eq!((engine.initializations, engine.abandoned), (1, 1));
        engine.initialize_error = None;
        assert_eq!(
            control.start(&mut engine, None, 0, ProfilerFlags(1)),
            Ok(())
        );
        assert_eq!(engine.initializations, 2);
    }

    #[test]
    fn buffers_are_sized_from_the_processor_count_or_the_requested_size() {
        let layout = |flags| buffer_layout(ProfilerFlags(flags));
        assert_eq!(layout(0), Err(NoProcessors));
        assert_eq!(
            layout(0x01).map(|layout| (layout.blocks, layout.bytes())),
            Ok((8, 0x10_0000))
        );
        assert_eq!(layout(0x03).map(|layout| layout.blocks), Ok(6));
        assert_eq!(layout(0x07).map(|layout| layout.blocks), Ok(5));
        assert_eq!(
            layout(0x3f).map(|layout| (layout.blocks, layout.memory)),
            Ok((4, BufferMemory::System))
        );
        // 15 MiB over two processors and the staging area: 80 blocks, capped.
        assert_eq!(
            layout(0x1e03).map(|layout| (layout.blocks, layout.memory)),
            Ok((18, BufferMemory::Title))
        );
        // 1 MiB over six processors and the staging area: 2 blocks each.
        assert_eq!(layout(0x23f).map(|layout| layout.blocks), Ok(2));
    }
}
