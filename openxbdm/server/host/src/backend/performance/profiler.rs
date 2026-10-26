//! Simulated CPU sampling profiler engine.

use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;

/// Simulated CPU sampling profiler engine.
#[derive(Debug, Clone)]
pub struct CpuProfiler {
    pub initialize_result: Result<(), ProfilerError>,
    pub start_result: Result<(), ProfilerError>,
    pub stop_result: Result<(), ProfilerError>,

    pub initializations: Vec<ProfilerFlags>,
    pub abandons: u32,
    /// Paths whose parent directories were created.
    pub directories: Vec<Vec<u8>>,
    /// Object paths and intervals of each start.
    pub starts: Vec<(Vec<u8>, u32)>,
    pub stops: u32,

    pub info: CpuProfilerInfo,
}

impl Default for CpuProfiler {
    fn default() -> Self {
        Self {
            initialize_result: Ok(()),
            start_result: Ok(()),
            stop_result: Ok(()),
            initializations: Vec::new(),
            abandons: 0,
            directories: Vec::new(),
            starts: Vec::new(),
            stops: 0,
            info: CpuProfilerInfo::default(),
        }
    }
}

impl profiler::Engine for CpuProfiler {
    fn initialize(&mut self, flags: ProfilerFlags) -> Result<(), ProfilerError> {
        self.initializations.push(flags);

        self.initialize_result
    }

    fn abandon(&mut self) {
        self.abandons += 1;
    }

    fn create_directories(&mut self, path: &[u8]) {
        self.directories.push(path.to_vec());
    }

    /// A name without an object path fails as the console engine reports it.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Result<(), ProfilerError> {
        let Some(path) = path else {
            return Err(ProfilerError::PrologueFailed);
        };

        self.starts.push((path.to_vec(), interval));

        self.start_result
    }

    fn stop(&mut self) -> Result<(), ProfilerError> {
        self.stops += 1;

        self.stop_result
    }

    fn info(&mut self) -> CpuProfilerInfo {
        self.info
    }
}
