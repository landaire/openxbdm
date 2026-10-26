#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::PerfCounterEntry;
    use openxbdm_client::commands::PerfCounterSample;

    use crate::error::ffi::OpenxbdmError;

    /// `pclist` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmPerfCounters(pub(crate) Vec<PerfCounterEntry>);

    impl OpenxbdmPerfCounters {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let entry = self.entry(idx)?;
            let _ = write!(out, "{}", entry.name);

            Ok(())
        }

        pub fn kind(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.entry(idx)?.kind)
        }
    }

    impl OpenxbdmPerfCounters {
        fn entry(&self, idx: usize) -> Result<&PerfCounterEntry, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `querypc` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmPerfCounterSample {
        kind: u32,
        value: u64,
        rate: u64,
    }

    impl From<PerfCounterSample> for OpenxbdmPerfCounterSample {
        fn from(sample: PerfCounterSample) -> Self {
            Self {
                kind: sample.kind,
                value: sample.value,
                rate: sample.rate,
            }
        }
    }

    impl OpenxbdmPerfCounterSample {
        pub fn kind(&self) -> u32 {
            self.kind
        }

        pub fn value(&self) -> u64 {
            self.value
        }

        pub fn rate(&self) -> u64 {
            self.rate
        }
    }
}
