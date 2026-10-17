#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::ModuleInfo;
    use openxbdm_client::commands::ModuleSection;
    use openxbdm_client::commands::ThreadDetail;
    use openxbdm_client::commands::Win32Error;
    use openxbdm_client::commands::XbeInfoResult;

    use crate::error::ffi::OpenxbdmError;

    /// `modules` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmModules(pub(crate) Vec<ModuleInfo>);

    impl OpenxbdmModules {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let module = self.module(idx)?;
            let _ = write!(out, "{}", module.name);

            Ok(())
        }

        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.base)
        }

        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.size)
        }

        pub fn checksum(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.checksum)
        }

        pub fn timestamp(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.timestamp)
        }

        pub fn pdata(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.pdata)
        }

        pub fn psize(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.psize)
        }

        pub fn thread(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.thread)
        }

        pub fn osize(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.osize)
        }

        pub fn is_dll(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.is_dll)
        }

        pub fn is_tls(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.is_tls)
        }

        pub fn is_xbe(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            Ok(self.module(idx)?.is_xbe)
        }
    }

    impl OpenxbdmModules {
        fn module(&self, idx: usize) -> Result<&ModuleInfo, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `modsections` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmModuleSections(pub(crate) Vec<ModuleSection>);

    impl OpenxbdmModuleSections {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let section = self.section(idx)?;
            let _ = write!(out, "{}", section.name);

            Ok(())
        }

        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.section(idx)?.base)
        }

        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.section(idx)?.size)
        }

        pub fn index(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.section(idx)?.index)
        }

        pub fn flags(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.section(idx)?.flags.0)
        }
    }

    impl OpenxbdmModuleSections {
        fn section(&self, idx: usize) -> Result<&ModuleSection, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `threads` reply: list of thread ids.
    #[diplomat::opaque]
    pub struct OpenxbdmThreadIds(pub(crate) Vec<u32>);

    impl OpenxbdmThreadIds {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn get(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .copied()
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `threadinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmThreadDetail {
        thread: u32,
        suspend: u32,
        priority: i32,
        tls_base: u32,

        start: u32,
        base: u32,
        limit: u32,
        slack: u32,

        create_time: u64,
        name_address: u32,
        name_length: u32,
        processor: u32,
        last_error: Option<Win32Error>,
    }

    impl From<ThreadDetail> for OpenxbdmThreadDetail {
        fn from(detail: ThreadDetail) -> Self {
            Self {
                thread: detail.thread.as_u32(),
                suspend: detail.suspend,
                priority: detail.priority,
                tls_base: detail.tls_base,
                start: detail.start,
                base: detail.base,
                limit: detail.limit,
                slack: detail.slack,
                create_time: detail.create_time.as_raw(),
                name_address: detail.name_address,
                name_length: detail.name_length,
                processor: detail.processor,
                last_error: detail.last_error,
            }
        }
    }

    impl OpenxbdmThreadDetail {
        pub fn thread(&self) -> u32 {
            self.thread
        }

        pub fn suspend(&self) -> u32 {
            self.suspend
        }

        pub fn priority(&self) -> i32 {
            self.priority
        }

        pub fn tls_base(&self) -> u32 {
            self.tls_base
        }

        pub fn start(&self) -> u32 {
            self.start
        }

        pub fn base(&self) -> u32 {
            self.base
        }

        pub fn limit(&self) -> u32 {
            self.limit
        }

        pub fn slack(&self) -> u32 {
            self.slack
        }

        pub fn create_time(&self) -> u64 {
            self.create_time
        }

        pub fn name_address(&self) -> u32 {
            self.name_address
        }

        pub fn name_length(&self) -> u32 {
            self.name_length
        }

        pub fn processor(&self) -> u32 {
            self.processor
        }

        /// The thread's last Win32 error; 0 for `ERROR_SUCCESS`.
        pub fn last_error(&self) -> u32 {
            self.last_error.map_or(0, Win32Error::code)
        }
    }

    /// `xbeinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmXbeInfo {
        timestamp: u32,
        checksum: u32,
        name: String,
    }

    impl From<XbeInfoResult> for OpenxbdmXbeInfo {
        fn from(info: XbeInfoResult) -> Self {
            Self {
                timestamp: info.timestamp,
                checksum: info.checksum,
                name: info.name,
            }
        }
    }

    impl OpenxbdmXbeInfo {
        pub fn timestamp(&self) -> u32 {
            self.timestamp
        }

        pub fn checksum(&self) -> u32 {
            self.checksum
        }

        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }
    }
}
