#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::DirEntry;
    use openxbdm_client::commands::DriveSpace;
    use openxbdm_client::commands::EofDisposition;
    use openxbdm_client::commands::FileAttributes;

    use crate::error::ffi::OpenxbdmError;

    /// How `fileeof` opens the file.
    #[allow(dead_code, reason = "foreign callers construct the variants")]
    pub enum FileEofDisposition {
        /// The file must exist.
        OpenExisting,
        /// The file must not exist.
        CreateNew,
        /// Create the file or truncate an existing one before resizing.
        CreateOrTruncate,
    }

    impl From<FileEofDisposition> for EofDisposition {
        fn from(disposition: FileEofDisposition) -> Self {
            match disposition {
                FileEofDisposition::OpenExisting => Self::OpenExisting,
                FileEofDisposition::CreateNew => Self::CreateNew,
                FileEofDisposition::CreateOrTruncate => Self::CreateOrTruncate,
            }
        }
    }

    /// `drivefreespace` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmDriveSpace {
        free_to_caller: u64,
        total: u64,
        total_free: u64,
    }

    impl From<DriveSpace> for OpenxbdmDriveSpace {
        fn from(space: DriveSpace) -> Self {
            Self {
                free_to_caller: space.free_to_caller_bytes,
                total: space.total_bytes,
                total_free: space.total_free_bytes,
            }
        }
    }

    impl OpenxbdmDriveSpace {
        pub fn free_to_caller_bytes(&self) -> u64 {
            self.free_to_caller
        }

        pub fn total_bytes(&self) -> u64 {
            self.total
        }

        pub fn total_free_bytes(&self) -> u64 {
            self.total_free
        }
    }

    /// `dirlist` reply: list of entries.
    #[diplomat::opaque]
    pub struct OpenxbdmDirEntries(pub(crate) Vec<DirEntry>);

    impl OpenxbdmDirEntries {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let entry = self.entry(idx)?;
            let _ = write!(out, "{}", entry.name);

            Ok(())
        }

        pub fn size(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            Ok(self.entry(idx)?.size)
        }

        pub fn create_time(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            Ok(self.entry(idx)?.create_time.as_raw())
        }

        pub fn change_time(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            Ok(self.entry(idx)?.change_time.as_raw())
        }

        pub fn is_directory(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            Ok(self.entry(idx)?.is_directory)
        }
    }

    impl OpenxbdmDirEntries {
        fn entry(&self, idx: usize) -> Result<&DirEntry, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `getfileattributes` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmFileAttributes {
        size: u64,
        create_time: u64,
        change_time: u64,
        is_directory: bool,
    }

    impl From<FileAttributes> for OpenxbdmFileAttributes {
        fn from(attributes: FileAttributes) -> Self {
            Self {
                size: attributes.size,
                create_time: attributes.create_time.as_raw(),
                change_time: attributes.change_time.as_raw(),
                is_directory: attributes.is_directory,
            }
        }
    }

    impl OpenxbdmFileAttributes {
        pub fn size(&self) -> u64 {
            self.size
        }

        pub fn create_time(&self) -> u64 {
            self.create_time
        }

        pub fn change_time(&self) -> u64 {
            self.change_time
        }

        pub fn is_directory(&self) -> bool {
            self.is_directory
        }
    }
}
