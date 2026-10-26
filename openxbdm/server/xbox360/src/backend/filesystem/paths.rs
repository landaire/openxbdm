//! The published drive table and drive path translation on the threads of
//! the monitor exports.

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::OBJECT_PATH_LIMIT;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::filesystem::PathServices;
use openxbdm_server::commands::filesystem::ScratchBlock;
use openxbdm_server::commands::hardware::pgo::IniFiles;
use xbox360::sync::SpinLock;

use crate::backend::console;
use crate::backend::debugger;
use crate::kernel;

/// The server's drive table (stock 0x91f96bf8), for other threads.
static DRIVES: SpinLock<DriveTable> = SpinLock::new(DriveTable::new());

/// [`PathServices`] and [`IniFiles`] of the calling thread.
pub(crate) struct CallerPaths {
    /// The longest mapped target a translation reads at once.
    scratch: [u8; OBJECT_PATH_LIMIT + 1],
}

impl CallerPaths {
    pub(crate) const fn new() -> Self {
        Self {
            scratch: [0; OBJECT_PATH_LIMIT + 1],
        }
    }
}

impl PathServices for CallerPaths {
    fn read_target(&mut self, address: u32, length: usize) -> Option<&[u8]> {
        let length = length.min(self.scratch.len());
        let bytes = &mut self.scratch[..length];

        debugger::copy_target(address, bytes).then_some(&*bytes)
    }

    fn resolve_link(&mut self, link: &[u8], target: &mut [u8]) -> Result<usize, KernelError> {
        super::translate_symbolic_link(link, target)
    }

    fn published_trace_mask(&mut self) -> TraceMask {
        console::trace_mask()
    }

    fn print_trace(&mut self, text: &[u8]) {
        kernel::debug_print_bytes(text);
    }
}

impl IniFiles for CallerPaths {
    fn create_file(
        &mut self,
        path: &[u8],
        request: &CreateRequest,
    ) -> Result<FileHandle, KernelError> {
        super::create_file(path, request)
    }

    fn read_file(&mut self, handle: FileHandle, buffer: &mut [u8]) -> Result<u32, KernelError> {
        super::read_file(handle, None, buffer)
    }

    fn close_file(&mut self, handle: FileHandle) {
        super::close_file(handle);
    }

    fn allocate_scratch(&mut self, size: u32) -> Option<ScratchBlock> {
        super::allocate_scratch(size)
    }

    fn free_scratch(&mut self, block: ScratchBlock) {
        super::free_scratch(block);
    }
}

/// Keep a copy of the server's drive table for other threads.
pub(crate) fn publish_drives(drives: &DriveTable) {
    DRIVES.lock().clone_from(drives);
}

/// A copy of the published drive table. Translation runs outside the lock:
/// it calls kernel services that require passive level.
pub(crate) fn published_drives() -> DriveTable {
    DRIVES.lock().clone()
}

/// Object name of drive path `name` (0x91f2e888) on the calling thread.
pub(crate) fn translate(name: &[u8]) -> Option<ObjectPath> {
    published_drives().translate(&mut CallerPaths::new(), name)
}

/// Drive path of object name `object` (0x91f2e750) on the calling thread;
/// returns the length.
pub(crate) fn drive_path(object: &[u8], output: &mut [u8]) -> usize {
    published_drives().object_path_to_drive_path(&mut CallerPaths::new(), object, output)
}

/// Open drive path `name` (0x91f2eb68) on the calling thread; a path that
/// does not translate fails with [`KernelError::NoSuchFile`].
pub(crate) fn open_translated(
    name: &[u8],
    request: &CreateRequest,
) -> Result<FileHandle, KernelError> {
    let path = translate(name).ok_or(KernelError::NoSuchFile)?;

    super::create_file(path.as_bytes(), request)
}
