//! Buffered capture file writer: frame callbacks copy records into a pool
//! buffer at raised IRQL and a writer thread drains it to the file (file
//! object of the frame-log library, 0x91f6a410..0x91f6b4e8).

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::network::netcap::BufferSizes;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::CaptureIo;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;

use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::IoStatusBlock;
use crate::kernel::ObjectAttributes;
use crate::kernel::SpinLocked;

/// Result bit marking a kernel status carried as a result.
const NT_STATUS_BIT: u32 = 0x1000_0000;
const GENERIC_READ_WRITE: u32 = 0xc000_0000;
const FILE_SHARE_READ: u32 = 1;
/// The capture file must not exist yet (mode bit 1).
const FILE_CREATE: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
/// Root directory handle for names that do not start with a backslash.
const RELATIVE_ROOT: u32 = 0xffff_fffd;
const FILE_END_OF_FILE_INFORMATION: u32 = 0x14;
const FILE_ALLOCATION_INFORMATION: u32 = 0x13;
/// Writer thread creation flags for mode bit 2, which `netcap` sets; the
/// 0x80 bit returns a referenced thread object instead of a handle.
const THREAD_FLAGS: u32 = 0x0400_04a4;
/// Added when the caller is not in the system process type.
const THREAD_FLAG_FOREIGN_PROCESS: u32 = 0x2;
const SYSTEM_PROCESS_TYPE: u32 = 1;
const EXECUTIVE: u32 = 3;
const KERNEL_MODE: u32 = 0;
const WAIT_KERNEL_MODE: u32 = 1;
/// Writer thread exit status when it is asked to stop.
const WRITER_STOPPED: u32 = 0x8007_04c7;

fn nt_failure(status: u32) -> Hresult {
    Hresult(status | NT_STATUS_BIT)
}

fn failed(status: u32) -> bool {
    (status as i32) < 0
}

/// Positional access to the open capture file.
struct FileIo(u32);

impl CaptureIo for FileIo {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Hresult> {
        let mut io = IoStatusBlock::default();
        let status = kernel::NtReadFile(
            self.0,
            0,
            0,
            0,
            &mut io,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &offset,
        );
        if failed(status) {
            return Err(nt_failure(status));
        }
        if io.information != buffer.len() as u32 {
            Err(capture_file::BAD_LENGTH)
        } else {
            Ok(())
        }
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), Hresult> {
        let mut io = IoStatusBlock::default();
        let status = kernel::NtWriteFile(
            self.0,
            0,
            0,
            0,
            &mut io,
            data.as_ptr(),
            data.len() as u32,
            &offset,
        );
        if failed(status) {
            return Err(nt_failure(status));
        }
        if io.information != data.len() as u32 {
            Err(capture_file::BAD_LENGTH)
        } else {
            Ok(())
        }
    }

    fn truncate(&mut self, length: u64) -> Result<(), Hresult> {
        for class in [FILE_END_OF_FILE_INFORMATION, FILE_ALLOCATION_INFORMATION] {
            let mut io = IoStatusBlock::default();
            let status =
                kernel::NtSetInformationFile(self.0, &mut io, (&raw const length).cast(), 8, class);
            if failed(status) {
                return Err(nt_failure(status));
            }
        }
        Ok(())
    }
}

/// Fixed after `open`.
struct Config {
    handle: u32,
    buffer: *mut u8,
    size: u32,
    /// Buffered bytes that wake the writer thread.
    chunk: u32,
}

/// Buffer state shared by the frame callbacks and the writer thread.
struct Progress {
    /// Buffered bytes.
    fill: u32,
    /// File offset after the buffered bytes.
    position: u64,
    /// End of the last complete record; `None` after a record was cut
    /// short by a full buffer.
    record_end: Option<u64>,
    /// `record_end` as of the last buffer write.
    flushed_record_end: u64,
}

pub(super) struct Writer {
    config: UnsafeCell<Config>,
    progress: SpinLocked<Progress>,
    /// Synchronization event that wakes the writer thread.
    event: UnsafeCell<[u32; 4]>,
    /// Referenced writer thread object; 0 once asked to stop.
    thread: AtomicU32,
}

impl Writer {
    pub(super) const fn new() -> Self {
        Self {
            config: UnsafeCell::new(Config {
                handle: 0,
                buffer: core::ptr::null_mut(),
                size: 0,
                chunk: 0,
            }),
            progress: SpinLocked::new(Progress {
                fill: 0,
                position: 0,
                record_end: None,
                flushed_record_end: 0,
            }),
            event: UnsafeCell::new([0; 4]),
            thread: AtomicU32::new(0),
        }
    }

    fn config(&self) -> &Config {
        // SAFETY: written only by `open` and `release`, which run while no
        // callback or writer thread uses the writer.
        unsafe { &*self.config.get() }
    }

    fn event(&self) -> *mut u32 {
        self.event.get().cast()
    }

    /// Create the file, write the header, allocate the buffer, and start
    /// the writer thread (0x91f6b4e8). The writer must stay at its address
    /// until `release`.
    pub(super) fn open(
        &self,
        path: &[u8],
        sizes: BufferSizes,
        header: &[u8; capture_file::HEADER_SIZE],
        pool: u32,
        tag: u32,
    ) -> Result<(), Hresult> {
        let name = AnsiString::new(path);
        let attributes = ObjectAttributes {
            root_directory: if path.first() == Some(&b'\\') {
                0
            } else {
                RELATIVE_ROOT
            },
            object_name: &name,
            attributes: kernel::OBJ_CASE_INSENSITIVE,
        };
        let mut handle = 0u32;
        let mut io = IoStatusBlock::default();
        let status = kernel::NtCreateFile(
            &mut handle,
            GENERIC_READ_WRITE,
            &attributes,
            &mut io,
            core::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_SYNCHRONOUS_IO_NONALERT,
        );
        if failed(status) {
            return Err(nt_failure(status));
        }
        let result = self.prepare(handle, sizes, header, pool, tag);
        if result.is_err() {
            self.release();
        }
        result
    }

    fn prepare(
        &self,
        handle: u32,
        sizes: BufferSizes,
        header: &[u8; capture_file::HEADER_SIZE],
        pool: u32,
        tag: u32,
    ) -> Result<(), Hresult> {
        // SAFETY: no other user exists during `open`.
        let config = unsafe { &mut *self.config.get() };
        config.handle = handle;
        FileIo(handle).write_at(0, header)?;
        let end = capture_file::HEADER_SIZE as u64;
        self.progress.with(|progress| {
            *progress = Progress {
                fill: 0,
                position: end,
                record_end: Some(end),
                flushed_record_end: end,
            };
        });
        let buffer = kernel::ExAllocatePoolTypeWithTag(sizes.buffer, tag, pool);
        if buffer == 0 {
            return Err(Hresult::OUT_OF_MEMORY);
        }
        config.buffer = buffer as usize as *mut u8;
        config.size = sizes.buffer;
        config.chunk = sizes.chunk;

        let list = self.event().wrapping_add(2) as usize as u32;
        // SAFETY: as above. Synchronization event, not signaled, empty wait
        // list.
        unsafe { *self.event.get() = [0x0100_0000, 0, list, list] };
        let mut flags = THREAD_FLAGS;
        if kernel::KeGetCurrentProcessType() != SYSTEM_PROCESS_TYPE {
            flags |= THREAD_FLAG_FOREIGN_PROCESS;
        }
        let mut object = 0u32;
        let mut thread_id = 0u32;
        let status = kernel::ExCreateThread(
            &mut object,
            0,
            &mut thread_id,
            0,
            writer_thread as *const () as usize as u32,
            self as *const Self as usize as u32,
            flags,
        );
        if failed(status) {
            return Err(nt_failure(status));
        }
        self.thread.store(object, Ordering::Release);
        Ok(())
    }

    /// Copy `data` into the buffer (0x91f6a730). Runs at raised IRQL from
    /// the frame callbacks, so a full buffer cannot be waited for.
    pub(super) fn put(&self, data: &[u8], completes_record: bool) -> Result<(), Hresult> {
        let config = self.config();
        let outcome = self.progress.with(|progress| {
            progress.record_end?;
            let count = data.len().min((config.size - progress.fill) as usize);
            // SAFETY: `fill + count` stays within the buffer of `size` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    config.buffer.add(progress.fill as usize),
                    count,
                );
            }
            progress.fill += count as u32;
            progress.position += count as u64;
            let complete = count == data.len();
            if complete && completes_record {
                progress.record_end = Some(progress.position);
            }
            Some((complete, progress.fill >= config.chunk))
        });
        let Some((complete, wake)) = outcome else {
            return Err(capture_file::WRITE_FAULT);
        };
        if wake {
            kernel::KeSetEvent(self.event(), 1, 0);
        }
        if complete {
            return Ok(());
        }
        self.progress.with(|progress| progress.record_end = None);
        Err(capture_file::WRITE_FAULT)
    }

    /// Write out the whole buffer in pieces of at most
    /// [`capture_file::WRITE_LIMIT`] bytes (0x91f6a4e8, forced).
    fn drain(&self) -> Result<(), Hresult> {
        let config = self.config();
        loop {
            let (fill, offset, committed) = self.progress.with(|progress| {
                (
                    progress.fill,
                    progress.position - u64::from(progress.fill),
                    progress.record_end,
                )
            });
            if fill == 0 {
                return Ok(());
            }
            let count = fill.min(capture_file::WRITE_LIMIT);
            // SAFETY: the first `fill` buffer bytes are written and only this
            // thread moves them; producers append after them.
            let bytes = unsafe { core::slice::from_raw_parts(config.buffer, count as usize) };
            FileIo(config.handle).write_at(offset, bytes)?;
            self.progress.with(|progress| {
                if let Some(end) = committed {
                    progress.flushed_record_end = end;
                }
                // SAFETY: the bytes after `count` up to `fill` are buffered.
                unsafe {
                    core::ptr::copy(
                        config.buffer.add(count as usize),
                        config.buffer,
                        (progress.fill - count) as usize,
                    );
                }
                progress.fill -= count;
            });
        }
    }

    /// Writer thread loop (0x91f6b2a0).
    fn run(&self) -> u32 {
        loop {
            let status = kernel::KeWaitForSingleObject(
                self.event(),
                EXECUTIVE,
                KERNEL_MODE,
                0,
                core::ptr::null(),
            );
            if failed(status) {
                return status;
            }
            let (running, fill) = self
                .progress
                .with(|progress| (self.thread.load(Ordering::Acquire) != 0, progress.fill));
            if !running {
                return WRITER_STOPPED;
            }
            if fill != 0
                && let Err(error) = self.drain()
            {
                return error.0;
            }
        }
    }

    /// Stop the writer thread and wait for it to exit (0x91f6a460).
    fn stop_thread(&self) {
        let object = self
            .progress
            .with(|_| self.thread.swap(0, Ordering::AcqRel));
        if object == 0 {
            return;
        }
        kernel::KeSetEvent(self.event(), 1, 1);
        kernel::KeWaitForSingleObject(
            object as usize as *mut u32,
            EXECUTIVE,
            WAIT_KERNEL_MODE,
            0,
            core::ptr::null(),
        );
        kernel::ObDereferenceObject(object);
    }

    /// Stop the thread, write the buffer, and finish the file (0x91f69d18).
    /// With records, the frame table starts after the last complete record
    /// written before a record was cut short (0x91f6b080).
    pub(super) fn finish(&self, recorder: &mut Recorder) -> Result<(), Hresult> {
        self.stop_thread();
        self.drain()?;
        let end = self.progress.with(|progress| match progress.record_end {
            None if recorder.frames() > 0 => progress.flushed_record_end,
            _ => progress.position,
        });
        recorder.finish(&mut FileIo(self.config().handle), end)
    }

    /// Stop the thread, free the buffer, and close the file (0x91f6b210).
    pub(super) fn release(&self) {
        self.stop_thread();
        // SAFETY: the thread has exited and no callback is attached.
        let config = unsafe { &mut *self.config.get() };
        if !config.buffer.is_null() {
            kernel::ExFreePool(config.buffer as usize as u32);
            config.buffer = core::ptr::null_mut();
        }
        if config.handle != 0 {
            kernel::NtClose(config.handle);
            config.handle = 0;
        }
    }
}

/// Writer thread start routine (0x91f6b428).
extern "C" fn writer_thread(context: u32) -> u32 {
    // SAFETY: `open` passes the writer, which outlives the thread:
    // `stop_thread` waits for it to exit before the writer is freed.
    let writer = unsafe { &*(context as usize as *const Writer) };
    let status = writer.run();
    kernel::ExTerminateThread(status);
    status
}
