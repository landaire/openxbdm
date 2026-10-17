//! Buffered capture file writer: frame callbacks copy records into a pool
//! buffer at raised IRQL and a writer thread drains it to the file (file
//! object of the frame-log library, 0x91f6a410..0x91f6b4e8).

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::network::netcap::BufferSizes;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::CaptureFileError;
use openxbdm_server::commands::network::netcap::capture_file::CaptureIo;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;
use xbox360::status::Hresult;
use xbox360::status::KernelError;
use xbox360::status::NtStatus;
use xbox360::status::Win32Error;
use xbox360::sync::SpinLock;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use crate::kernel;

const GENERIC_READ_WRITE: AccessMask = AccessMask::GENERIC_WRITE.union(AccessMask::GENERIC_READ);
/// Writer thread creation flags for mode bit 2, which `netcap` sets: a
/// referenced thread object instead of a handle. Bit 0x4 has no known
/// meaning; stock passes it.
const THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::RETURN_THREAD_OBJECT
    .union(ThreadCreationFlags::NOT_DEBUGGABLE)
    .union(ThreadCreationFlags::PROCESSOR2)
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::from_bits_retain(0x4));
/// Writer thread exit status when it is asked to stop.
const WRITER_STOPPED: Hresult = Hresult::from_win32(Win32Error::CANCELLED);

/// Why the writer thread exited.
enum WriterExit {
    /// Waiting for the wake event failed.
    Wait(KernelError),
    /// `stop_thread` asked it to stop.
    Stopped,
    /// Writing the buffer failed.
    Write(CaptureFileError),
}

impl WriterExit {
    /// The thread exit code: a kernel status or a result value, as stock
    /// mixes them.
    fn exit_code(self) -> u32 {
        match self {
            Self::Wait(error) => NtStatus::from(error).0,
            Self::Stopped => WRITER_STOPPED.0,
            Self::Write(error) => Hresult::from(error).0,
        }
    }
}

/// Positional access to the open capture file.
struct FileIo(Handle);

impl FileIo {
    /// `NtReadFile` or `NtWriteFile` of exactly `length` bytes.
    #[inline(never)]
    fn transfer(
        &mut self,
        write: bool,
        offset: u64,
        buffer: *mut u8,
        length: u32,
    ) -> Result<(), CaptureFileError> {
        let mut io = IoStatusBlock::default();
        // SAFETY: `self.0` is the open capture file; `io`, `offset` and the
        // `length` bytes at `buffer` are live for the synchronous call.
        let status = unsafe {
            if write {
                xboxkrnl::NtWriteFile(self.0, Handle::NULL, 0, 0, &mut io, buffer, length, &offset)
            } else {
                xboxkrnl::NtReadFile(self.0, Handle::NULL, 0, 0, &mut io, buffer, length, &offset)
            }
        };
        status.result()?;
        if io.information != length {
            Err(CaptureFileError::BadLength)
        } else {
            Ok(())
        }
    }
}

impl CaptureIo for FileIo {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), CaptureFileError> {
        self.transfer(false, offset, buffer.as_mut_ptr(), buffer.len() as u32)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), CaptureFileError> {
        self.transfer(true, offset, data.as_ptr().cast_mut(), data.len() as u32)
    }

    fn truncate(&mut self, length: u64) -> Result<(), CaptureFileError> {
        for class in [
            FileInformationClass::EndOfFile,
            FileInformationClass::Allocation,
        ] {
            let mut io = IoStatusBlock::default();
            // SAFETY: `self.0` is the open capture file; `io` and the 8-byte
            // `length` are live.
            let status = unsafe {
                xboxkrnl::NtSetInformationFile(
                    self.0,
                    &mut io,
                    (&raw const length).cast(),
                    size_of::<u64>() as u32,
                    class,
                )
            };
            status.result()?;
        }
        Ok(())
    }
}

/// Fixed after `open`.
struct Config {
    handle: Handle,
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
    progress: SpinLock<Progress>,
    /// Synchronization event that wakes the writer thread.
    event: Kevent,
    /// Referenced writer thread object; 0 once asked to stop.
    thread: AtomicU32,
}

impl Writer {
    pub(super) const fn new() -> Self {
        Self {
            config: UnsafeCell::new(Config {
                handle: Handle::NULL,
                buffer: core::ptr::null_mut(),
                size: 0,
                chunk: 0,
            }),
            progress: SpinLock::new(Progress {
                fill: 0,
                position: 0,
                record_end: None,
                flushed_record_end: 0,
            }),
            event: Kevent::new(),
            thread: AtomicU32::new(0),
        }
    }

    fn config(&self) -> &Config {
        // SAFETY: written only by `open` and `release`, which run while no
        // callback or writer thread uses the writer.
        unsafe { &*self.config.get() }
    }

    fn event(&self) -> *mut Kevent {
        self.event.as_ptr()
    }

    /// Create the file, write the header, allocate the buffer, and start
    /// the writer thread (0x91f6b4e8). The writer must stay at its address
    /// until `release`.
    pub(super) fn open(
        &self,
        path: &[u8],
        sizes: BufferSizes,
        header: &[u8; capture_file::HEADER_SIZE],
        pool: PoolType,
        tag: PoolTag,
    ) -> Result<(), CaptureFileError> {
        let name = kernel::ansi_string(path);
        let attributes = ObjectAttributes {
            root_directory: if path.first() == Some(&b'\\') {
                Handle::NULL
            } else {
                Handle::DOS_DEVICES
            },
            object_name: &name,
            attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
        };
        let mut handle = Handle::NULL;
        let mut io = IoStatusBlock::default();
        // SAFETY: `handle`, `attributes`, the name it refers to, and `io`
        // are live for the call.
        let status = unsafe {
            xboxkrnl::NtCreateFile(
                (&raw mut handle).cast(),
                GENERIC_READ_WRITE,
                &attributes,
                &mut io,
                core::ptr::null(),
                FileAttributes::empty(),
                ShareAccess::READ,
                CreateDisposition::Create,
                CreateOptions::SYNCHRONOUS_IO_NONALERT,
            )
        };
        status.result()?;
        let result = self.prepare(handle, sizes, header, pool, tag);
        if result.is_err() {
            self.release();
        }
        result
    }

    fn prepare(
        &self,
        handle: Handle,
        sizes: BufferSizes,
        header: &[u8; capture_file::HEADER_SIZE],
        pool: PoolType,
        tag: PoolTag,
    ) -> Result<(), CaptureFileError> {
        // SAFETY: no other user exists during `open`.
        let config = unsafe { &mut *self.config.get() };
        config.handle = handle;
        FileIo(handle).write_at(0, header)?;
        let end = capture_file::HEADER_SIZE as u64;
        *self.progress.lock() = Progress {
            fill: 0,
            position: end,
            record_end: Some(end),
            flushed_record_end: end,
        };
        // SAFETY: pool allocation of the requested size; the result is checked below.
        let buffer = unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(sizes.buffer, tag, pool) };
        if buffer == 0 {
            return Err(CaptureFileError::OutOfMemory);
        }
        config.buffer = buffer as usize as *mut u8;
        config.size = sizes.buffer;
        config.chunk = sizes.chunk;

        // SAFETY: as above; the writer stays at its address until `release`.
        unsafe { self.event.initialize(EventType::Synchronization, false) };
        let mut flags = THREAD_FLAGS;
        if xboxkrnl::KeGetCurrentProcessType() != ProcessType::TITLE {
            flags |= ThreadCreationFlags::SYSTEM_PROCESS;
        }
        let mut object = 0u32;
        let mut thread_id = 0u32;
        // SAFETY: `object` and `thread_id` are live; the thread receives this
        // writer, which `release` keeps alive until the thread has exited.
        let status = unsafe {
            xboxkrnl::ExCreateThread(
                &mut object,
                0,
                &mut thread_id,
                0,
                writer_thread as *const () as usize as u32,
                self as *const Self as usize as u32,
                flags,
            )
        };
        status.result()?;
        self.thread.store(object, Ordering::Release);
        Ok(())
    }

    /// Copy `data` into the buffer (0x91f6a730). Runs at raised IRQL from
    /// the frame callbacks, so a full buffer cannot be waited for.
    pub(super) fn put(&self, data: &[u8], completes_record: bool) -> Result<(), CaptureFileError> {
        let config = self.config();
        let outcome = {
            let mut progress = self.progress.lock();
            if progress.record_end.is_some() {
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
            } else {
                None
            }
        };
        let Some((complete, wake)) = outcome else {
            return Err(CaptureFileError::WriteFault);
        };
        if wake {
            // SAFETY: the event was initialized by `prepare` and lives in the writer.
            unsafe { xboxkrnl::KeSetEvent(self.event(), 1, false) };
        }
        if complete {
            return Ok(());
        }
        self.progress.lock().record_end = None;
        Err(CaptureFileError::WriteFault)
    }

    /// Write out the whole buffer in pieces of at most
    /// [`capture_file::WRITE_LIMIT`] bytes (0x91f6a4e8, forced).
    fn drain(&self) -> Result<(), CaptureFileError> {
        let config = self.config();
        loop {
            let (fill, offset, committed) = {
                let progress = self.progress.lock();
                (
                    progress.fill,
                    progress.position - u64::from(progress.fill),
                    progress.record_end,
                )
            };
            if fill == 0 {
                return Ok(());
            }
            let count = fill.min(capture_file::WRITE_LIMIT);
            // SAFETY: the first `fill` buffer bytes are written and only this
            // thread moves them; producers append after them.
            let bytes = unsafe { core::slice::from_raw_parts(config.buffer, count as usize) };
            FileIo(config.handle).write_at(offset, bytes)?;
            let mut progress = self.progress.lock();
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
        }
    }

    /// Writer thread loop (0x91f6b2a0).
    fn run(&self) -> WriterExit {
        loop {
            // SAFETY: the event was initialized by `prepare` and lives in the writer.
            let status = unsafe {
                xboxkrnl::KeWaitForSingleObject(
                    self.event().cast(),
                    WaitReason::UserRequest,
                    ProcessorMode::Kernel,
                    false,
                    core::ptr::null(),
                )
            };
            if let Err(error) = status.result() {
                return WriterExit::Wait(error);
            }
            let (running, fill) = {
                let progress = self.progress.lock();
                (self.thread.load(Ordering::Acquire) != 0, progress.fill)
            };
            if !running {
                return WriterExit::Stopped;
            }
            if fill != 0
                && let Err(error) = self.drain()
            {
                return WriterExit::Write(error);
            }
        }
    }

    /// Stop the writer thread and wait for it to exit (0x91f6a460).
    fn stop_thread(&self) {
        let object = {
            let _guard = self.progress.lock();
            self.thread.swap(0, Ordering::AcqRel)
        };
        if object == 0 {
            return;
        }
        // SAFETY: the event was initialized by `prepare`; `object` is the
        // referenced writer thread, released once here.
        unsafe {
            xboxkrnl::KeSetEvent(self.event(), 1, true);
            xboxkrnl::KeWaitForSingleObject(
                object as usize as *mut _,
                WaitReason::UserRequest,
                ProcessorMode::User,
                false,
                core::ptr::null(),
            );
            xboxkrnl::ObDereferenceObject(object);
        }
    }

    /// Stop the thread, write the buffer, and finish the file (0x91f69d18).
    /// With records, the frame table starts after the last complete record
    /// written before a record was cut short (0x91f6b080).
    pub(super) fn finish(&self, recorder: &mut Recorder) -> Result<(), CaptureFileError> {
        self.stop_thread();
        self.drain()?;
        let end = {
            let progress = self.progress.lock();
            match progress.record_end {
                None if recorder.frames() > 0 => progress.flushed_record_end,
                _ => progress.position,
            }
        };
        recorder.finish(&mut FileIo(self.config().handle), end)
    }

    /// Stop the thread, free the buffer, and close the file (0x91f6b210).
    pub(super) fn release(&self) {
        self.stop_thread();
        // SAFETY: the thread has exited and no callback is attached.
        let config = unsafe { &mut *self.config.get() };
        if !config.buffer.is_null() {
            // SAFETY: the buffer was allocated by `prepare` and the thread has exited.
            unsafe { xboxkrnl::ExFreePool(config.buffer as usize as u32) };
            config.buffer = core::ptr::null_mut();
        }
        if !config.handle.is_null() {
            // SAFETY: the file handle was opened by `open` and is closed once.
            unsafe { xboxkrnl::NtClose(config.handle) };
            config.handle = Handle::NULL;
        }
    }
}

/// Writer thread start routine (0x91f6b428).
extern "C" fn writer_thread(context: u32) -> u32 {
    // SAFETY: `open` passes the writer, which outlives the thread:
    // `stop_thread` waits for it to exit before the writer is freed.
    let writer = unsafe { &*(context as usize as *const Writer) };
    let status = writer.run().exit_code();
    // SAFETY: ends the writer thread; it holds no resources that need unwinding.
    unsafe { xboxkrnl::ExTerminateThread(status) }
}
