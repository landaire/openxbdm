//! The `dmtelllog` log: its open state, the engine callback that writes
//! the log file, and the producer control codes.

use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session::LogEngineError;
use openxbdm_server::commands::session::TellLogAreas;
use openxbdm_server::commands::session::TellLogBackend;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;
use openxbdm_server::commands::session::TellLogWriter;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;

use super::log_engine;
use super::log_engine::Engine;
use crate::backend::Console;

static TELL_LOG: TellLog = TellLog {
    engine: AtomicU32::new(0),
    file: AtomicU32::new(0),
    closing: AtomicBool::new(false),
    area: AtomicU32::new(0),
    entry_size: AtomicU32::new(0),
    worker: AtomicU32::new(0),
    producers: AtomicU32::new(0),
};

static TELL_LOG_WRITER: WriterCell = WriterCell(UnsafeCell::new(TellLogWriter::new()));

/// Open-log state (stock 0x91fa1fe4..0x91fa1ff4), read by the producers
/// and the engine writer on other threads.
struct TellLog {
    /// Engine address; 0 while no log is open.
    engine: AtomicU32,
    file: AtomicU32,
    /// The log is closing; producers leave it alone.
    closing: AtomicBool,

    area: AtomicU32,
    entry_size: AtomicU32,

    /// Thread id of the engine worker while the log is open; the server
    /// thread may be waiting for it.
    worker: AtomicU32,
    /// Producers inside the engine. Stock destroys the engine without
    /// waiting for them; the stop here waits so that none uses it after.
    producers: AtomicU32,
}

impl TellLogBackend for Console {
    fn tell_log_area(&mut self) -> Option<TellLogAreas> {
        tell_log_engine()
            .map(|_| TellLogAreas::from_bits_retain(TELL_LOG.area.load(Ordering::Acquire)))
    }

    fn set_tell_log_area(&mut self, area: TellLogAreas) {
        TELL_LOG.area.store(area.bits(), Ordering::Release);
    }

    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: TellLogAreas,
        config: TellLogConfig,
    ) -> Result<(), LogEngineError> {
        TELL_LOG.file.store(file.0, Ordering::Release);

        let context = &TELL_LOG as *const TellLog as usize as u32;
        match log_engine::create_for_callback(context, tell_log_write, config) {
            Ok(engine) => {
                TELL_LOG
                    .entry_size
                    .store(config.entry_size, Ordering::Release);
                TELL_LOG.area.store(area.bits(), Ordering::Release);
                TELL_LOG
                    .worker
                    .store(log_engine::worker_id(engine), Ordering::Release);
                TELL_LOG.engine.store(engine.address(), Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                TELL_LOG.file.store(0, Ordering::Release);
                Err(error)
            }
        }
    }

    fn tell_log_close(&mut self) -> Option<TellLogCounters> {
        let engine = tell_log_engine()?;

        TELL_LOG.closing.store(true, Ordering::SeqCst);
        log_engine::write(engine, &[0]);

        Some(log_engine::counters(engine))
    }

    fn tell_log_stop(&mut self) -> Option<FileHandle> {
        let engine = tell_log_engine()?;

        // Producers that entered before the closing flag finish first; the
        // running worker frees the entries they may wait for.
        while TELL_LOG.producers.load(Ordering::SeqCst) != 0 {
            sleep(Duration::from_millis(1));
        }

        // SAFETY: producers have left and the closing flag keeps new ones
        // away from the engine word until it is cleared below, after the
        // close; nothing else uses the engine off the server thread.
        unsafe { log_engine::close_after_worker(engine) };
        TELL_LOG.engine.store(0, Ordering::SeqCst);
        TELL_LOG.worker.store(0, Ordering::Release);
        TELL_LOG.area.store(0, Ordering::Release);
        TELL_LOG.closing.store(false, Ordering::SeqCst);

        Some(FileHandle(TELL_LOG.file.swap(0, Ordering::AcqRel)))
    }
}

/// Producer record of monitor control code 0x88. The length is the high
/// half of the first word, read with one word load as stock reads it; the
/// load is atomic so that it is not narrowed to a halfword load.
#[repr(C)]
pub(super) struct TellLogRecord {
    /// Text length in bits 16 to 31; bits 0 to 15 are unused.
    length_word: AtomicU32,
    /// Address of the text.
    text: u32,
}

impl TellLogRecord {
    const LENGTH_SHIFT: u32 = 16;

    #[inline(always)]
    pub(super) fn new(length: u16, text: u32) -> Self {
        Self {
            length_word: AtomicU32::new(u32::from(length) << Self::LENGTH_SHIFT),
            text,
        }
    }

    #[inline(always)]
    fn length(&self) -> u32 {
        self.length_word.load(Ordering::Relaxed) >> Self::LENGTH_SHIFT
    }
}

/// The writer's collection buffer; it outlives a log, as stock's static
/// buffer does.
struct WriterCell(UnsafeCell<TellLogWriter>);

// SAFETY: only the worker of the open log touches the writer.
unsafe impl Sync for WriterCell {}

/// Thread id of the log worker while a log is open.
#[inline(always)]
pub(super) fn worker() -> Option<NonZeroU32> {
    NonZeroU32::new(TELL_LOG.worker.load(Ordering::Acquire))
}

fn tell_log_engine() -> Option<Engine> {
    // SAFETY: the word holds 0 or the engine of the open log. Only
    // `tell_log_stop` on the server thread destroys the engine, after
    // `tell_log_close` set the closing flag: it waits until no producer is
    // inside `service_tell_log_record`, closes the engine, and then clears
    // the word. Producers test the flag before they load the word, so none
    // uses the engine from that wait on; the other callers run on the
    // server thread or only test whether a log is open.
    unsafe { Engine::new(TELL_LOG.engine.load(Ordering::SeqCst)) }
}

/// Engine callback of the log (stock 0x91f51938): collect the entry text
/// and write the collection to the log file. The state is static, so the
/// context is not read. A success carries the NT status form.
extern "C" fn tell_log_write(_context: u32, entry: u32, length: u32) -> Hresult {
    // SAFETY: only the worker of the open log calls the writer.
    let writer = unsafe { &mut *TELL_LOG_WRITER.0.get() };
    // SAFETY: the worker passes an entry of `length` bytes.
    let entry =
        unsafe { core::slice::from_raw_parts(entry as usize as *const u8, length as usize) };

    let file = TELL_LOG.file.load(Ordering::Acquire);
    let closing = TELL_LOG.closing.load(Ordering::Acquire);
    let mut write = |bytes: &[u8]| write_log(file, bytes);

    match writer.process(entry, closing, &mut write) {
        Ok(()) => Hresult::from_nt(NtStatus::SUCCESS),
        Err(error) => Hresult::from(error),
    }
}

fn write_log(file: u32, bytes: &[u8]) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();

    // SAFETY: `file` is the open log file and `bytes` is valid for its
    // length.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(file),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            bytes.as_ptr(),
            bytes.len() as u32,
            core::ptr::null(),
        )
    };

    status.result()
}

/// Monitor control code 0x88 (stock 0x91f51d58): write a record to the
/// open log through export 363.
///
/// # Safety
///
/// `argument` must be 0 or the address of a [`TellLogRecord`] whose text
/// holds its length in readable bytes, both unchanged for the call.
pub(crate) unsafe fn service_tell_log_record(argument: u32) -> u32 {
    TELL_LOG.producers.fetch_add(1, Ordering::SeqCst);

    // The closing flag is read first: a stop clears the engine before the
    // flag.
    if !TELL_LOG.closing.load(Ordering::SeqCst)
        && let Some(engine) = tell_log_engine()
        // SAFETY: the caller's contract.
        && let Some(record) =
            unsafe { core::ptr::with_exposed_provenance::<TellLogRecord>(argument as usize).as_ref() }
    {
        let length = record.length();
        let text = record.text;
        if length != 0 && text != 0 {
            // SAFETY: the record's text holds `length` bytes.
            let text =
                unsafe { core::slice::from_raw_parts(text as usize as *const u8, length as usize) };
            log_engine::write(engine, text);
        }
    }

    TELL_LOG.producers.fetch_sub(1, Ordering::SeqCst);

    0
}

/// Monitor control code 0x89: entry size of the open log, else 0.
pub(crate) fn service_tell_log_entry_size(_argument: u32) -> u32 {
    tell_log_engine().map_or(0, |_| TELL_LOG.entry_size.load(Ordering::Acquire))
}

/// Monitor control code 0x8a: area bits of the open log, else 0.
pub(crate) fn service_tell_log_area(_argument: u32) -> u32 {
    tell_log_engine().map_or(0, |_| TELL_LOG.area.load(Ordering::Acquire))
}
