//! Simulated `netcap` services: frames fed by tests are captured through the
//! shared capture file encoder and a buffered writer into a file of the
//! simulated file system.

mod writer;

use std::mem;

use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netcap;
use openxbdm_server::commands::network::netcap::CaptureClose;
use openxbdm_server::commands::network::netcap::CaptureFlags;
use openxbdm_server::commands::network::netcap::CaptureRequest;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::Admission;
use openxbdm_server::commands::network::netcap::capture_file::CaptureFileError;
use openxbdm_server::commands::network::netcap::capture_file::CaptureIo;
use openxbdm_server::commands::network::netcap::capture_file::Clock;
use openxbdm_server::commands::network::netcap::capture_file::LocalTime;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::writer::Writer;
use crate::backend::MockBackend;

/// Local time the simulated console reports.
pub const LOCAL_TIME: LocalTime = LocalTime {
    year: 2026,
    month: 10,
    day_of_week: 3,
    day: 14,
    hour: 12,
    minute: 0,
    second: 0,
    millisecond: 0,
};

/// How the capture receives frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    /// Ethernet intercept callbacks.
    Intercept,
    /// Chained into the network simulator instance.
    Simulator,
    /// Attached, but a failed simulator creation removed the intercept and
    /// no instance forwards frames.
    Unrouted,
}

/// An open capture context.
#[derive(Debug)]
pub struct Capture {
    writer: Writer,

    /// Object name the console opened.
    pub object_path: Vec<u8>,
    pub request_flags: CaptureFlags,
    pub sizes: netcap::BufferSizes,

    recorder: Recorder,
    clock: Clock,
    /// Flags the callbacks apply.
    flags: CaptureFlags,
    /// First frame callback failure.
    error: Option<CaptureFileError>,
}

impl Capture {
    /// Append one frame (0x91f699f8).
    fn append(
        &mut self,
        backend: &mut MockBackend,
        frame: &[u8],
        now: u64,
    ) -> Result<(), CaptureFileError> {
        let length = frame.len() as u32;
        if self.recorder.admit(length)? == Admission::Discard {
            return Ok(());
        }

        let header = capture_file::record_header(self.clock.timestamp(now), length);
        let writer = &mut self.writer;
        let written = writer
            .put(backend, &header, false)
            .and_then(|()| writer.put(backend, frame, false))
            .and_then(|()| writer.put(backend, &capture_file::RECORD_TRAILER, true));

        match written {
            Ok(()) => self.recorder.recorded(length),
            Err(error) => self.recorder.failed(error),
        }

        written
    }
}

/// Simulated state of `netcap`.
#[derive(Debug)]
pub struct Mock {
    pub local_time: LocalTime,
    /// Time base reading; tests advance it between frames.
    pub timebase: u64,

    pub promiscuous: bool,
    pub attachment: Option<Attachment>,
    pub capture: Option<Capture>,

    /// Result of the next capture creation.
    pub open_error: Option<CaptureFileError>,
    /// Fail the next request to enable promiscuous mode.
    pub promiscuous_error: bool,
    /// Result of the next intercept installation.
    pub intercept_error: Option<WsaError>,
    /// The writer thread does not get to run until the capture stops, as
    /// when the network stack outpaces it.
    pub writer_stalled: bool,
    /// Result of finishing the next capture file.
    pub finish_error: Option<CaptureFileError>,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            local_time: LOCAL_TIME,
            timebase: 0,
            promiscuous: false,
            attachment: None,
            capture: None,
            open_error: None,
            promiscuous_error: false,
            intercept_error: None,
            writer_stalled: false,
            finish_error: None,
        }
    }
}

impl MockBackend {
    /// The network stack transmits `frame` (0x91f34de0).
    pub fn transmit_frame(&mut self, frame: &[u8]) {
        self.deliver_frame(frame, false);
    }

    /// The network stack receives `frame` (0x91f34e78).
    pub fn receive_frame(&mut self, frame: &[u8]) {
        self.deliver_frame(frame, true);
    }

    /// The simulated network simulator releases frames without delay, so a
    /// chained capture records them as the intercept does.
    fn deliver_frame(&mut self, frame: &[u8], received: bool) {
        let mock = &mut self.network.netcap;
        if !matches!(
            mock.attachment,
            Some(Attachment::Intercept | Attachment::Simulator)
        ) {
            return;
        }

        let now = mock.timebase;
        let Some(mut capture) = mock.capture.take() else {
            return;
        };

        if capture.error.is_none()
            && !(received && capture.flags.skips_received(frame))
            && let Err(error) = capture.append(self, frame, now)
        {
            capture.error = Some(error);
        }

        self.network.netcap.capture = Some(capture);
    }

    /// Create the capture file and write its header (0x91f6b4e8).
    fn create_capture(
        &mut self,
        request: &CaptureRequest<'_>,
    ) -> Result<Capture, CaptureFileError> {
        /// Directory that resolves names without a leading backslash, which
        /// the console opens relative to root handle 0xfffffffd.
        const RELATIVE_ROOT: &[u8] = b"\\??\\";
        /// Time base rate of the simulated console.
        const TIMEBASE_FREQUENCY: u64 = 50_000_000;

        let mut name = Vec::new();
        if request.path.first() != Some(&b'\\') {
            name.extend_from_slice(RELATIVE_ROOT);
        }
        name.extend_from_slice(request.path);

        let create = CreateRequest {
            access: AccessMask::GENERIC_READ.union(AccessMask::GENERIC_WRITE),
            allocation_size: None,
            attributes: FileAttributes::empty(),
            share: ShareAccess::READ,
            disposition: CreateDisposition::Create,
            options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
        };
        let handle = filesystem::Backend::create_file(self, &name, &create)?;
        let writer = Writer::new(
            handle,
            name,
            request.sizes,
            capture_file::HEADER_SIZE as u64,
        );

        let header = capture_file::file_header(&self.network.netcap.local_time);
        if let Err(error) = writer.io(self).write_at(0, &header) {
            filesystem::Backend::close_file(self, handle);
            return Err(error);
        }

        Ok(Capture {
            writer,
            object_path: request.path.to_vec(),
            request_flags: request.flags,
            sizes: request.sizes,
            recorder: Recorder::new(request.data_limit),
            clock: Clock::new(self.network.netcap.timebase, TIMEBASE_FREQUENCY),
            flags: request.flags,
            error: None,
        })
    }
}

impl netcap::Backend for MockBackend {
    fn open_capture(&mut self, request: &CaptureRequest<'_>) -> Result<(), CaptureFileError> {
        if let Some(error) = self.network.netcap.open_error.take() {
            return Err(error);
        }

        let capture = self.create_capture(request)?;
        self.network.netcap.capture = Some(capture);

        Ok(())
    }

    fn set_promiscuous(&mut self, enable: bool) -> bool {
        let mock = &mut self.network.netcap;
        if enable && mem::take(&mut mock.promiscuous_error) {
            return false;
        }

        mock.promiscuous = enable;

        true
    }

    fn attach_capture(&mut self, flags: CaptureFlags) -> Result<(), WsaError> {
        let simulator = self.network.netsim.has_instance();
        let mock = &mut self.network.netcap;

        if let Some(capture) = mock.capture.as_mut() {
            capture.flags = flags;
            capture.error = None;
        }

        if simulator {
            mock.attachment = Some(Attachment::Simulator);
            return Ok(());
        }
        if let Some(error) = mock.intercept_error.take() {
            return Err(error);
        }

        mock.attachment = Some(Attachment::Intercept);

        Ok(())
    }

    fn detach_capture(&mut self) {
        self.network.netcap.attachment = None;
    }

    fn capture_error(&self) -> Option<CaptureFileError> {
        self.network
            .netcap
            .capture
            .as_ref()
            .and_then(|capture| capture.error)
    }

    fn close_capture(&mut self) -> CaptureClose {
        self.network.netcap.attachment = None;

        let Some(mut capture) = self.network.netcap.capture.take() else {
            return CaptureClose {
                result: Ok(()),
                frames: 0,
            };
        };

        capture.recorder.begin_close();
        let result = match self.network.netcap.finish_error.take() {
            Some(error) => Err(error),
            None => capture.writer.finish(self, &mut capture.recorder),
        };
        filesystem::Backend::close_file(self, capture.writer.handle());

        CaptureClose {
            result,
            frames: capture.recorder.frames(),
        }
    }
}
