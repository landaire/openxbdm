//! Simulated capture engine of instrumented titles.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::Instrumentation;
use openxbdm_server::commands::performance::capture::Started;

/// Simulated capture engine of instrumented titles; the control sequences
/// run through `capture::{start, stop, abort}`.
#[derive(Debug, Clone)]
pub struct Capture {
    pub fast_cap: bool,
    pub call_cap: bool,
    /// Calls of the kernel call-cap service (debug monitor service 2).
    pub kernel_call_cap: Vec<bool>,

    pub flags: CaptureFlags,
    pub previous_flags: CaptureFlags,

    /// Buffers of a running or stopped capture.
    pub session: Option<CaptureSession>,
    /// A processor buffer filled up.
    pub full: bool,

    pub title_terminated: bool,
    /// Result word of a capture handed to the title; `None` when the title
    /// published no control words.
    pub title_capture: Option<Hresult>,

    pub counters_ready: bool,
    /// Object names of written capture files.
    pub written: Vec<Vec<u8>>,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            fast_cap: false,
            call_cap: false,
            kernel_call_cap: Vec::new(),
            flags: CaptureFlags::IDLE,
            previous_flags: CaptureFlags(0),
            session: None,
            full: false,
            title_terminated: false,
            title_capture: None,
            counters_ready: true,
            written: Vec::new(),
        }
    }
}

impl Capture {
    pub(super) fn status(&self) -> Result<(), CaptureError> {
        if self.title_terminated {
            return Err(CaptureError::TitleTerminated);
        }

        match &self.session {
            Some(session) if session.recording => {
                if self.full {
                    Err(CaptureError::BufferFull)
                } else {
                    Ok(())
                }
            }
            _ => Err(CaptureError::NoCapture),
        }
    }
}

impl capture::Engine for Capture {
    fn instrumented(&mut self, kind: Instrumentation) -> bool {
        match kind {
            Instrumentation::FastCap => self.fast_cap,
            Instrumentation::CallCap => self.call_cap,
        }
    }

    fn set_kernel_call_cap(&mut self, enable: bool) -> Result<(), KernelError> {
        self.kernel_call_cap.push(enable);

        Ok(())
    }

    fn set_title_terminated(&mut self, terminated: bool) {
        self.title_terminated = terminated;
    }

    fn request_title_capture(&mut self, _megabytes: u8) -> Result<Started, CaptureError> {
        self.title_capture
            .map_or(Err(CaptureError::TitleCaptureFailed), capture::title_result)
    }

    fn begin(
        &mut self,
        name: &[u8],
        buffer_size: u32,
        exclusive: bool,
    ) -> Result<Started, CaptureError> {
        if let Some(session) = self.session.as_mut().filter(|session| session.recording) {
            if exclusive {
                return Err(CaptureError::AlreadyRunning);
            }
            session.name = name.to_vec();
            return Ok(Started::Continued);
        }

        self.full = false;
        self.session = Some(CaptureSession {
            name: name.to_vec(),
            buffer_size,
            recording: true,
        });

        Ok(Started::Recording)
    }

    fn end(&mut self) -> Result<(), CaptureError> {
        match &mut self.session {
            Some(session) if session.recording => {
                session.recording = false;
                if self.full {
                    Err(CaptureError::BufferFull)
                } else {
                    Ok(())
                }
            }
            _ => Err(CaptureError::NoCapture),
        }
    }

    fn flags(&mut self) -> CaptureFlags {
        self.flags
    }

    fn retire_flags(&mut self, previous: CaptureFlags) {
        self.flags = CaptureFlags::IDLE;
        self.previous_flags = previous;
    }

    fn finish_counters(&mut self, _flags: CaptureFlags) -> Result<(), CaptureError> {
        Ok(())
    }

    fn release_counters(&mut self) {
        self.counters_ready = true;
    }

    fn counters_ready(&mut self) -> bool {
        self.counters_ready
    }

    fn try_lock(&mut self) -> bool {
        true
    }

    // The simulated engine has no lock to release.
    fn unlock(&mut self) {}

    /// An untranslatable name fails the open and keeps the buffers.
    fn write(&mut self, paths: &mut dyn capture::Paths) -> Result<(), KernelError> {
        let Some(session) = &self.session else {
            return Ok(());
        };

        let path = paths
            .object_path(&session.name)
            .ok_or(KernelError::NoSuchFile)?;
        self.written.push(path.as_bytes().to_vec());
        self.session = None;

        Ok(())
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        const ERROR_FILE_NOT_FOUND: u32 = 2;

        match error {
            KernelError::NoSuchFile => Win32Error::new(ERROR_FILE_NOT_FOUND),
            _ => None,
        }
    }

    fn discard(&mut self) {
        self.session = None;
    }
}

/// Buffers of a simulated capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSession {
    pub name: Vec<u8>,
    pub buffer_size: u32,
    pub recording: bool,
}
