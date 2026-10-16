//! Simulated CIV services. IPTV settings live in the console configuration
//! store of the console domain.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::services;
use openxbdm_server::commands::services::CivProgress;
use openxbdm_server::commands::services::CivResult;
use openxbdm_server::commands::services::DetectionBit;
use openxbdm_server::commands::services::DetectionMask;
use openxbdm_server::commands::services::DetectionRoutineMissing;
use openxbdm_server::commands::services::DetectionUpdate;
use openxbdm_server::commands::services::LastError;
use openxbdm_server::commands::services::ThreadHandle;

use super::MockBackend;

/// First handle the simulated kernel hands out.
const FIRST_THREAD_HANDLE: u32 = 0xf800_0040;
/// Distance between simulated handles.
const THREAD_HANDLE_STRIDE: u32 = 4;

/// A request made to the XAM content verification services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CivCall {
    /// The failure thread ran XAM 0x9c0(0xff), then restarted the console
    /// when `reboot` is set.
    Failure {
        reboot: bool,
    },
    Inject {
        hash_errors: u32,
        read_errors: u32,
    },
    CreateProcess {
        thread_id: u32,
    },
    CloseProcess,
    Verify {
        milliseconds: u32,
    },
}

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    /// Requests in the order they were made.
    pub calls: Vec<CivCall>,
    /// Thread creation fails with this last error when set.
    pub thread_failure: Option<LastError>,
    next_thread_handle: u32,
    /// Kernel security detection mask; `None` before the security state is
    /// initialized, when the kernel reports all bits set.
    pub detection_mask: Option<u64>,
    /// A detection export the simulated kernel lacks.
    pub missing_detection_routine: Option<DetectionRoutineMissing>,
    /// Return value of XAM 0x9bb.
    pub create_result: CivResult,
    /// Return value of XAM 0x9bd.
    pub verify_result: CivResult,
    /// What XAM 0x9be reports.
    pub progress: Result<CivProgress, CivResult>,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            thread_failure: None,
            next_thread_handle: FIRST_THREAD_HANDLE,
            // A booted console has loaded its security settings.
            detection_mask: Some(0),
            missing_detection_routine: None,
            create_result: CivResult::Returned(Hresult(0)),
            verify_result: CivResult::Returned(Hresult(0)),
            progress: Ok(CivProgress::default()),
        }
    }
}

impl Mock {
    /// The kernel's detection read: the mask, or all ones before
    /// initialization.
    fn detected(&self) -> u64 {
        self.detection_mask.unwrap_or(u64::MAX)
    }

    /// The kernel's set export: already-set bits succeed without a change.
    fn set_detected(&mut self, bit: DetectionBit) -> NtStatus {
        if bit.0 >= u64::BITS {
            return KernelError::InvalidParameter.into();
        }
        let mask = self.detection_mask.get_or_insert(0);
        *mask |= 1 << bit.0;
        NtStatus::SUCCESS
    }
}

impl services::Backend for MockBackend {
    fn start_civ_failure_thread(&mut self, reboot: bool) -> Result<ThreadHandle, LastError> {
        let mock = &mut self.services;
        if let Some(error) = mock.thread_failure {
            return Err(error);
        }
        let handle = ThreadHandle(mock.next_thread_handle);
        mock.next_thread_handle += THREAD_HANDLE_STRIDE;
        mock.calls.push(CivCall::Failure { reboot });
        Ok(handle)
    }

    fn inject_civ_errors(&mut self, hash_errors: u32, read_errors: u32) {
        self.services.calls.push(CivCall::Inject {
            hash_errors,
            read_errors,
        });
    }

    fn update_civ_detection(
        &mut self,
        bit: Option<DetectionBit>,
    ) -> Result<DetectionUpdate, DetectionRoutineMissing> {
        let mock = &mut self.services;
        if let Some(missing) = mock.missing_detection_routine {
            return Err(missing);
        }
        let old_mask = DetectionMask(mock.detected() as u32);
        mock.detection_mask = Some(0);
        let status = bit.map_or(NtStatus::SUCCESS, |bit| mock.set_detected(bit));
        Ok(DetectionUpdate {
            status,
            old_mask,
            new_mask: DetectionMask(mock.detected() as u32),
        })
    }

    fn create_civ_process(&mut self, thread_id: u32) -> CivResult {
        self.services
            .calls
            .push(CivCall::CreateProcess { thread_id });
        self.services.create_result
    }

    fn close_civ_process(&mut self) {
        self.services.calls.push(CivCall::CloseProcess);
    }

    fn verify_civ(&mut self, milliseconds: u32) -> CivResult {
        self.services.calls.push(CivCall::Verify { milliseconds });
        self.services.verify_result
    }

    fn civ_progress(&mut self) -> Result<CivProgress, CivResult> {
        self.services.progress
    }
}
