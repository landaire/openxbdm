//! Simulated hardware controls. Each service records its requests and
//! replies from settable simulated state.

mod automation;

use std::collections::BTreeMap;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::commands::hardware;
use openxbdm_server::commands::hardware::AvatarError;
use openxbdm_server::commands::hardware::AvatarHook;
use openxbdm_server::commands::hardware::ExportMissing;
use openxbdm_server::commands::hardware::InputOwner;
use openxbdm_server::commands::hardware::OddLogNotRunning;
use openxbdm_server::commands::hardware::OddLogStartError;
use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::PlayToCommand;
use openxbdm_server::commands::hardware::PlayToState;
use openxbdm_server::commands::hardware::StackAddresses;
use openxbdm_server::commands::hardware::UsbController;
use openxbdm_server::commands::hardware::UsbPort;
use openxbdm_server::commands::hardware::XamError;
use openxbdm_server::commands::hardware::XamHeapBlock;
use openxbdm_server::commands::hardware::XamHeapId;
use openxbdm_server::commands::hardware::automation::Automation;
use openxbdm_server::commands::hardware::automation::AutomationError;
use openxbdm_server::commands::hardware::automation::Gamepad;
use openxbdm_server::commands::hardware::automation::QueueEntry;
use openxbdm_server::commands::hardware::automation::QueueStatus;
use openxbdm_server::commands::hardware::automation::UploadLayout;

use self::automation::pool_allows;
use super::MockBackend;

pub use self::automation::Input;

/// A simulated XAM heap.
#[derive(Debug, Clone)]
pub struct XamHeap {
    pub id: XamHeapId,
    pub name: Vec<u8>,
    /// Information class 3 after its size dword.
    pub usage: [u8; 0x14],
    /// Information class 2 after its size dword.
    pub limits: [u8; 0x18],
}

/// Heap counts reported by the XAM heap count query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XamHeapCounts {
    pub system: u32,
    pub cooperative: u32,
}

/// A USB port power request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbPortRequest {
    pub controller: UsbController,
    pub port: UsbPort,
    pub enable: bool,
}

/// A registered instrumented module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgoRecord {
    pub address: u32,
    /// Counting requested by `start`.
    pub enabled: bool,

    /// The count block is allocated; the allocation scale is locked.
    pub counts_allocated: bool,
    pub allocation_scale: u32,

    /// Phase names of written profiles.
    pub snapshots: Vec<Vec<u8>>,
    /// Number of count resets.
    pub resets: u32,
}

/// Optical disc log writer state.
#[derive(Debug)]
pub struct OddLog {
    /// A start owns the writer.
    pub busy: bool,
    /// The writer is told to stop.
    pub stopped: bool,

    /// Result of the next file creation.
    pub file_result: Result<(), KernelError>,
    /// Paths of started logs.
    pub files: Vec<Vec<u8>>,
}

impl Default for OddLog {
    fn default() -> Self {
        Self {
            busy: false,
            stopped: true,
            file_result: Ok(()),
            files: Vec::new(),
        }
    }
}

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub automation: Automation<Vec<QueueEntry>>,
    pub input: Input,
    /// `queuepackets` uploads by connection.
    pub uploads: BTreeMap<u8, Vec<u8>>,

    /// Input focus reported by the system; `None` when its export is absent.
    pub input_owner: Option<InputOwner>,
    /// Users passed to the input focus query.
    pub input_focus_users: Vec<u32>,

    pub avatar_available: bool,
    /// Failures injected per hook index.
    pub avatar_failures: BTreeMap<u32, AvatarError>,
    pub avatar_calls: Vec<AvatarHook>,

    pub radio_result: Result<(), KernelError>,
    pub radio_requests: Vec<bool>,

    pub memory_statistics_result: Result<(), KernelError>,
    pub xam_heap_count_available: bool,
    pub xam_heap_info_available: bool,
    pub xam_heap_count_result: Result<(), XamError>,
    pub xam_heap_counts: XamHeapCounts,
    pub xam_heaps: Vec<XamHeap>,

    /// Result of every mock currency message.
    pub mock_currency_result: Result<(), XamError>,
    /// Mock currency settings sent.
    pub mock_currency_settings: Vec<[u8; 0x14]>,
    pub play_to: Result<PlayToState, XamError>,
    pub play_to_requests: Vec<PlayToCommand>,
    pub addresses: StackAddresses,

    pub odd_log: OddLog,
    pub pgo_records: Vec<PgoRecord>,
    pub ignore_gdf_attributes: bool,

    pub usb_port_available: bool,
    pub usb_port_result: Result<(), KernelError>,
    pub usb_port_requests: Vec<UsbPortRequest>,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            automation: Automation::default(),
            input: Input::default(),
            uploads: BTreeMap::new(),

            input_owner: Some(InputOwner::Title),
            input_focus_users: Vec::new(),

            avatar_available: true,
            avatar_failures: BTreeMap::new(),
            avatar_calls: Vec::new(),

            radio_result: Ok(()),
            radio_requests: Vec::new(),

            memory_statistics_result: Ok(()),
            xam_heap_count_available: true,
            xam_heap_info_available: true,
            xam_heap_count_result: Ok(()),
            xam_heap_counts: XamHeapCounts {
                system: 3,
                cooperative: 5,
            },
            xam_heaps: vec![XamHeap {
                id: XamHeapId(0x1a),
                name: b"XamSystemHeap".to_vec(),
                usage: core::array::from_fn(|index| index as u8),
                limits: core::array::from_fn(|index| 0xe0 | index as u8),
            }],

            // The marketplace service rejects the mock currency message
            // with E_INVALIDARG, which the monitor treats as success.
            mock_currency_result: Err(XamError::InvalidArgument),
            mock_currency_settings: Vec::new(),
            play_to: Ok(PlayToState::default()),
            play_to_requests: Vec::new(),
            addresses: StackAddresses {
                title: [192, 168, 1, 30],
                debug: [192, 168, 1, 31],
            },

            odd_log: OddLog::default(),
            pgo_records: Vec::new(),
            ignore_gdf_attributes: false,

            usb_port_available: true,
            usb_port_result: Ok(()),
            usb_port_requests: Vec::new(),
        }
    }
}

impl Mock {
    fn pgo_select(&mut self, module: PgoModule) -> Result<Vec<&mut PgoRecord>, PgoError> {
        let selected: Vec<&mut PgoRecord> = self
            .pgo_records
            .iter_mut()
            .filter(|record| match module {
                PgoModule::All => true,
                PgoModule::Record(address) => record.address == address,
            })
            .collect();

        if matches!(module, PgoModule::Record(_)) && selected.is_empty() {
            return Err(PgoError::NoSuchModule);
        }

        Ok(selected)
    }
}

impl hardware::Backend for MockBackend {
    fn automation_connect(&mut self, user: u32) -> Result<(), AutomationError> {
        self.hardware.automation.connect(user)
    }

    fn automation_disconnect(&mut self, user: u32) -> Result<(), AutomationError> {
        self.hardware.automation.disconnect(user)
    }

    fn automation_bind(&mut self, user: u32, queue_length: u32) -> Result<(), AutomationError> {
        hardware::automation::bind(&mut self.hardware, user, queue_length)
    }

    fn automation_unbind(&mut self, user: u32) -> Result<(), AutomationError> {
        hardware::automation::unbind(&mut self.hardware, user)
    }

    fn automation_clear_queue(&mut self, user: u32) -> Result<(), AutomationError> {
        self.hardware.automation.clear_queue(user)
    }

    fn automation_query_queue(&mut self, user: u32) -> Result<QueueStatus, AutomationError> {
        let Mock {
            automation, input, ..
        } = &mut self.hardware;

        automation.query(user, input)
    }

    fn automation_set_packet(&mut self, user: u32, packet: Gamepad) -> Result<(), AutomationError> {
        hardware::automation::set_packet(&mut self.hardware, user, packet)
    }

    fn automation_begin_upload(&mut self, connection: ConnectionIndex, size: u32) -> bool {
        self.hardware.uploads.remove(&connection.0);

        if !pool_allows(u64::from(size)) {
            return false;
        }

        self.hardware
            .uploads
            .insert(connection.0, vec![0; size as usize]);

        true
    }

    fn automation_upload(&mut self, connection: ConnectionIndex, offset: u32, bytes: &[u8]) {
        let Some(upload) = self.hardware.uploads.get_mut(&connection.0) else {
            return;
        };

        let start = offset as usize;
        upload[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn automation_discard_upload(&mut self, connection: ConnectionIndex) {
        self.hardware.uploads.remove(&connection.0);
    }

    fn automation_queue_upload(
        &mut self,
        connection: ConnectionIndex,
        user: u32,
        layout: UploadLayout,
    ) -> Result<u32, AutomationError> {
        let Mock {
            automation,
            input,
            uploads,
            ..
        } = &mut self.hardware;

        // Without a begun upload, the queue reads an empty upload.
        let upload = uploads.remove(&connection.0).unwrap_or_default();

        automation.queue(user, layout, &upload, input)
    }

    fn automation_input_owner(&mut self, user: u32) -> Result<InputOwner, ExportMissing> {
        let owner = self.hardware.input_owner.ok_or(ExportMissing)?;

        self.hardware.input_focus_users.push(user);

        Ok(owner)
    }

    fn avatar_hooks_available(&mut self) -> bool {
        self.hardware.avatar_available
    }

    fn avatar_hook(&mut self, hook: AvatarHook) -> Result<(), AvatarError> {
        if let Some(&failure) = self.hardware.avatar_failures.get(&hook.index()) {
            return Err(failure);
        }

        self.hardware.avatar_calls.push(hook);

        Ok(())
    }

    fn set_wireless_radio(&mut self, enabled: bool) -> Result<(), KernelError> {
        self.hardware.radio_requests.push(enabled);

        self.hardware.radio_result
    }

    fn devkit_memory_statistics(&mut self, block: &mut [u8; 0x90]) -> Result<(), KernelError> {
        if self.hardware.memory_statistics_result.is_ok() {
            for (index, byte) in block.iter_mut().enumerate().skip(8) {
                *byte = index as u8;
            }
        }

        self.hardware.memory_statistics_result
    }

    fn xam_heap_count_available(&mut self) -> bool {
        self.hardware.xam_heap_count_available
    }

    fn xam_heap_info_available(&mut self) -> bool {
        self.hardware.xam_heap_info_available
    }

    fn xam_heap_count(&mut self, block: &mut [u8; 12]) -> Result<(), XamError> {
        let counts = self.hardware.xam_heap_counts;
        block[4..8].copy_from_slice(&counts.system.to_be_bytes());
        block[8..12].copy_from_slice(&counts.cooperative.to_be_bytes());

        self.hardware.xam_heap_count_result
    }

    fn xam_heap_name(&mut self, id: XamHeapId, name: &mut [u8; 0x20]) -> Result<(), XamError> {
        let Some(heap) = self.hardware.xam_heaps.iter().find(|heap| heap.id == id) else {
            return Err(XamError::InvalidArgument);
        };

        let length = heap.name.len().min(name.len() - 1);
        name[..length].copy_from_slice(&heap.name[..length]);
        name[length] = 0;

        Ok(())
    }

    fn xam_heap_info(&mut self, id: XamHeapId, block: XamHeapBlock<'_>) -> Result<(), XamError> {
        let Some(heap) = self.hardware.xam_heaps.iter().find(|heap| heap.id == id) else {
            return Err(XamError::InvalidArgument);
        };

        let data: &[u8] = match block {
            XamHeapBlock::Usage(_) => &heap.usage,
            XamHeapBlock::Limits(_) => &heap.limits,
        };
        block.sized().1[4..].copy_from_slice(data);

        Ok(())
    }

    fn mock_currency(&mut self, setting: &mut [u8; 0x14]) -> Result<(), XamError> {
        self.hardware.mock_currency_settings.push(*setting);

        self.hardware.mock_currency_result
    }

    fn play_to(&mut self, command: PlayToCommand) -> Result<PlayToState, XamError> {
        self.hardware.play_to_requests.push(command);

        self.hardware.play_to
    }

    fn stack_addresses(&mut self) -> StackAddresses {
        self.hardware.addresses
    }

    fn odd_log_start(&mut self, path: Result<&[u8], KernelError>) -> Result<(), OddLogStartError> {
        let log = &mut self.hardware.odd_log;
        if log.busy {
            return Err(OddLogStartError::Busy);
        }

        log.busy = true;
        log.stopped = false;

        let error = match path.and_then(|path| log.file_result.map(|()| path)) {
            Ok(path) => {
                log.files.push(path.to_vec());
                return Ok(());
            }
            Err(error) => error,
        };

        // The writer reports a failure only for statuses with both
        // severity bits set; it then exits without clearing the stop flag.
        if NtStatus::from(error).0 & 0xc000_0000 == 0xc000_0000 {
            log.busy = false;
            return Err(OddLogStartError::Failed(error));
        }

        Ok(())
    }

    fn odd_log_stop(&mut self) -> Result<(), OddLogNotRunning> {
        let log = &mut self.hardware.odd_log;
        if log.stopped {
            return Err(OddLogNotRunning);
        }

        log.stopped = true;
        log.busy = false;

        Ok(())
    }

    fn pgo_start(&mut self, module: PgoModule) -> Result<(), PgoError> {
        for record in self.hardware.pgo_select(module)? {
            record.enabled = true;
        }

        Ok(())
    }

    fn pgo_stop(&mut self, module: PgoModule) -> Result<(), PgoError> {
        for record in self.hardware.pgo_select(module)? {
            record.enabled = false;
        }

        Ok(())
    }

    fn pgo_snapshot(
        &mut self,
        phase: &[u8],
        reset: bool,
        module: PgoModule,
    ) -> Result<(), PgoError> {
        for record in self.hardware.pgo_select(module)? {
            record.snapshots.push(phase.to_vec());
            if reset {
                record.resets += 1;
            }
        }

        Ok(())
    }

    fn pgo_set_allocation_scale(&mut self, module: PgoModule, scale: u32) -> Result<(), PgoError> {
        let PgoModule::Record(address) = module else {
            return Err(PgoError::NoSuchModule);
        };

        let record = self
            .hardware
            .pgo_records
            .iter_mut()
            .find(|record| record.address == address)
            .ok_or(PgoError::NoSuchModule)?;
        if record.counts_allocated {
            return Err(PgoError::Busy);
        }

        record.allocation_scale = scale;

        Ok(())
    }

    fn set_ignore_gdf_attributes(&mut self, ignore: bool) {
        self.hardware.ignore_gdf_attributes = ignore;
    }

    fn ignore_gdf_attributes(&mut self) -> bool {
        self.hardware.ignore_gdf_attributes
    }

    fn usb_port_power_available(&mut self) -> bool {
        self.hardware.usb_port_available
    }

    fn set_usb_port_power(
        &mut self,
        controller: UsbController,
        port: UsbPort,
        enable: bool,
    ) -> Result<(), KernelError> {
        self.hardware.usb_port_requests.push(UsbPortRequest {
            controller,
            port,
            enable,
        });

        self.hardware.usb_port_result
    }
}
