//! Simulated hardware controls. Each service records its requests and
//! replies from settable simulated state.

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
use openxbdm_server::commands::hardware::SystemApp;
use openxbdm_server::commands::hardware::SystemMessage;
use openxbdm_server::commands::hardware::UsbController;
use openxbdm_server::commands::hardware::UsbPort;
use openxbdm_server::commands::hardware::XamError;
use openxbdm_server::commands::hardware::XamHeapId;
use openxbdm_server::commands::hardware::XamHeapInfoClass;
use openxbdm_server::commands::hardware::automation;
use openxbdm_server::commands::hardware::automation::Automation;
use openxbdm_server::commands::hardware::automation::AutomationError;
use openxbdm_server::commands::hardware::automation::Controllers;
use openxbdm_server::commands::hardware::automation::DebuggerMessage;
use openxbdm_server::commands::hardware::automation::Gamepad;
use openxbdm_server::commands::hardware::automation::InputPlatform;
use openxbdm_server::commands::hardware::automation::Poll;
use openxbdm_server::commands::hardware::automation::QueueEntry;
use openxbdm_server::commands::hardware::automation::QueueStatus;
use openxbdm_server::commands::hardware::automation::UploadLayout;

use super::MockBackend;

/// Pool bytes available to simulated allocations.
const POOL_BYTES: u64 = 0x10_0000;

/// Simulated input system.
#[derive(Debug, Default)]
pub struct Input {
    /// Millisecond tick count.
    pub now: u32,
    /// The input system refuses to bind controllers.
    pub refuse_bind: bool,
    /// The input system refuses to unbind controllers.
    pub refuse_unbind: bool,
    /// Users bound, in request order.
    pub binds: Vec<u32>,
    /// Users unbound, in request order.
    pub unbinds: Vec<u32>,
    /// Users whose guide button press was reported.
    pub guide_presses: Vec<u32>,
    /// Messages for the debugger extension.
    pub debugger_messages: Vec<DebuggerMessage>,
}

impl InputPlatform for Input {
    fn tick(&mut self) -> u32 {
        self.now
    }

    fn press_guide(&mut self, user: u32) {
        self.guide_presses.push(user);
    }
}

impl Controllers for Mock {
    type Storage = Vec<QueueEntry>;

    fn locked<R>(
        &mut self,
        operation: impl FnOnce(&mut Automation<Vec<QueueEntry>>, &mut dyn InputPlatform) -> R,
    ) -> R {
        operation(&mut self.automation, &mut self.input)
    }

    fn allocate(&mut self, queue_length: u32) -> Option<Vec<QueueEntry>> {
        pool_allows(automation::allocation_size(queue_length))
            .then(|| vec![QueueEntry::default(); automation::storage_entries(queue_length)])
    }

    fn bind_controller(&mut self, user: u32) -> bool {
        self.input.binds.push(user);
        !self.input.refuse_bind
    }

    fn unbind_controller(&mut self, user: u32) -> bool {
        self.input.unbinds.push(user);
        !self.input.refuse_unbind
    }

    fn tell_debugger(&mut self, message: DebuggerMessage) {
        self.input.debugger_messages.push(message);
    }
}

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

/// A message sent to a system service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    pub app: SystemApp,
    pub message: SystemMessage,
    pub buffer: Vec<u8>,
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
    /// System and cooperative heap counts.
    pub xam_heap_counts: (u32, u32),
    pub xam_heaps: Vec<XamHeap>,

    /// Result of every system message.
    pub system_message_result: Result<(), XamError>,
    /// Messages sent.
    pub system_messages: Vec<SentMessage>,
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
            xam_heap_counts: (3, 5),
            xam_heaps: vec![XamHeap {
                id: XamHeapId(0x1a),
                name: b"XamSystemHeap".to_vec(),
                usage: core::array::from_fn(|index| index as u8),
                limits: core::array::from_fn(|index| 0xe0 | index as u8),
            }],
            // The marketplace service rejects the mock currency message
            // with E_INVALIDARG, which the monitor treats as success.
            system_message_result: Err(XamError::InvalidArgument),
            system_messages: Vec::new(),
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
    /// Input system poll of a user slot.
    pub fn poll(&mut self, user: u32) -> Option<Poll> {
        self.automation.poll(user, &mut self.input)
    }

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

/// Simulated pool allocation of `bytes`.
fn pool_allows(bytes: u64) -> bool {
    bytes <= POOL_BYTES
}

impl hardware::Backend for MockBackend {
    fn automation_connect(&mut self, user: u32) -> Result<(), AutomationError> {
        self.hardware.automation.connect(user)
    }

    fn automation_disconnect(&mut self, user: u32) -> Result<(), AutomationError> {
        self.hardware.automation.disconnect(user)
    }

    fn automation_bind(&mut self, user: u32, queue_length: u32) -> Result<(), AutomationError> {
        automation::bind(&mut self.hardware, user, queue_length)
    }

    fn automation_unbind(&mut self, user: u32) -> Result<(), AutomationError> {
        automation::unbind(&mut self.hardware, user)
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
        automation::set_packet(&mut self.hardware, user, packet)
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
        if let Some(upload) = self.hardware.uploads.get_mut(&connection.0) {
            let start = offset as usize;
            upload[start..start + bytes.len()].copy_from_slice(bytes);
        }
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
        let (system, cooperative) = self.hardware.xam_heap_counts;
        block[4..8].copy_from_slice(&system.to_be_bytes());
        block[8..12].copy_from_slice(&cooperative.to_be_bytes());
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

    fn xam_heap_info(
        &mut self,
        id: XamHeapId,
        class: XamHeapInfoClass,
        block: &mut [u8],
    ) -> Result<(), XamError> {
        let Some(heap) = self.hardware.xam_heaps.iter().find(|heap| heap.id == id) else {
            return Err(XamError::InvalidArgument);
        };
        match class {
            XamHeapInfoClass::Usage => block[4..].copy_from_slice(&heap.usage),
            XamHeapInfoClass::Limits => block[4..].copy_from_slice(&heap.limits),
            XamHeapInfoClass::Name => return Err(XamError::InvalidArgument),
        }
        Ok(())
    }

    fn system_message(
        &mut self,
        app: SystemApp,
        message: SystemMessage,
        buffer: &mut [u8],
    ) -> Result<(), XamError> {
        self.hardware.system_messages.push(SentMessage {
            app,
            message,
            buffer: buffer.to_vec(),
        });
        self.hardware.system_message_result
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
