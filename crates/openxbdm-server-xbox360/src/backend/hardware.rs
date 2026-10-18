//! Hardware control services: virtual controllers, configuration hooks,
//! system service messages, the optical disc log, and NuiCam raw data
//! requests.

pub(crate) mod nuicam;
pub(super) mod pgo;

use core::num::NonZeroU32;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::ObjectPath;
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
use openxbdm_server::commands::hardware::XamHeapBlock;
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
use openxbdm_server::commands::hardware::odd::MountRequest;
use openxbdm_server::commands::hardware::odd::OddLog;
use openxbdm_server::commands::hardware::odd::OddLogReservation;
use openxbdm_server::commands::hardware::odd::OddPlatform;
use openxbdm_server::commands::hardware::odd::ReadRequest;
use openxbdm_server::commands::hardware::odd::SpeedChangeRequest;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::sync::SpinLock;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360_sys::status::Win32ErrorCode;
use xbox360_sys::xam;
use xbox360_sys::xam::XnAddr;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::XInputdSetRFPowerMode;

use super::Console;
use super::filesystem;
use super::filesystem::CallerPaths;
use super::network::xam_procedure;
use super::performance::pix;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::KernelEvent;

/// XAM ordinal: heap information `(id, class, buffer) -> HRESULT`.
const XAM_HEAP_INFO: Ordinal = Ordinal::new(0x827).unwrap();
/// XAM ordinal: heap counts `(buffer) -> HRESULT`.
const XAM_HEAP_COUNT: Ordinal = Ordinal::new(0x828).unwrap();
/// Kernel ordinal: USB port power `(controller, port, enable) -> NTSTATUS`.
const KERNEL_USB_PORT_POWER: Ordinal = Ordinal::new(825).unwrap();
const MAX_CONNECTIONS: usize = 8;
/// Status word of controls 0x7b and 0x7c for a slot without a controller.
const NOT_CONNECTED: Win32ErrorCode = Win32ErrorCode(Win32Error::DEVICE_NOT_CONNECTED.code());

/// The input system polls the controllers from other threads.
static AUTOMATION: SpinLock<Automation<PoolEntries>> = SpinLock::new(Automation::new());
/// Title decompression ignores GDF attributes (`tdecomp`).
static IGNORE_GDF_ATTRIBUTES: AtomicBool = AtomicBool::new(false);
/// XAM input focus query, resolved once at startup (stock 0x91f25288 into
/// 0x91f9e47c, without the entry point check).
static INPUT_FOCUS: AtomicU32 = AtomicU32::new(0);
static HEAP_COUNT: CachedExport = CachedExport::new();
static HEAP_INFO: CachedExport = CachedExport::new();
static USB_PORT_POWER: CachedExport = CachedExport::new();
static ODD_LOG: OddLog = OddLog::new();
static ODD_WRITER: OddWriter = OddWriter {
    work: KernelEvent::new(),
    finished: KernelEvent::new(),
    thread: AtomicU32::new(0),
};
/// Drive authentication state kept for the optical disc trace stream.
static ODD_AUTH_STATE: AtomicU32 = AtomicU32::new(0);

/// Platform state of this domain.
pub struct Data {
    uploads: [Option<PoolBlock>; MAX_CONNECTIONS],
}

impl Data {
    pub const fn new() -> Self {
        Self {
            uploads: [const { None }; MAX_CONNECTIONS],
        }
    }
}

impl commands::hardware::Backend for Console {
    fn automation_connect(&mut self, user: u32) -> Result<(), AutomationError> {
        connect(user)
    }

    fn automation_disconnect(&mut self, user: u32) -> Result<(), AutomationError> {
        disconnect(user)
    }

    fn automation_bind(&mut self, user: u32, queue_length: u32) -> Result<(), AutomationError> {
        automation::bind(&mut XboxControllers, user, queue_length)
    }

    fn automation_unbind(&mut self, user: u32) -> Result<(), AutomationError> {
        automation::unbind(&mut XboxControllers, user)
    }

    fn automation_clear_queue(&mut self, user: u32) -> Result<(), AutomationError> {
        clear_queue(user)
    }

    fn automation_query_queue(&mut self, user: u32) -> Result<QueueStatus, AutomationError> {
        query_queue(user)
    }

    fn automation_set_packet(&mut self, user: u32, packet: Gamepad) -> Result<(), AutomationError> {
        automation::set_packet(&mut XboxControllers, user, packet)
    }

    fn automation_begin_upload(&mut self, connection: ConnectionIndex, size: u32) -> bool {
        const POOL_TAG: PoolTag = PoolTag::new(*b"DMAU");

        let slot = &mut self.hardware.uploads[connection.0 as usize];

        // The previous upload is freed before the new one is allocated.
        *slot = None;
        *slot = PoolBlock::allocate(u64::from(size), POOL_TAG);

        slot.is_some()
    }

    fn automation_upload(&mut self, connection: ConnectionIndex, offset: u32, bytes: &[u8]) {
        let Some(block) = self.hardware.uploads[connection.0 as usize].as_mut() else {
            return;
        };

        let start = offset as usize;
        block.bytes_mut()[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn automation_discard_upload(&mut self, connection: ConnectionIndex) {
        self.hardware.uploads[connection.0 as usize] = None;
    }

    fn automation_queue_upload(
        &mut self,
        connection: ConnectionIndex,
        user: u32,
        layout: UploadLayout,
    ) -> Result<u32, AutomationError> {
        let upload = self.hardware.uploads[connection.0 as usize].take();
        let bytes = upload.as_ref().map_or(&[][..], PoolBlock::bytes);

        AUTOMATION.lock().queue(user, layout, bytes, &mut Input)
    }

    fn automation_input_owner(&mut self, user: u32) -> Result<InputOwner, ExportMissing> {
        query_input_focus(user).map(|system| {
            if system != 0 {
                InputOwner::System
            } else {
                InputOwner::Title
            }
        })
    }

    fn avatar_hooks_available(&mut self) -> bool {
        avatar_lookup().is_some()
    }

    fn avatar_hook(&mut self, hook: AvatarHook) -> Result<(), AvatarError> {
        let lookup = avatar_lookup().ok_or(AvatarError::NoFunction)?;

        let mut function = 0u32;
        // SAFETY: the lookup takes an index and an output pointer.
        let result = unsafe {
            kernel::call_export(lookup, hook.index(), output_address(&mut function), 0, 0)
        };
        XamError::check(Hresult(result)).map_err(AvatarError::Lookup)?;
        if function == 0 {
            return Err(AvatarError::NoFunction);
        }

        let (first, second) = match hook {
            AvatarHook::LoadAssetDelay(value)
            | AvatarHook::QueryMarketplaceDelay(value)
            | AvatarHook::ChangeMetadata(value) => (value, 0),
            AvatarHook::SimulateError { kind, value } => (kind, value),
        };
        // SAFETY: the hooks take at most two dword arguments.
        let result = unsafe { kernel::call_export(function, first, second, 0, 0) };

        XamError::check(Hresult(result)).map_err(AvatarError::Hook)
    }

    fn set_wireless_radio(&mut self, enabled: bool) -> Result<(), KernelError> {
        // SAFETY: the radio service takes only the mode.
        NtStatus(unsafe { XInputdSetRFPowerMode(u32::from(enabled)) }).result()
    }

    fn devkit_memory_statistics(&mut self, block: &mut [u8; 0x90]) -> Result<(), KernelError> {
        // SAFETY: `block` is the 0x90-byte buffer the statistics service fills.
        unsafe {
            xboxkrnl::ExDebugMonitorService(
                DebugMonitorService::MemoryStatistics,
                output_address(&mut block[..]),
                0,
                0,
            )
        }
        .result()
    }

    fn xam_heap_count_available(&mut self) -> bool {
        HEAP_COUNT.xam(XAM_HEAP_COUNT).is_some()
    }

    fn xam_heap_info_available(&mut self) -> bool {
        HEAP_INFO.xam(XAM_HEAP_INFO).is_some()
    }

    fn xam_heap_count(&mut self, block: &mut [u8; 12]) -> Result<(), XamError> {
        let Some(function) = HEAP_COUNT.xam(XAM_HEAP_COUNT) else {
            return Err(XamError::Fail);
        };

        // SAFETY: the export fills the sized block.
        let result =
            unsafe { kernel::call_export(function, output_address(&mut block[..]), 0, 0, 0) };

        XamError::check(Hresult(result))
    }

    fn xam_heap_name(&mut self, id: XamHeapId, name: &mut [u8; 0x20]) -> Result<(), XamError> {
        let Some(function) = HEAP_INFO.xam(XAM_HEAP_INFO) else {
            return Err(XamError::Fail);
        };

        let mut length = name.len() as u32;
        let request = [output_address(&mut name[..]), output_address(&mut length)];
        // SAFETY: the name class takes `{buffer, &length}`.
        let result = unsafe {
            kernel::call_export(
                function,
                id.0,
                XamHeapInfoClass::Name.code(),
                kernel::address_of(&request[..]),
                0,
            )
        };

        XamError::check(Hresult(result))
    }

    fn xam_heap_info(&mut self, id: XamHeapId, block: XamHeapBlock<'_>) -> Result<(), XamError> {
        let Some(function) = HEAP_INFO.xam(XAM_HEAP_INFO) else {
            return Err(XamError::Fail);
        };

        let (class, block) = block.sized();
        // SAFETY: the limits and usage classes fill the block whose first
        // dword holds its size.
        let result =
            unsafe { kernel::call_export(function, id.0, class.code(), output_address(block), 0) };

        XamError::check(Hresult(result))
    }

    fn mock_currency(&mut self, setting: &mut [u8; 0x14]) -> Result<(), XamError> {
        // SAFETY: the mock currency message reads its 0x14-byte setting in
        // place; the request is synchronous.
        XamError::check(unsafe {
            xam::XMsgStartIORequest(
                SystemApp::MARKETPLACE.0,
                SystemMessage::MOCK_CURRENCY.0,
                core::ptr::null_mut(),
                setting.as_mut_ptr(),
                setting.len() as u32,
            )
        })
    }

    fn play_to(&mut self, command: PlayToCommand) -> Result<PlayToState, XamError> {
        /// Media service application and PlayTo message.
        const MEDIA_APP: SystemApp = SystemApp(0xf0);
        const MEDIA_PLAY_TO: SystemMessage = SystemMessage(0x900002);

        /// PlayTo message buffer.
        #[repr(C)]
        struct Request {
            command: u32,
            output: u32,
            output_size: u32,
        }

        let mut output = [0u32; 2];
        let mut request = Request {
            command: command.code(),
            output: output_address(&mut output[..]),
            output_size: size_of_val(&output) as u32,
        };
        // SAFETY: `request` points at `output`; the request is synchronous.
        let result = unsafe {
            xam::XMsgStartIORequest(
                MEDIA_APP.0,
                MEDIA_PLAY_TO.0,
                core::ptr::null_mut(),
                (&raw mut request).cast(),
                size_of::<Request>() as u32,
            )
        };
        XamError::check(result)?;

        Ok(PlayToState {
            xmp_heap: output[0],
            play_to: output[1],
        })
    }

    fn stack_addresses(&mut self) -> StackAddresses {
        let mut title = XnAddr::default();
        let mut debug = XnAddr::default();
        // SAFETY: each query stores one XNADDR.
        unsafe {
            xam::NetDll_XNetGetTitleXnAddr(XnCaller::DebugMonitor, (&raw mut title).cast());
            xam::NetDll_XNetGetDebugXnAddr(XnCaller::DebugMonitor, (&raw mut debug).cast());
        }

        StackAddresses {
            title: title.address.to_be_bytes(),
            debug: debug.address.to_be_bytes(),
        }
    }

    fn odd_log_reserve(&mut self) -> Result<OddLogReservation, OddLogStartError> {
        ODD_LOG.reserve(&mut OddServices)
    }

    fn odd_log_start(
        &mut self,
        reservation: OddLogReservation,
        path: Result<&[u8], KernelError>,
    ) -> Result<(), OddLogStartError> {
        ODD_LOG.start(&mut OddServices, reservation, path)
    }

    fn odd_log_stop(&mut self) -> Result<(), OddLogNotRunning> {
        ODD_LOG.stop(&mut OddServices)
    }

    fn pgo_start(&mut self, module: PgoModule) -> Result<(), PgoError> {
        pgo::control_start(module)
    }

    fn pgo_stop(&mut self, module: PgoModule) -> Result<(), PgoError> {
        pgo::control_stop(module)
    }

    fn pgo_snapshot(
        &mut self,
        phase: &[u8],
        reset: bool,
        module: PgoModule,
    ) -> Result<(), PgoError> {
        pgo::control_snapshot(phase, reset, module)
    }

    fn pgo_set_allocation_scale(&mut self, module: PgoModule, scale: u32) -> Result<(), PgoError> {
        pgo::control_allocation_scale(module, scale)
    }

    fn set_ignore_gdf_attributes(&mut self, ignore: bool) {
        IGNORE_GDF_ATTRIBUTES.store(ignore, Ordering::Relaxed);
    }

    fn ignore_gdf_attributes(&mut self) -> bool {
        IGNORE_GDF_ATTRIBUTES.load(Ordering::Relaxed)
    }

    fn usb_port_power_available(&mut self) -> bool {
        USB_PORT_POWER.kernel(KERNEL_USB_PORT_POWER).is_some()
    }

    fn set_usb_port_power(
        &mut self,
        controller: UsbController,
        port: UsbPort,
        enable: bool,
    ) -> Result<(), KernelError> {
        let function = USB_PORT_POWER
            .kernel(KERNEL_USB_PORT_POWER)
            .ok_or(KernelError::OrdinalNotFound)?;

        // SAFETY: the export takes three dword arguments.
        NtStatus(unsafe {
            kernel::call_export(function, controller.0, port.0, u32::from(enable), 0)
        })
        .result()
    }
}

/// Queue storage of a controller in pool memory.
pub struct PoolEntries {
    block: PoolBlock,
    count: usize,
}

impl AsRef<[QueueEntry]> for PoolEntries {
    fn as_ref(&self) -> &[QueueEntry] {
        // SAFETY: the block holds `count` zeroed entries, a valid bit
        // pattern, and pool memory is suitably aligned.
        unsafe { core::slice::from_raw_parts(self.block.base().cast::<QueueEntry>(), self.count) }
    }
}

impl AsMut<[QueueEntry]> for PoolEntries {
    fn as_mut(&mut self) -> &mut [QueueEntry] {
        // SAFETY: as `as_ref`, with exclusive access through `&mut self`.
        unsafe {
            core::slice::from_raw_parts_mut(self.block.base().cast::<QueueEntry>(), self.count)
        }
    }
}

/// Pool memory owned by a Rust value; freed on drop.
struct PoolBlock {
    address: NonZeroU32,
    len: usize,
}

impl PoolBlock {
    fn allocate(bytes: u64, tag: PoolTag) -> Option<Self> {
        let size = u32::try_from(bytes).ok()?;

        // SAFETY: the allocation takes only a size, tag and pool type.
        let address = NonZeroU32::new(unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(size, tag, PoolType::System)
        })?;
        let block = Self {
            address,
            len: size as usize,
        };

        // SAFETY: the pool returned `size` writable bytes at `address`. The
        // bytes are uninitialized, so they are zeroed before `bytes_mut`
        // can view them.
        unsafe { core::ptr::write_bytes(block.base(), 0, block.len) };

        Some(block)
    }

    fn base(&self) -> *mut u8 {
        self.address.get() as usize as *mut u8
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the block owns `len` bytes at `address` until dropped.
        unsafe { core::slice::from_raw_parts(self.base(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`, with exclusive access through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.base(), self.len) }
    }
}

impl Drop for PoolBlock {
    fn drop(&mut self) {
        // SAFETY: the block owns the pool allocation at `address`.
        unsafe { xboxkrnl::ExFreePool(self.address.get()) };
    }
}

struct Input;

impl InputPlatform for Input {
    fn tick(&mut self) -> u32 {
        TickCount::now().milliseconds()
    }

    fn press_guide(&mut self, user: u32) {
        // SAFETY: the export takes only a user number.
        unsafe { press_guide_button(user) };
    }
}

struct XboxControllers;

impl Controllers for XboxControllers {
    type Storage = PoolEntries;

    fn locked<R>(
        &mut self,
        operation: impl FnOnce(&mut Automation<PoolEntries>, &mut dyn InputPlatform) -> R,
    ) -> R {
        operation(&mut AUTOMATION.lock(), &mut Input)
    }

    fn allocate(&mut self, queue_length: u32) -> Option<PoolEntries> {
        const POOL_TAG: PoolTag = PoolTag::new(*b"dmau");

        let block = PoolBlock::allocate(automation::allocation_size(queue_length), POOL_TAG)?;
        let count = automation::storage_entries(queue_length);
        if count * core::mem::size_of::<QueueEntry>() > block.len {
            return None;
        }

        Some(PoolEntries { block, count })
    }

    fn bind_controller(&mut self, user: u32) -> bool {
        // SAFETY: the export takes only a user number.
        unsafe { bind_automation_controller(user) != 0 }
    }

    fn unbind_controller(&mut self, user: u32) -> bool {
        // SAFETY: the export takes only a user number.
        unsafe { unbind_automation_controller(user) != 0 }
    }

    fn tell_debugger(&mut self, message: DebuggerMessage) {
        let (payload, _) = message.payload();
        let Some(block) = kernel::published_debug_monitor_data() else {
            return;
        };

        let control = block.control_routine.load(Ordering::Relaxed);
        if control == 0 {
            return;
        }

        // SAFETY: the control routine takes a code and a data pointer.
        unsafe {
            kernel::call_export(
                control,
                message.code(),
                payload.as_ptr() as usize as u32,
                0,
                0,
            )
        };
    }
}

/// Address of an export, resolved once and cached; absent exports are
/// looked up again on the next use, as the monitor does.
struct CachedExport(AtomicU32);

impl CachedExport {
    const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// XAM exports are resolved without the entry point check.
    fn xam(&self, ordinal: Ordinal) -> Option<u32> {
        let cached = self.0.load(Ordering::Relaxed);
        if cached != 0 {
            return Some(cached);
        }

        let address = xam_procedure(ordinal).filter(|&address| address != 0)?;
        self.0.store(address, Ordering::Relaxed);

        Some(address)
    }

    fn kernel(&self, ordinal: Ordinal) -> Option<u32> {
        let cached = self.0.load(Ordering::Relaxed);
        if cached != 0 {
            return Some(cached);
        }

        let module = SystemModule::Kernel.handle().ok()?;
        let address = resolve_export(module, ordinal).ok()?.raw();
        self.0.store(address, Ordering::Relaxed);

        Some(address)
    }
}

/// Request of monitor controls 0x7a to 0x7c: the user, the address of the
/// control code's output or 0, and the address of the caller's status
/// word.
#[repr(C)]
struct AutomationRequest {
    user: u32,
    output: u32,
    status: u32,
}

/// Output of monitor control 0x7a: `XINPUT_STATE` with the gamepad in
/// console layout.
#[repr(C)]
struct AutomationState {
    packet_number: u32,
    gamepad: [u8; Gamepad::WIRE_SIZE],
}

const _: () = assert!(size_of::<AutomationState>() == size_of::<xam::InputState>());

/// Writer thread of the optical disc log.
struct OddWriter {
    work: KernelEvent,
    /// Notification event: no writer runs.
    finished: KernelEvent,
    /// Referenced thread object of the last writer started.
    thread: AtomicU32,
}

/// Kernel services of the optical disc log.
struct OddServices;

impl OddPlatform for OddServices {
    type File = Handle;

    fn timebase(&mut self) -> u64 {
        Timebase::now().ticks()
    }

    fn create_file(&mut self, path: &[u8]) -> Result<Handle, KernelError> {
        /// `FILE_SHARE_READ | FILE_SHARE_DELETE`.
        const SHARE_READ_DELETE: ShareAccess = ShareAccess::from_bits_retain(5);

        let request = CreateRequest {
            access: AccessMask::GENERIC_WRITE,
            allocation_size: None,
            attributes: FileAttributes::NORMAL,
            share: SHARE_READ_DELETE,
            disposition: CreateDisposition::OverwriteIf,
            options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
        };
        let FileHandle(handle) = super::filesystem::create_file(path, &request)?;

        Ok(Handle::from_raw(handle))
    }

    fn write_file(&mut self, file: Handle, text: &[u8]) -> NtStatus {
        let mut io_status = xboxkrnl::IoStatusBlock {
            status: NtStatus::SUCCESS,
            information: 0,
        };

        // SAFETY: `file` is the open log file and `text` is valid for its length.
        unsafe {
            xboxkrnl::NtWriteFile(
                file,
                Handle::NULL,
                0,
                0,
                &mut io_status,
                text.as_ptr(),
                text.len() as u32,
                core::ptr::null(),
            )
        }
    }

    fn close_file(&mut self, file: Handle) {
        // SAFETY: the log owns `file` and closes it once.
        unsafe { xboxkrnl::NtClose(file) };
    }

    fn writer_starting(&mut self) {
        ODD_WRITER.finished.reset();
    }

    fn start_writer(&mut self, file: Handle) -> NtStatus {
        const WRITER_STACK: u32 = 0x8000;
        const WRITER_FLAGS: ThreadCreationFlags =
            kernel::SYSTEM_THREAD_FLAGS.union(ThreadCreationFlags::EXEMPT_FROM_STOPS);

        let mut thread = 0u32;
        // SAFETY: `thread` is a local word; `odd_writer` takes the handle as
        // its context.
        let created = unsafe {
            xboxkrnl::ExCreateThread(
                &mut thread,
                WRITER_STACK,
                core::ptr::null_mut(),
                0,
                odd_writer as *const () as usize as u32,
                file.raw(),
                WRITER_FLAGS,
            )
        };

        // A stop that ran before this store left the previous object behind.
        if thread != 0 {
            let previous = ODD_WRITER.thread.swap(thread, Ordering::AcqRel);
            if previous != 0 {
                // SAFETY: `previous` is a referenced thread object from an
                // earlier start.
                unsafe { xboxkrnl::ObDereferenceObject(previous) };
            }
        }

        created
    }

    fn writer_absent(&mut self) {
        ODD_WRITER.finished.set();
    }

    fn wake_writer(&mut self, _log: &OddLog) {
        ODD_WRITER.work.set();
    }

    fn join_writer(&mut self) {
        ODD_WRITER.finished.wait();

        // Creation flag 0x80 returns a referenced thread object rather than
        // a handle.
        let thread = ODD_WRITER.thread.swap(0, Ordering::AcqRel);
        if thread != 0 {
            // SAFETY: `thread` is the referenced object ExCreateThread returned.
            unsafe { xboxkrnl::ObDereferenceObject(thread) };
        }
    }
}

/// Optical disc records of the trace stream.
mod odd_trace {
    /// Record tag `ODD `.
    pub(super) const TAG: u32 = 0x4f44_4420;
    /// Bit 0 of the record's low time word: set on completion records.
    pub(super) const COMPLETION: u32 = 1;

    /// Record payload: the words in console memory order.
    pub(super) fn payload<const WORDS: usize>(words: [u32; WORDS]) -> [[u8; 4]; WORDS] {
        words.map(u32::to_be_bytes)
    }
}

// The automation exports take the user number from the request as stock
// passes it, without the `UserIndex` check.
kernel::forward!(fn bind_automation_controller(u32) -> u32 => xam::XAutomationpBindController);
kernel::forward!(fn unbind_automation_controller(u32) -> u32 => xam::XAutomationpUnbindController);
kernel::forward!(fn press_guide_button(u32) -> u32 => xam::XAutomationpInputXenonButton);

/// Startup steps of this domain, in stock's order (0x91f32628).
pub(crate) fn initialize() {
    /// XAM ordinal: input focus query, nonzero when the system has focus.
    const XAM_INPUT_FOCUS: Ordinal = Ordinal::new(0x3dd).unwrap();

    pgo::initialize();
    odd_initialize();
    if let Some(address) = xam_procedure(XAM_INPUT_FOCUS) {
        INPUT_FOCUS.store(address, Ordering::Relaxed);
    }
    nuicam::initialize();
}

/// Monitor control 0x7a: current state of a virtual controller; the
/// output receives the packet number and the gamepad. Returns 1 when the
/// slot has a controller.
///
/// # Safety
///
/// `argument` must be the address of an `AutomationRequest` the caller
/// keeps unchanged for the call, whose status word is writable and whose
/// output is 0 or a writable `XINPUT_STATE`, neither otherwise accessed
/// for the call.
pub(crate) unsafe fn service_automation_get_state(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let (request, status, state) = unsafe {
        let request = kernel::object_at::<AutomationRequest>(argument);
        (
            request,
            kernel::object_at_mut::<NtStatus>(request.status),
            core::ptr::with_exposed_provenance_mut::<AutomationState>(request.output as usize)
                .as_mut(),
        )
    };

    // The lock is released before the results are written.
    let polled = AUTOMATION.lock().poll(request.user, &mut Input);

    match polled {
        None => 0,
        Some(Poll::NotConnected) => {
            *status = KernelError::DeviceNotConnected.status();
            1
        }
        Some(Poll::State {
            packet_number,
            packet,
        }) => {
            *status = NtStatus::SUCCESS;
            if let Some(state) = state {
                *state = AutomationState {
                    packet_number,
                    gamepad: packet.to_console(),
                };
            }
            1
        }
    }
}

/// Monitor control 0x7b: connection status of a virtual controller. The
/// request's output is unused.
///
/// # Safety
///
/// `argument` must be the address of an `AutomationRequest` the caller
/// keeps unchanged for the call, whose status word is writable and not
/// otherwise accessed for the call.
pub(crate) unsafe fn service_automation_get_status(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let (request, status) = unsafe {
        let request = kernel::object_at::<AutomationRequest>(argument);
        (
            request,
            kernel::object_at_mut::<Win32ErrorCode>(request.status),
        )
    };

    let connected = AUTOMATION.lock().is_connected(request.user);

    match connected {
        None => 0,
        Some(connected) => {
            *status = if connected {
                Win32ErrorCode::SUCCESS
            } else {
                NOT_CONNECTED
            };
            1
        }
    }
}

/// Monitor control 0x7c: capabilities of a virtual controller; the output
/// receives an `XINPUT_CAPABILITIES`.
///
/// # Safety
///
/// `argument` must be the address of an `AutomationRequest` the caller
/// keeps unchanged for the call, whose status word is writable and whose
/// output is 0 or a writable `XINPUT_CAPABILITIES`, neither otherwise
/// accessed for the call.
pub(crate) unsafe fn service_automation_get_capabilities(argument: u32) -> u32 {
    type Capabilities = [u8; size_of::<xam::Capabilities>()];

    /// Capabilities reported for a connected virtual controller.
    const CAPABILITIES: Capabilities = [
        1, 1, 0, 0xe, 0xff, 0xff, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0,
    ];

    // SAFETY: the caller's contract.
    let (request, status, capabilities) = unsafe {
        let request = kernel::object_at::<AutomationRequest>(argument);
        (
            request,
            kernel::object_at_mut::<Win32ErrorCode>(request.status),
            core::ptr::with_exposed_provenance_mut::<Capabilities>(request.output as usize)
                .as_mut(),
        )
    };

    let connected = AUTOMATION.lock().is_connected(request.user);

    match connected {
        None => 0,
        Some(true) => {
            *status = Win32ErrorCode::SUCCESS;
            if let Some(capabilities) = capabilities {
                *capabilities = CAPABILITIES;
            }
            1
        }
        Some(false) => {
            *status = NOT_CONNECTED;
            1
        }
    }
}

/// Monitor control 0x21, first step: the input system restarted; bind
/// every installed controller again. Returns nothing meaningful; the
/// dispatcher continues with the title launch handling.
pub(crate) fn service_automation_rebind(_argument: u32) -> u32 {
    automation::rebind_all(&mut XboxControllers);
    0
}

/// Monitor control 0x7e without the DVD emulator check: whether title
/// decompression ignores GDF attributes. The dispatcher answers 1 instead
/// when the attached DVD emulator reports protocol 0002.
pub(crate) fn service_ignore_gdf_attributes(_argument: u32) -> u32 {
    u32::from(IGNORE_GDF_ATTRIBUTES.load(Ordering::Relaxed))
}

/// Monitor control 0x46 (0x91f3d210): the drive started a read.
///
/// # Safety
///
/// `argument` must be the address of a `ReadRequest` the caller keeps
/// valid and unchanged for the call.
pub(crate) unsafe fn service_odd_read_start(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = *unsafe { kernel::object_at::<ReadRequest>(argument) };
    let time = Timebase::now().ticks();

    if pix::stream_active() {
        let words = [
            (time >> 32) as u32,
            time as u32 & !odd_trace::COMPLETION,
            request.sector,
            request.count,
            ODD_AUTH_STATE.load(Ordering::Relaxed),
        ];
        pix::write_tagged_record(odd_trace::TAG, odd_trace::payload(words).as_flattened());
    }

    ODD_LOG.read_start(request, time);

    0
}

/// Monitor control 0x47 (0x91f3d6e0): the pending read completed; the
/// argument is the completion status itself.
pub(crate) fn service_odd_read_complete(argument: u32) -> u32 {
    let status = NtStatus(argument);
    let completed = Timebase::now().ticks();

    if pix::stream_active() {
        let words = [
            (completed >> 32) as u32,
            completed as u32 | odd_trace::COMPLETION,
            status.0,
        ];
        pix::write_tagged_record(odd_trace::TAG, odd_trace::payload(words).as_flattened());
    }

    ODD_LOG.read_complete(&mut OddServices, status, completed);

    0
}

/// Monitor control 0x48 (0x91f3d7a0): a GDFX volume was mounted.
///
/// # Safety
///
/// `argument` must be the address of the mounted volume's descriptor,
/// starting with a `MountRequest`, which the caller keeps valid and
/// unchanged for the call.
pub(crate) unsafe fn service_odd_mount(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = *unsafe { kernel::object_at::<MountRequest>(argument) };

    ODD_LOG.mount(&mut OddServices, request);

    0
}

/// Monitor control 0x49 (0x91f3d808): the spindle speed changed.
///
/// # Safety
///
/// `argument` must be the address of a `SpeedChangeRequest` the caller
/// keeps valid and unchanged for the call.
pub(crate) unsafe fn service_odd_speed_change(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = *unsafe { kernel::object_at::<SpeedChangeRequest>(argument) };

    ODD_LOG.speed_change(&mut OddServices, request);

    0
}

/// Monitor control 0x4a: the drive authentication state changed.
pub(crate) fn service_odd_auth_state(state: u32) -> u32 {
    ODD_AUTH_STATE.store(odd_auth_state(state), Ordering::Relaxed);
    0
}

fn input_focus() -> Option<u32> {
    Some(INPUT_FOCUS.load(Ordering::Relaxed)).filter(|&address| address != 0)
}

/// Address of a buffer a console service writes.
fn output_address<T: ?Sized>(value: &mut T) -> u32 {
    value as *mut T as *mut u8 as usize as u32
}

/// States 1 to 4 are kept; anything else reads as 0.
fn odd_auth_state(state: u32) -> u32 {
    if (1..=4).contains(&state) { state } else { 0 }
}

/// Startup (0x91f3d558): the log's events, then the drive's current
/// authentication state.
fn odd_initialize() {
    const OPTICAL_DRIVE: &[u8] = b"\\Device\\CdRom0";
    /// Object attributes stock passes when opening the drive.
    const OPTICAL_DRIVE_ATTRIBUTES: ObjectAttributeFlags =
        ObjectAttributeFlags::PERMANENT.union(ObjectAttributeFlags::CASE_INSENSITIVE);

    ODD_WRITER.work.initialize();
    ODD_WRITER.finished.initialize_notification(true);

    let name = kernel::ansi_string(OPTICAL_DRIVE);
    let attributes = xboxkrnl::ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: OPTICAL_DRIVE_ATTRIBUTES,
    };
    let mut io_status = xboxkrnl::IoStatusBlock::default();
    let mut handle = 0u32;
    // SAFETY: `handle`, `attributes`, the name it refers to and `io_status`
    // are live locals.
    let opened = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            xboxkrnl::AccessMask::GENERIC_READ,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            xboxkrnl::FileAttributes::NORMAL,
            xboxkrnl::ShareAccess::empty(),
            xboxkrnl::CreateDisposition::Open,
            xboxkrnl::CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    if opened.result().is_err() {
        return;
    }

    // Stock reads the output even when the request fails (uninitialized
    // stack); a failed request leaves 0 here.
    let mut state = [0u8; 4];
    // SAFETY: `handle` was opened above; `state` holds the output bytes.
    unsafe {
        xboxkrnl::NtDeviceIoControlFile(
            Handle::from_raw(handle),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            IoControlCode::ODD_AUTH_STATE,
            core::ptr::null(),
            0,
            state.as_mut_ptr(),
            state.len() as u32,
        )
    };
    ODD_AUTH_STATE.store(odd_auth_state(u32::from_be_bytes(state)), Ordering::Relaxed);

    // SAFETY: `handle` was opened above and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
}

/// Writer thread (0x91f3d878); the context is the log file handle.
extern "C" fn odd_writer(context: u32) -> u32 {
    let file = Handle::from_raw(context);

    while !ODD_LOG.is_stopped() {
        ODD_WRITER.work.wait();
        ODD_LOG.drain(&mut OddServices, file);
    }

    OddServices.close_file(file);
    ODD_WRITER.finished.set();

    0
}

/// The XAM input focus query for `user`; nonzero when the system has
/// focus.
fn query_input_focus(user: u32) -> Result<u32, ExportMissing> {
    let function = input_focus().ok_or(ExportMissing)?;

    // SAFETY: the query takes the user index.
    Ok(unsafe { kernel::call_export(function, user, 0, 0, 0) })
}

// Shared by the exports and the command backend.
#[inline(never)]
fn connect(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.lock().connect(user)
}

#[inline(never)]
fn disconnect(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.lock().disconnect(user)
}

#[inline(never)]
fn clear_queue(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.lock().clear_queue(user)
}

#[inline(never)]
fn query_queue(user: u32) -> Result<QueueStatus, AutomationError> {
    AUTOMATION.lock().query(user, &mut Input)
}

/// The avatar hook lookup; resolved on every use, as the monitor does.
fn avatar_lookup() -> Option<u32> {
    /// XAM ordinal: avatar test hook lookup `(index, &function) -> HRESULT`.
    const XAM_AVATAR_HOOKS: Ordinal = Ordinal::new(0x5f2).unwrap();

    xam_procedure(XAM_AVATAR_HOOKS)
}

/// Export 166 (stock 0x91f24468): input focus of `user` into `focus`;
/// 0 and `407` when the XAM query is absent.
extern "C" fn export_query_input_focus(user: u32, focus: *mut u32) -> Hresult {
    let (value, result) = match query_input_focus(user) {
        Ok(value) => (value, Hresult::OK),
        Err(ExportMissing) => (0, ErrorCode::UnknownCommand.hresult()),
    };

    // SAFETY: the caller passes a writable dword; stock writes it without a
    // null check or alignment.
    unsafe { focus.write_unaligned(value) };

    result
}

/// Export 167 (stock 0x91f24c08): `autoinput bind`.
extern "C" fn export_automation_bind(user: u32, queue_length: u32) -> Hresult {
    export_result(automation::bind(&mut XboxControllers, user, queue_length))
}

/// Export 168 (stock 0x91f24d60): `autoinput unbind`.
extern "C" fn export_automation_unbind(user: u32) -> Hresult {
    export_result(automation::unbind(&mut XboxControllers, user))
}

/// Export 169 (stock 0x91f244c8): `autoinput connect`.
extern "C" fn export_automation_connect(user: u32) -> Hresult {
    export_result(connect(user))
}

/// Export 170 (stock 0x91f24580): `autoinput disconnect`.
extern "C" fn export_automation_disconnect(user: u32) -> Hresult {
    export_result(disconnect(user))
}

/// Export 171 (stock 0x91f24e20): `autoinput setpacket` with a gamepad
/// state in console layout.
extern "C" fn export_automation_set_packet(
    user: u32,
    packet: *const [u8; Gamepad::WIRE_SIZE],
) -> Hresult {
    if user >= automation::USERS {
        return Hresult::from(AutomationError::BadParameter);
    }

    // SAFETY: the caller passes a gamepad state.
    let packet = unsafe { packet.read_unaligned() };
    let packet = Gamepad::from_console(&packet);

    export_result(automation::set_packet(&mut XboxControllers, user, packet))
}

/// Export 172 (stock 0x91f24f90): queue `count` gamepad states in console
/// layout with optional time and poll-count arrays; `queued` receives the
/// number accepted.
extern "C" fn export_automation_queue(
    user: u32,
    packets: *const [u8; Gamepad::WIRE_SIZE],
    times: *const u32,
    counts: *const u32,
    count: u32,
    queued: *mut u32,
) -> Hresult {
    if user >= automation::USERS
        || packets.is_null()
        || queued.is_null()
        || (times.is_null() && counts.is_null())
    {
        return Hresult::from(AutomationError::BadParameter);
    }

    let layout = UploadLayout {
        count,
        times: !times.is_null(),
        counts: !counts.is_null(),
    };
    // SAFETY: the caller passes `count` states and, where present, `count`
    // times and counts, without an alignment guarantee.
    let entry = |item: usize| unsafe {
        QueueEntry {
            packet: Gamepad::from_console(&packets.add(item).read_unaligned()),
            time: if times.is_null() {
                0
            } else {
                times.add(item).read_unaligned()
            },
            count: if counts.is_null() {
                0
            } else {
                counts.add(item).read_unaligned()
            },
        }
    };
    let accepted = AUTOMATION
        .lock()
        .queue_entries(user, layout, entry, &mut Input);

    match accepted {
        Ok(accepted) => {
            // SAFETY: checked non-null above; the caller passes a writable
            // dword, which stock does not align.
            unsafe { queued.write_unaligned(accepted) };
            Hresult::OK
        }
        Err(error) => Hresult::from(error),
    }
}

/// Export 173 (stock 0x91f24630): `autoinput clearqueue`.
extern "C" fn export_automation_clear_queue(user: u32) -> Hresult {
    export_result(clear_queue(user))
}

/// Export 174 (stock 0x91f246c8): `autoinput queryqueue`; every present
/// output is cleared first.
extern "C" fn export_automation_query_queue(
    user: u32,
    queue_length: *mut u32,
    queued: *mut u32,
    remaining_ms: *mut u32,
    remaining_count: *mut u32,
) -> Hresult {
    if user >= automation::USERS {
        return Hresult::from(AutomationError::BadParameter);
    }

    let outputs = [queue_length, queued, remaining_ms, remaining_count];
    let store = |values: [u32; 4]| {
        for (output, value) in outputs.into_iter().zip(values) {
            if !output.is_null() {
                // SAFETY: the caller passes writable dwords or null, which
                // stock does not align; two outputs may name the same
                // dword, so no reference is made.
                unsafe { output.write_unaligned(value) };
            }
        }
    };
    store([0; 4]);

    match query_queue(user) {
        Ok(status) => {
            store([
                status.queue_length,
                status.queued,
                status.remaining_ms,
                status.remaining_count,
            ]);
            Hresult::OK
        }
        Err(error) => Hresult::from(error),
    }
}

/// Export 147 (stock 0x91f3dad0): start the optical disc log at the drive
/// path `path`. Stock checks the busy writer first; its writer then
/// translates the name through the drive table (0x91f2eb68). Here the
/// caller translates it with the published table after the busy check,
/// and a name that does not translate fails with STATUS_NO_SUCH_FILE as
/// stock's open does.
extern "C" fn export_odd_log_start(path: *const core::ffi::c_char) -> Hresult {
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();

    let reservation = match ODD_LOG.reserve(&mut OddServices) {
        Ok(reservation) => reservation,
        Err(error) => return Hresult::from(error),
    };

    let translated = filesystem::published_drives().translate(&mut CallerPaths::new(), name);
    let translated = translated
        .as_ref()
        .map(ObjectPath::as_bytes)
        .ok_or(KernelError::NoSuchFile);

    export_result(ODD_LOG.start(&mut OddServices, reservation, translated))
}

/// Export 148 (stock 0x91f3d140): stop the optical disc log.
extern "C" fn export_odd_log_stop() -> Hresult {
    export_result(ODD_LOG.stop(&mut OddServices))
}

export!(147, export_odd_log_start);
export!(148, export_odd_log_stop);
export!(166, export_query_input_focus);
export!(167, export_automation_bind);
export!(168, export_automation_unbind);
export!(169, export_automation_connect);
export!(170, export_automation_disconnect);
export!(171, export_automation_set_packet);
export!(172, export_automation_queue);
export!(173, export_automation_clear_queue);
export!(174, export_automation_query_queue);
