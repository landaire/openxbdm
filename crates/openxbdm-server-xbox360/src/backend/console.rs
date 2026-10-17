//! Console identity and configuration services.

mod error;
mod exports;
mod http;

use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::Platform;
use openxbdm_server::commands;
use openxbdm_server::commands::console::CONSOLE_ID_LENGTH;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::ConsoleId;
use openxbdm_server::commands::console::DUMP_SETTINGS_SIZE;
use openxbdm_server::commands::console::DebugName;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::HttpStartFailure;
use openxbdm_server::commands::console::KitFeatures;
use openxbdm_server::commands::console::MemoryStatistics;
use openxbdm_server::commands::console::NETWORK_ADDRESS_SIZE;
use openxbdm_server::commands::console::NetworkAddress;
use openxbdm_server::commands::console::NetworkRaError;
use openxbdm_server::commands::console::NetworkRaFlags;
use openxbdm_server::commands::console::NetworkRaRecord;
use openxbdm_server::commands::console::NetworkRaRequest;
use openxbdm_server::commands::console::Published;
use openxbdm_server::commands::console::RegistrationResult;
use openxbdm_server::commands::console::SETTINGS_BLOCK_SIZE;
use openxbdm_server::commands::console::SYSTEM_SETTINGS_SIZE;
use openxbdm_server::commands::console::SystemInformation;
use openxbdm_server::commands::console::SystemSettings;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::console::Version;
use openxbdm_server::commands::hardware::SystemApp;
use openxbdm_server::commands::hardware::SystemMessage;
use openxbdm_server::text::LineText;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::sync::SpinLock;
use xbox360::time::TickCount;
use xbox360::time::sleep;
use xbox360_sys::processor;
use xbox360_sys::xam;
use xbox360_sys::xam::XamSetInactivityTimeFromConfig;
use xbox360_sys::xam::XnAddrStatus;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::SmcCommand;
use xbox360_sys::xboxkrnl::SmcI2cDevice;
use xbox360_sys::xboxkrnl::SmcMessage;
use xbox360_sys::xboxkrnl::XeKeysGetConsoleID;

use self::http::HTTP_BODY;
use super::Console;
use crate::kernel;
use crate::kernel::version_words;
use crate::net;

pub(crate) use self::exports::service_get_debug_name;
pub(crate) use self::exports::service_get_system_settings;
pub(crate) use self::exports::service_set_system_settings;

/// Bytes per SMC I2C transfer.
const SMC_I2C_CHUNK: usize = 8;
/// Attempts per SMC I2C transfer.
const SMC_I2C_ATTEMPTS: usize = 2;

/// The server's debug name, for other threads (stock 0x91fab9c0).
static DEBUG_NAME: SpinLock<DebugName> = SpinLock::new(DebugName::EMPTY);

/// Settings block of control codes 0x1e and 0x1f (stock 0x91fade20).
static SYSTEM_SETTINGS: SpinLock<SystemSettings> =
    SpinLock::new(SystemSettings([0; SYSTEM_SETTINGS_SIZE]));

/// Startup found a test kit that lacks the hardware flag (stock 0x91f9f680).
static TEST_KIT: AtomicBool = AtomicBool::new(false);

/// Mirrors of the server's crash dump mode (stock 0x91f9f660), crash dump
/// settings block (0x91f9f520) and event defer mask (0x91f97604), with
/// the server's initial values.
static DUMP_MODE: AtomicU32 = AtomicU32::new(0);
static DUMP_SETTINGS: SpinLock<[u8; DUMP_SETTINGS_SIZE]> = SpinLock::new([0; DUMP_SETTINGS_SIZE]);
static EVENT_DEFER: AtomicU32 = AtomicU32::new(0x27);

/// Mirror of the server's trace mask (stock 0x91f9fef4).
static TRACE_MASK: AtomicU32 = AtomicU32::new(0);

/// Mirror of the lab server registration (stock 0x91f9f638 state,
/// 0x91f9f654 length, 0x91f9f658 transaction, 0x91fadee0 response).
static REGISTRATION: SpinLock<RegistrationResult> = SpinLock::new(RegistrationResult::EMPTY);

/// Platform state of this domain.
pub struct Data {
    /// Kernel export 700 once resolved; stock retries until it resolves.
    config_modify: Option<u32>,

    http_started: bool,
    http_session: u32,
    http_connection: u32,
    http_request: u32,

    /// NUL-terminated server name and path of the registration request.
    /// XAM keeps their addresses from `NetDll_XHttpConnect` and
    /// `NetDll_XHttpOpenRequest` and reads them during later
    /// `NetDll_XHttpDoWork` calls until `close_http` closes the handles.
    /// Only `begin_http` writes them, before the handles exist, so XAM's
    /// reads never overlap a write; they are module state with a fixed
    /// address.
    http_server: [u8; 0x100],
    http_path: [u8; 0x400],
}

impl Data {
    pub const fn new() -> Self {
        Self {
            config_modify: None,
            http_started: false,
            http_session: 0,
            http_connection: 0,
            http_request: 0,
            http_server: [0; 0x100],
            http_path: [0; 0x400],
        }
    }
}

/// Operation of a [`NetworkRaMessage`].
#[repr(u32)]
#[derive(Clone, Copy)]
enum NetworkRaOperation {
    Get = 0,
    Set = 1,
}

/// Request record of the network configuration message.
#[repr(C)]
struct NetworkRaMessage {
    /// A [`NetworkRaOperation`]; the service may rewrite the record.
    operation: u32,
    flags: u32,
    custom_boot_address: u32,
}

/// Descriptor kind of the network configuration message.
#[repr(u32)]
#[derive(Clone, Copy)]
enum NetworkRaKind {
    Reset = 2,
    Record = 5,
}

/// Descriptor passed with the network configuration message.
#[repr(C)]
struct NetworkRaDescriptor {
    /// A [`NetworkRaKind`].
    kind: u32,
    record: u32,
    size: u32,
}

impl Console {
    fn config_modify_export(&mut self) -> Option<u32> {
        // Kernel export that atomically modifies a configuration dword.
        const CONFIG_MODIFY_ORDINAL: Ordinal = Ordinal::new(700).unwrap();

        if self.console.config_modify.is_none() {
            let module = SystemModule::Kernel.handle().ok()?;
            self.console.config_modify = resolve_export(module, CONFIG_MODIFY_ORDINAL)
                .ok()
                .map(ExportAddress::raw);
        }

        self.console.config_modify
    }

    fn feature_switch(&mut self) -> Option<u32> {
        // System UI library export that switches a feature.
        const FEATURE_SWITCH_ORDINAL: Ordinal = Ordinal::new(515).unwrap();

        let module = SystemModule::Xam.handle().ok()?;

        let mut address = 0u32;
        // SAFETY: `address` is a live local.
        unsafe {
            xboxkrnl::XexGetProcedureAddress(
                module.raw(),
                u32::from(FEATURE_SWITCH_ORDINAL.get()),
                &mut address,
            )
        }
        .result()
        .ok()?;

        Some(address)
    }

    fn network_address(
        query: unsafe extern "C" fn(XnCaller, *mut u8) -> XnAddrStatus,
    ) -> NetworkAddress {
        let mut record = [0u8; NETWORK_ADDRESS_SIZE];
        // SAFETY: `record` is a live buffer of the XNADDR size.
        let status = unsafe { query(XnCaller::DebugMonitor, record.as_mut_ptr()) }.bits();

        NetworkAddress { status, record }
    }
}

impl commands::console::Backend for Console {
    fn kit_features(&mut self) -> KitFeatures {
        kit_features()
    }

    fn xconfig_get(
        &mut self,
        setting: ConfigSetting,
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        // The export takes a 16-bit size, so a larger buffer is offered as
        // its first 0xffff bytes.
        let capacity = u16::try_from(output.len()).unwrap_or(u16::MAX);

        let mut length = 0u16;
        // SAFETY: `output` holds at least `capacity` bytes, and `output` and
        // `length` are live for the call.
        unsafe {
            xboxkrnl::ExGetXConfigSetting(
                u16::from(setting.category),
                u16::from(setting.index),
                output.as_mut_ptr(),
                capacity,
                &mut length,
            )
        }
        .result()?;

        Ok(usize::from(length))
    }

    fn xconfig_set(&mut self, setting: ConfigSetting, value: &[u8]) -> Result<(), KernelError> {
        let size = u16::try_from(value.len()).map_err(|_| KernelError::InvalidParameter)?;

        // SAFETY: `value` is live for the call.
        unsafe {
            xboxkrnl::ExSetXConfigSetting(
                u16::from(setting.category),
                u16::from(setting.index),
                value.as_ptr(),
                size,
            )
        }
        .result()
    }

    fn xconfig_modify(
        &mut self,
        setting: ConfigSetting,
        and_mask: u32,
        or_mask: u32,
    ) -> Result<(), KernelError> {
        let Some(function) = self.config_modify_export() else {
            return Err(KernelError::OrdinalNotFound);
        };

        // SAFETY: export 700 takes (category, index, and mask, or mask).
        let status = unsafe {
            kernel::call_export(
                function,
                u32::from(setting.category),
                u32::from(setting.index),
                and_mask,
                or_mask,
            )
        };

        NtStatus(status).result()
    }

    /// Stock 0x91f4e378: four 8-byte SMC reads, two attempts each.
    fn read_settings_block(&mut self) -> Option<[u8; SETTINGS_BLOCK_SIZE]> {
        let mut block = [0u8; SETTINGS_BLOCK_SIZE];

        for address in (0..SETTINGS_BLOCK_SIZE).step_by(SMC_I2C_CHUNK) {
            let mut message = smc_i2c_message(address, 0);
            message.0[2] = SMC_I2C_CHUNK as u8;
            message.0[5] = SmcI2cDevice::SETTINGS_EEPROM.0;

            let reply = (0..SMC_I2C_ATTEMPTS).find_map(|_| {
                let mut reply = SmcMessage::default();
                // SAFETY: `message` and `reply` are live SMC messages.
                unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
                (reply.0[1] == 0).then_some(reply)
            })?;

            block[address..address + SMC_I2C_CHUNK].copy_from_slice(&reply.0[3..3 + SMC_I2C_CHUNK]);
        }

        Some(block)
    }

    /// Stock 0x91f4e4e0: four 8-byte SMC writes, two attempts each, with a
    /// 2 ms pause after a write and 3 ms after a failure.
    fn write_settings_block(&mut self, block: &[u8; SETTINGS_BLOCK_SIZE]) -> bool {
        for address in (0..SETTINGS_BLOCK_SIZE).step_by(SMC_I2C_CHUNK) {
            let mut message = smc_i2c_message(address, SMC_I2C_CHUNK);
            message.0[7..7 + SMC_I2C_CHUNK]
                .copy_from_slice(&block[address..address + SMC_I2C_CHUNK]);

            let written = (0..SMC_I2C_ATTEMPTS).any(|_| {
                let mut reply = SmcMessage::default();
                // SAFETY: `message` and `reply` are live SMC messages.
                unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
                if reply.0[1] == 0 {
                    sleep(Duration::from_millis(2));
                    return true;
                }

                sleep(Duration::from_millis(3));
                let error = reply.0[1];
                let mut text = LineText::new();
                let _ = writeln!(
                    text,
                    "dm: I2C Write failed.  Error=0x{error:x}, Addr={address}, DataLen={SMC_I2C_CHUNK}, "
                );
                self.debug_print(text.as_bytes());

                false
            });

            if !written {
                return false;
            }
        }

        true
    }

    fn memory_statistics(&mut self) -> Option<MemoryStatistics> {
        memory_statistics()
    }

    fn system_information(&mut self) -> SystemInformation {
        SystemInformation {
            base_kernel: Version(version_words(kernel::base_kernel_version())),
            kernel: Version(version_words(kernel_version())),
            hardware_flags: hardware_flags(),
        }
    }

    fn console_id(&mut self) -> Result<ConsoleId, KernelError> {
        let mut text = [0u8; CONSOLE_ID_LENGTH + 1];
        // SAFETY: `text` holds the console ID text and its NUL.
        unsafe { XeKeysGetConsoleID(core::ptr::null_mut(), text.as_mut_ptr()) }.result()?;

        let mut id = [0u8; CONSOLE_ID_LENGTH];
        id.copy_from_slice(&text[..CONSOLE_ID_LENGTH]);

        Ok(ConsoleId(id))
    }

    fn debug_network_address(&mut self) -> NetworkAddress {
        Self::network_address(xam::NetDll_XNetGetDebugXnAddr)
    }

    fn title_network_address(&mut self) -> NetworkAddress {
        Self::network_address(xam::NetDll_XNetGetTitleXnAddr)
    }

    fn apply_inactivity_time(&mut self) {
        // SAFETY: takes a scalar flag and reads the console configuration.
        unsafe { XamSetInactivityTimeFromConfig(1) };
    }

    fn network_ra_request(&mut self, request: NetworkRaRequest<'_>) -> Result<(), NetworkRaError> {
        let (operation, record) = match request {
            NetworkRaRequest::Reset => {
                let mut descriptor = NetworkRaDescriptor {
                    kind: NetworkRaKind::Reset as u32,
                    record: 0,
                    size: 0,
                };
                return send_network_ra(&mut descriptor);
            }
            NetworkRaRequest::Get(record) => (NetworkRaOperation::Get, record),
            NetworkRaRequest::Set(record) => (NetworkRaOperation::Set, record),
        };

        let mut message = NetworkRaMessage {
            operation: operation as u32,
            flags: record.flags.bits(),
            custom_boot_address: record.custom_boot_address,
        };
        let mut descriptor = NetworkRaDescriptor {
            kind: NetworkRaKind::Record as u32,
            record: &mut message as *mut NetworkRaMessage as usize as u32,
            size: size_of::<NetworkRaMessage>() as u32,
        };
        let result = send_network_ra(&mut descriptor);

        *record = NetworkRaRecord {
            flags: NetworkRaFlags::from_bits_retain(message.flags),
            custom_boot_address: message.custom_boot_address,
        };

        result
    }

    fn feature_switch_present(&mut self) -> bool {
        self.feature_switch().is_some()
    }

    fn set_feature(&mut self, enable: u32, feature: u32) {
        let Some(function) = self.feature_switch() else {
            return;
        };

        // SAFETY: XAM export 515 takes (enable, feature).
        unsafe { kernel::call_export(function, enable, feature, 0, 0) };
    }

    fn load_network_client(&mut self) -> Result<(), KernelError> {
        // SAFETY: the path is NUL-terminated; a null handle pointer is
        // allowed.
        unsafe {
            xboxkrnl::XexLoadImage(
                c"\\SystemRoot\\connectx.xex".as_ptr().cast(),
                ImageFlags::DLL,
                ImageVersion::ANY,
                core::ptr::null_mut(),
            )
        }
        .result()
    }

    fn tick_milliseconds(&mut self) -> u32 {
        TickCount::now().milliseconds()
    }

    fn xam_version(&mut self) -> u32 {
        xam::XamGetSystemVersion()
    }

    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure> {
        self.console.begin_http(request)
    }

    fn http_poll(&mut self) -> HttpProgress {
        self.console.poll_http()
    }

    fn http_close(&mut self) {
        self.console.close_http();
    }

    fn publish(&mut self, value: Published<'_>) {
        match value {
            Published::DebugName(name) => *DEBUG_NAME.lock() = *name,
            Published::DumpMode(mode) => DUMP_MODE.store(mode.raw(), Ordering::Release),
            Published::DumpSettings(settings) => *DUMP_SETTINGS.lock() = settings.to_block(),
            Published::EventDefer(mask) => EVENT_DEFER.store(mask.bits(), Ordering::Release),
            Published::TraceMask(mask) => TRACE_MASK.store(mask.bits(), Ordering::Release),
            Published::Registration(registration) => {
                // SAFETY: `publish` runs on the server thread, the only one
                // that calls into XAM, so no XAM write to `HTTP_BODY` is in
                // progress and no other reference to it exists.
                let body = unsafe { &*(&raw const HTTP_BODY) };
                *REGISTRATION.lock() = RegistrationResult::new(registration, body);
            }
        }
    }

    fn system_settings(&mut self) -> SystemSettings {
        *SYSTEM_SETTINGS.lock()
    }

    fn set_system_settings(&mut self, settings: SystemSettings) {
        *SYSTEM_SETTINGS.lock() = settings;
    }

    fn mark_test_kit(&mut self) {
        TEST_KIT.store(true, Ordering::Release);
    }

    fn current_thread(&mut self) -> u32 {
        processor::current_thread()
    }

    fn trace_mask(&mut self) -> TraceMask {
        trace_mask()
    }
}

/// The server's trace mask, for code that runs on other threads.
pub(crate) fn trace_mask() -> TraceMask {
    TraceMask::from_bits_retain(TRACE_MASK.load(Ordering::Acquire))
}

/// The debug name the server published; readable on any thread.
pub(crate) fn debug_name() -> DebugName {
    *DEBUG_NAME.lock()
}

/// Whether startup marked the console as a test kit.
pub(crate) fn test_kit_marked() -> bool {
    TEST_KIT.load(Ordering::Acquire)
}

/// Stock 0x91f4cd60 (export 220, `consolefeatures`).
fn kit_features() -> KitFeatures {
    let flags = hardware_flags();

    KitFeatures {
        debugging: !flags.contains(HardwareFlags::TEST_KIT),
        secondary_nic: net::has_secondary_nic(),
        one_gigabyte_ram: flags.contains(HardwareFlags::ONE_GIGABYTE),
    }
}

/// `ExDebugMonitorService` 8; `None` when it fails or replies short.
fn memory_statistics() -> Option<MemoryStatistics> {
    let mut block = DebugMemoryStatistics::new();
    // SAFETY: `block` is a live statistics block whose length fields give
    // its size.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            &mut block as *mut DebugMemoryStatistics as usize as u32,
            0,
            0,
        )
    };
    if status.result().is_err() || !block.is_complete() {
        return None;
    }

    Some(MemoryStatistics {
        physical_pages: block.statistics.total_physical_pages,
        debug_memory: block.debug_memory,
        page_threshold: block.page_threshold,
    })
}

/// An I2C transfer to the settings EEPROM at `address` that writes
/// `written` data bytes after the address byte.
fn smc_i2c_message(address: usize, written: usize) -> SmcMessage {
    let mut message = SmcMessage::new(SmcCommand::I2c);
    // Bytes written, counting the address byte, in the high nibble.
    message.0[1] = ((written + 1) << 4) as u8;
    message.0[3] = SmcI2cDevice::SETTINGS_EEPROM.0;
    message.0[6] = address as u8;

    message
}

fn send_network_ra(descriptor: &mut NetworkRaDescriptor) -> Result<(), NetworkRaError> {
    // System message service of the network configuration and its message.
    const NETWORK_APP: SystemApp = SystemApp(0xef);
    const NETWORK_RA_MESSAGE: SystemMessage = SystemMessage(0x00a0_0004);

    // SAFETY: `descriptor` is live for the synchronous request; no
    // overlapped block is passed.
    let result = unsafe {
        xam::XMsgStartIORequest(
            NETWORK_APP.0,
            NETWORK_RA_MESSAGE.0,
            core::ptr::null_mut(),
            (descriptor as *mut NetworkRaDescriptor).cast(),
            size_of::<NetworkRaDescriptor>() as u32,
        )
    };
    if result.is_failure() {
        return Err(NetworkRaError(result));
    }

    Ok(())
}
