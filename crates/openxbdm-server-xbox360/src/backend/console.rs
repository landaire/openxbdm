//! Console identity and configuration services.

use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::Platform;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::console::CONSOLE_ID_LENGTH;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::ConsoleId;
use openxbdm_server::commands::console::ConsoleMemory;
use openxbdm_server::commands::console::DEBUG_NAME_CAPACITY;
use openxbdm_server::commands::console::DUMP_SETTINGS_SIZE;
use openxbdm_server::commands::console::DebugName;
use openxbdm_server::commands::console::ExportedSetting;
use openxbdm_server::commands::console::HttpFailure;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::HttpStartFailure;
use openxbdm_server::commands::console::HttpStartStage;
use openxbdm_server::commands::console::KitFeatures;
use openxbdm_server::commands::console::MemoryStatistics;
use openxbdm_server::commands::console::NETWORK_ADDRESS_SIZE;
use openxbdm_server::commands::console::NetworkAddress;
use openxbdm_server::commands::console::NetworkRaError;
use openxbdm_server::commands::console::NetworkRaFlags;
use openxbdm_server::commands::console::NetworkRaRecord;
use openxbdm_server::commands::console::NetworkRaRequest;
use openxbdm_server::commands::console::Published;
use openxbdm_server::commands::console::REGISTRATION_RESPONSE_CAPACITY;
use openxbdm_server::commands::console::RegistrationResult;
use openxbdm_server::commands::console::SETTINGS_BLOCK_SIZE;
use openxbdm_server::commands::console::SYSTEM_SETTINGS_SIZE;
use openxbdm_server::commands::console::SystemInformation;
use openxbdm_server::commands::console::SystemSettings;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::console::Version;
use openxbdm_server::text::LineText;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::status::last_error;
use xbox360::sync::SpinLock;
use xbox360::time::TickCount;
use xbox360::time::sleep;
use xbox360_sys::export_raw;
use xbox360_sys::processor;
use xbox360_sys::xam;
use xbox360_sys::xam::NetDll_XHttpCloseHandle;
use xbox360_sys::xam::NetDll_XHttpConnect;
use xbox360_sys::xam::NetDll_XHttpDoWork;
use xbox360_sys::xam::NetDll_XHttpOpen;
use xbox360_sys::xam::NetDll_XHttpOpenRequest;
use xbox360_sys::xam::NetDll_XHttpQueryHeaders;
use xbox360_sys::xam::NetDll_XHttpReadData;
use xbox360_sys::xam::NetDll_XHttpReceiveResponse;
use xbox360_sys::xam::NetDll_XHttpSendRequest;
use xbox360_sys::xam::NetDll_XHttpSetOption;
use xbox360_sys::xam::NetDll_XHttpSetStatusCallback;
use xbox360_sys::xam::NetDll_XHttpShutdown;
use xbox360_sys::xam::NetDll_XHttpStartup;
use xbox360_sys::xam::XamSetInactivityTimeFromConfig;
use xbox360_sys::xam::XnAddrStatus;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::SmcCommand;
use xbox360_sys::xboxkrnl::SmcMessage;
use xbox360_sys::xboxkrnl::XeKeysGetConsoleID;

use super::Console;
use super::HARDWARE_NOT_DEBUGGABLE;
use crate::exports::bridged;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::version_words;
use crate::net;
use crate::net::XamNetwork;

/// Hardware flag: 1 GiB of memory is installed.
const HARDWARE_ONE_GIGABYTE: u32 = 0x0001_0000;
/// Kernel export that atomically modifies a configuration dword.
const CONFIG_MODIFY_ORDINAL: Ordinal = Ordinal::new(700).unwrap();
/// System UI library export that switches a feature.
const FEATURE_SWITCH_ORDINAL: u32 = 515;
/// Size of the memory statistics block of `ExDebugMonitorService` 8.
const MEMORY_STATISTICS_SIZE: usize = 0x90;
/// System message service of the network configuration and its message.
const NETWORK_SERVICE: u32 = 0xef;
const NETWORK_RA_MESSAGE: u32 = 0x00a0_0004;
/// Descriptor kinds of the network configuration message.
const NETWORK_RA_RECORD: u32 = 5;
const NETWORK_RA_RESET: u32 = 2;
/// I2C device of the settings block.
const SMC_I2C_DEVICE: u8 = 0xd4;
/// Bytes per SMC I2C transfer.
const SMC_I2C_CHUNK: usize = 8;
/// Attempts per SMC I2C transfer.
const SMC_I2C_ATTEMPTS: usize = 2;

/// Platform state of this domain.
pub struct Data {
    /// Kernel export 700 once resolved; stock retries until it resolves.
    config_modify: Option<u32>,
    http_started: bool,
    http_session: u32,
    http_connection: u32,
    http_request: u32,
    /// NUL-terminated server name and path of the registration request.
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

/// Request record of the network configuration message.
#[repr(C)]
struct NetworkRaMessage {
    operation: u32,
    flags: u32,
    custom_boot_address: u32,
}

/// Descriptor passed with the network configuration message.
#[repr(C)]
struct NetworkRaDescriptor {
    kind: u32,
    record: u32,
    size: u32,
}

fn smc_i2c_message(address: usize) -> SmcMessage {
    let mut message = SmcMessage::new(SmcCommand::I2c);
    message.0[3] = SMC_I2C_DEVICE;
    message.0[6] = address as u8;
    message
}

fn send_network_ra(descriptor: &mut NetworkRaDescriptor) -> Result<(), NetworkRaError> {
    // SAFETY: `descriptor` is live for the synchronous request; no
    // overlapped block is passed.
    let result = unsafe {
        xam::XMsgStartIORequest(
            NETWORK_SERVICE,
            NETWORK_RA_MESSAGE,
            core::ptr::null_mut(),
            (descriptor as *mut NetworkRaDescriptor).cast(),
            size_of::<NetworkRaDescriptor>() as u32,
        )
    };
    if result.is_failure() {
        Err(NetworkRaError(result))
    } else {
        Ok(())
    }
}

impl Console {
    fn config_modify_export(&mut self) -> Option<u32> {
        if self.console.config_modify.is_none() {
            let module = SystemModule::Kernel.handle().ok()?;
            self.console.config_modify = resolve_export(module, CONFIG_MODIFY_ORDINAL)
                .ok()
                .map(ExportAddress::raw);
        }
        self.console.config_modify
    }

    fn feature_switch(&mut self) -> Option<u32> {
        let module = SystemModule::Xam.handle().ok()?;
        let mut address = 0u32;
        // SAFETY: `address` is a live local.
        unsafe {
            xboxkrnl::XexGetProcedureAddress(module.raw(), FEATURE_SWITCH_ORDINAL, &mut address)
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

/// Stock 0x91f4cd60 (export 220, `consolefeatures`).
fn kit_features() -> KitFeatures {
    let flags = hardware_flags().bits();
    KitFeatures {
        debugging: flags & HARDWARE_NOT_DEBUGGABLE == 0,
        secondary_nic: net::has_secondary_nic(),
        one_gigabyte_ram: flags & HARDWARE_ONE_GIGABYTE != 0,
    }
}

/// `ExDebugMonitorService` 8; `None` when it fails or replies short.
fn memory_statistics() -> Option<MemoryStatistics> {
    let mut words = [0u32; MEMORY_STATISTICS_SIZE / 4];
    words[0] = MEMORY_STATISTICS_SIZE as u32;
    words[1] = 0x68;
    // SAFETY: `words` is a live buffer whose first word gives its size.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            words.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    if status.result().is_err() || (words[0] as usize) < MEMORY_STATISTICS_SIZE {
        return None;
    }
    Some(MemoryStatistics {
        physical_pages: words[2],
        debug_memory: words[0x70 / 4],
        page_threshold: words[0x7c / 4],
    })
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
            let mut message = smc_i2c_message(address);
            message.0[1] = 0x10;
            message.0[2] = SMC_I2C_CHUNK as u8;
            message.0[5] = SMC_I2C_DEVICE;
            let mut done = false;
            for _ in 0..SMC_I2C_ATTEMPTS {
                let mut reply = SmcMessage::default();
                // SAFETY: `message` and `reply` are live SMC messages.
                unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
                if reply.0[1] == 0 {
                    block[address..address + SMC_I2C_CHUNK]
                        .copy_from_slice(&reply.0[3..3 + SMC_I2C_CHUNK]);
                    done = true;
                    break;
                }
            }
            if !done {
                return None;
            }
        }
        Some(block)
    }

    /// Stock 0x91f4e4e0: four 8-byte SMC writes, two attempts each, with a
    /// 2 ms pause after a write and 3 ms after a failure.
    fn write_settings_block(&mut self, block: &[u8; SETTINGS_BLOCK_SIZE]) -> bool {
        for address in (0..SETTINGS_BLOCK_SIZE).step_by(SMC_I2C_CHUNK) {
            let mut message = smc_i2c_message(address);
            message.0[1] = ((SMC_I2C_CHUNK + 1) << 4) as u8;
            message.0[7..7 + SMC_I2C_CHUNK]
                .copy_from_slice(&block[address..address + SMC_I2C_CHUNK]);
            let mut done = false;
            for _ in 0..SMC_I2C_ATTEMPTS {
                let mut reply = SmcMessage::default();
                // SAFETY: `message` and `reply` are live SMC messages.
                unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
                if reply.0[1] == 0 {
                    sleep(Duration::from_millis(2));
                    done = true;
                    break;
                }
                sleep(Duration::from_millis(3));
                let mut text = LineText::new();
                let _ = writeln!(
                    text,
                    "dm: I2C Write failed.  Error=0x{:x}, Addr={}, DataLen={}, ",
                    reply.0[1], address, SMC_I2C_CHUNK
                );
                self.debug_print(text.as_bytes());
            }
            if !done {
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
            hardware_flags: hardware_flags().bits(),
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
                    kind: NETWORK_RA_RESET,
                    record: 0,
                    size: 0,
                };
                return send_network_ra(&mut descriptor);
            }
            NetworkRaRequest::Get(record) => (0, record),
            NetworkRaRequest::Set(record) => (1, record),
        };
        let mut message = NetworkRaMessage {
            operation,
            flags: record.flags.bits(),
            custom_boot_address: record.custom_boot_address,
        };
        let mut descriptor = NetworkRaDescriptor {
            kind: NETWORK_RA_RECORD,
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
        if let Some(function) = self.feature_switch() {
            // SAFETY: XAM export 515 takes (enable, feature).
            unsafe { kernel::call_export(function, enable, feature, 0, 0) };
        }
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

    /// Stock 0x91f300e0 after the URL is built.
    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure> {
        let data = &mut self.console;
        let fail = |data: &mut Data, stage| {
            let error = last_error();
            data.close_http();
            Err(HttpStartFailure { stage, error })
        };
        // SAFETY: startup takes scalar arguments.
        if unsafe { NetDll_XHttpStartup(XnCaller::DebugMonitor, 0, 0) } == 0 {
            return Err(HttpStartFailure {
                stage: HttpStartStage::Startup,
                error: last_error(),
            });
        }
        data.http_started = true;
        // SAFETY: the user agent string is NUL-terminated.
        data.http_session = unsafe {
            NetDll_XHttpOpen(
                XnCaller::DebugMonitor,
                c"Xbox Debugger/2.0.21256.0".as_ptr().cast(),
                0,
                0,
                0,
                0x1000_0000,
            )
        };
        if data.http_session == 0 {
            return fail(data, HttpStartStage::Session);
        }
        let server = request.server.len().min(data.http_server.len() - 1);
        data.http_server[..server].copy_from_slice(&request.server[..server]);
        data.http_server[server] = 0;
        // SAFETY: `http_server` is NUL-terminated module state that outlives
        // the session.
        data.http_connection = unsafe {
            NetDll_XHttpConnect(
                XnCaller::DebugMonitor,
                data.http_session,
                data.http_server.as_ptr(),
                u32::from(request.port),
                1,
            )
        };
        if data.http_connection == 0 {
            return fail(data, HttpStartStage::Connection);
        }
        let path = request.path.len().min(data.http_path.len() - 1);
        data.http_path[..path].copy_from_slice(&request.path[..path]);
        data.http_path[path] = 0;
        // SAFETY: the verb and `http_path` are NUL-terminated; `http_path`
        // is module state that outlives the request.
        data.http_request = unsafe {
            NetDll_XHttpOpenRequest(
                XnCaller::DebugMonitor,
                data.http_connection,
                c"GET".as_ptr().cast(),
                data.http_path.as_ptr(),
                0,
                0,
                0,
                0,
            )
        };
        if data.http_request == 0 {
            return fail(data, HttpStartStage::Request);
        }
        let mut value = 3u32;
        // SAFETY: `http_status_entry` has the status callback signature and
        // `value` is a live 4-byte option buffer.
        unsafe {
            NetDll_XHttpSetStatusCallback(
                XnCaller::DebugMonitor,
                data.http_request,
                http_status_entry as *const () as usize as u32,
                u32::MAX,
                0,
            );
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                data.http_request,
                0x59,
                &mut value,
                4,
            );
            value = 8;
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                data.http_request,
                0x3f,
                &mut value,
                4,
            );
        }
        HTTP_STATE.store(1, Ordering::Relaxed);
        // SAFETY: the request handle was opened above; no headers or body.
        if unsafe {
            NetDll_XHttpSendRequest(XnCaller::DebugMonitor, data.http_request, 0, 0, 0, 0, 0, 0)
        } == 0
        {
            return fail(data, HttpStartStage::Send);
        }
        Ok(())
    }

    /// Stock 0x91f30580 states 1 to 7; the status callback advances the
    /// state during `NetDll_XHttpDoWork`.
    fn http_poll(&mut self, body: &mut [u8; REGISTRATION_RESPONSE_CAPACITY]) -> HttpProgress {
        let data = &mut self.console;
        // SAFETY: the session handle was opened by `http_begin`.
        if unsafe { NetDll_XHttpDoWork(XnCaller::DebugMonitor, data.http_session, 0) } == 0 {
            return HttpProgress::Failed(HttpFailure::Work {
                error: last_error(),
            });
        }
        if HTTP_STATE.load(Ordering::Relaxed) == 2 {
            HTTP_STATE.store(3, Ordering::Relaxed);
            // SAFETY: the request handle was opened by `http_begin`.
            if unsafe { NetDll_XHttpReceiveResponse(XnCaller::DebugMonitor, data.http_request, 0) }
                == 0
            {
                return HttpProgress::Failed(HttpFailure::Receive {
                    error: last_error(),
                });
            }
        }
        if HTTP_STATE.load(Ordering::Relaxed) == 4 {
            let mut code = 0u32;
            let mut length = 4u32;
            // SAFETY: `code` and `length` are live locals of the stated size.
            if unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    data.http_request,
                    0x2000_fffe,
                    0,
                    &mut code,
                    &mut length,
                    0,
                )
            } == 0
            {
                return HttpProgress::Failed(HttpFailure::StatusQuery {
                    error: last_error(),
                });
            }
            if code != 200 {
                return HttpProgress::Failed(HttpFailure::Status { code });
            }
            let mut content = 0u32;
            length = 4;
            // SAFETY: `content` and `length` are live locals of the stated size.
            if unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    data.http_request,
                    0x2000_0009,
                    0,
                    &mut content,
                    &mut length,
                    0,
                )
            } == 0
            {
                return HttpProgress::Failed(HttpFailure::ContentLength {
                    error: last_error(),
                });
            }
            if content as usize > REGISTRATION_RESPONSE_CAPACITY {
                return HttpProgress::Failed(HttpFailure::TooLarge { length: content });
            }
            body.fill(0);
            HTTP_REMAINING.store(content, Ordering::Relaxed);
            HTTP_RECEIVED.store(0, Ordering::Relaxed);
            HTTP_STATE.store(6, Ordering::Relaxed);
        }
        if HTTP_STATE.load(Ordering::Relaxed) == 6 {
            let remaining = HTTP_REMAINING.load(Ordering::Relaxed);
            let received = HTTP_RECEIVED.load(Ordering::Relaxed);
            if remaining == 0 {
                return HttpProgress::Complete(received as usize);
            }
            HTTP_STATE.store(5, Ordering::Relaxed);
            let target = body[received as usize..].as_mut_ptr();
            // SAFETY: `target` has at least `remaining` bytes of `body`, which
            // the caller keeps for the whole transfer; `read` is not used.
            if unsafe {
                NetDll_XHttpReadData(
                    XnCaller::DebugMonitor,
                    data.http_request,
                    target,
                    remaining,
                    core::ptr::null_mut(),
                )
            } == 0
            {
                return HttpProgress::Failed(HttpFailure::Read {
                    error: last_error(),
                });
            }
        }
        if HTTP_STATE.load(Ordering::Relaxed) == 7 {
            let failure = match HTTP_FAILURE_KIND.load(Ordering::Relaxed) {
                FAILURE_TRUNCATED => HttpFailure::Truncated {
                    received: HTTP_RECEIVED.load(Ordering::Relaxed),
                    expected: HTTP_REMAINING.load(Ordering::Relaxed),
                },
                _ => HttpFailure::Request {
                    state: HTTP_FAILURE_STATE.load(Ordering::Relaxed),
                    error: Win32Error::new(HTTP_FAILURE_ERROR.load(Ordering::Relaxed)),
                },
            };
            return HttpProgress::Failed(failure);
        }
        HttpProgress::Pending
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
            Published::Registration(registration) => *REGISTRATION.lock() = registration.result(),
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

/// Result of a NULL output pointer.
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();
/// Hardware flag that enables the setting of exports 175 and 176; 0x20
/// marks a hard disk.
const HARDWARE_XCONFIG_QWORD: u32 = 0x10;

/// Apply an exported setting of a waiting caller on the server thread.
fn service_apply_setting(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    setting: &mut ExportedSetting,
) -> u32 {
    let setting = *setting;
    commands::console::apply_exported_setting(&mut server.state, console, setting);
    0
}

/// Exports 43, 118, 120, 122. Off the server thread at passive level the
/// setting is applied before the export returns, as stock does; otherwise
/// the server cannot be reached and the setting is dropped.
fn apply_setting(mut setting: ExportedSetting) -> u32 {
    let _ = super::dispatcher::call_on_server_with(&mut setting, service_apply_setting);
    Hresult::OK.0
}

/// Export 43: NULL clears the name; at most 20 bytes are kept.
extern "C" fn export_set_debug_name(name: u32) -> u32 {
    let mut bytes = [0u8; DEBUG_NAME_CAPACITY - 1];
    let mut length = 0;
    while name != 0 && length < bytes.len() {
        // SAFETY: the caller passes a NUL-terminated string.
        let byte = unsafe { core::ptr::read_volatile((name as usize + length) as *const u8) };
        if byte == 0 {
            break;
        }
        bytes[length] = byte;
        length += 1;
    }
    apply_setting(ExportedSetting::DebugName(DebugName::new(&bytes[..length])))
}
export!(43, export_set_debug_name);

extern "C" fn export_set_dump_mode(mode: u32) -> u32 {
    apply_setting(ExportedSetting::DumpMode(mode))
}
export!(118, export_set_dump_mode);

extern "C" fn export_set_dump_settings(block: u32) -> u32 {
    let mut copy = [0u8; DUMP_SETTINGS_SIZE];
    // SAFETY: the caller passes a block of DUMP_SETTINGS_SIZE bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            block as usize as *const u8,
            copy.as_mut_ptr(),
            DUMP_SETTINGS_SIZE,
        )
    };
    apply_setting(ExportedSetting::DumpSettings(copy))
}
export!(120, export_set_dump_settings);

extern "C" fn export_set_event_defer(mask: u32) -> u32 {
    apply_setting(ExportedSetting::EventDefer(mask))
}
export!(122, export_set_event_defer);
const HARDWARE_HDD: u32 = 0x20;
/// XConfig setting of exports 175 and 176.
const XCONFIG_QWORD: (u16, u16) = (3, 8);

/// Store `value` through the caller's pointer; NULL fails (stock exports
/// 117, 121, 140).
fn store_word(output: u32, value: u32) -> u32 {
    if output == 0 {
        return BAD_PARAMETER.0;
    }
    write_word(output, value);
    Hresult::OK.0
}

/// Export 17: copy the debug name into `buffer` of `*size` bytes.
extern "C" fn export_get_debug_name(buffer: u32, size: u32) -> u32 {
    get_debug_name(buffer, size)
}
export!(17, export_get_debug_name);

/// Export 91 returns its argument (stock returns the copy's destination).
extern "C" fn export_get_system_settings(block: u32) -> u32 {
    service_get_system_settings(block);
    block
}
export!(91, export_get_system_settings);

extern "C" fn export_set_system_settings(block: u32) -> u32 {
    service_set_system_settings(block)
}
export!(92, export_set_system_settings);

/// Export 117: the crash dump mode.
extern "C" fn export_get_dump_mode(output: u32) -> u32 {
    store_word(output, DUMP_MODE.load(Ordering::Acquire))
}
export!(117, export_get_dump_mode);

/// Export 119: copy the crash dump settings block; the pointer is not
/// checked, as in stock.
extern "C" fn export_get_dump_settings(output: u32) -> u32 {
    let block = *DUMP_SETTINGS.lock();
    // SAFETY: the caller passes a block of DUMP_SETTINGS_SIZE bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            block.as_ptr(),
            output as usize as *mut u8,
            DUMP_SETTINGS_SIZE,
        )
    };
    Hresult::OK.0
}
export!(119, export_get_dump_settings);

/// Export 121: the event defer mask.
extern "C" fn export_get_event_defer(output: u32) -> u32 {
    store_word(output, EVENT_DEFER.load(Ordering::Acquire))
}
export!(121, export_get_event_defer);

/// Export 140: whether the console is a test kit (stock 0x91f9f680).
extern "C" fn export_is_test_kit(output: u32) -> u32 {
    let test_kit = hardware_flags().bits() & HARDWARE_NOT_DEBUGGABLE != 0 || test_kit_marked();
    store_word(output, u32::from(test_kit))
}
export!(140, export_is_test_kit);

/// Export 161: `{+0 size (>= 0x20, set to 0x20), +4 base kernel version,
/// +0xc kernel version, +0x14 XDK version, +0x1c flags}`; the whole stated
/// size is cleared first.
extern "C" fn export_get_system_info(block: u32) -> u32 {
    if block == 0 || (read_word(block) as i32) < 0x20 {
        return BAD_PARAMETER.0;
    }
    let size = read_word(block) as usize;
    // SAFETY: the caller's block holds the size it states.
    let bytes = unsafe { core::slice::from_raw_parts_mut(block as usize as *mut u8, size) };
    bytes.fill(0);
    bytes[..4].copy_from_slice(&0x20u32.to_be_bytes());
    let versions = [
        version_words(kernel::base_kernel_version()),
        version_words(kernel_version()),
        commands::console::XDK_VERSION.0,
    ];
    for (index, version) in versions.iter().enumerate() {
        for (part, value) in version.iter().enumerate() {
            let offset = 4 + index * 8 + part * 2;
            bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
    }
    let hardware = hardware_flags().bits();
    let generation = match hardware & 0xf000_0000 {
        generation @ (0 | 0x1000_0000 | 0x2000_0000 | 0x3000_0000 | 0x4000_0000 | 0x5000_0000
        | 0x6000_0000 | 0x8000_0000) => generation,
        _ => 0xf000_0000,
    };
    let mut flags = (hardware & 3) | generation | (hardware & HARDWARE_HDD);
    if hardware & HARDWARE_NOT_DEBUGGABLE != 0 || test_kit_marked() {
        flags |= HARDWARE_NOT_DEBUGGABLE;
    }
    bytes[0x1c..0x20].copy_from_slice(&flags.to_be_bytes());
    Hresult::OK.0
}
export!(161, export_get_system_info);

/// Exports 175 and 176: a failed setting call returns its status with the
/// NT facility bit.
fn xconfig_result(status: u32) -> u32 {
    export_result(NtStatus(status).result()).0
}

/// Export 175: read the 8-byte setting (3, 8) into `output`.
extern "C" fn export_get_xconfig_qword(output: u32) -> u32 {
    if hardware_flags().bits() & HARDWARE_XCONFIG_QWORD == 0 {
        return ErrorCode::UnknownCommand.hresult().0;
    }
    if output == 0 {
        return BAD_PARAMETER.0;
    }
    let mut length = 0u16;
    // SAFETY: the export contract requires `output` to address 8 writable
    // bytes; `length` is a live local.
    xconfig_result(
        unsafe {
            xboxkrnl::ExGetXConfigSetting(
                XCONFIG_QWORD.0,
                XCONFIG_QWORD.1,
                output as usize as *mut u8,
                8,
                &mut length,
            )
        }
        .0,
    )
}
export!(175, export_get_xconfig_qword);

/// Export 176 with the 64-bit value split into its high and low words by
/// [`export_set_xconfig_qword_entry`].
extern "C" fn export_set_xconfig_qword(high: u32, low: u32) -> u32 {
    if hardware_flags().bits() & HARDWARE_XCONFIG_QWORD == 0 {
        return ErrorCode::UnknownCommand.hresult().0;
    }
    let value = (u64::from(high) << 32 | u64::from(low)).to_be_bytes();
    // SAFETY: `value` is a live 8-byte local.
    xconfig_result(
        unsafe {
            xboxkrnl::ExSetXConfigSetting(XCONFIG_QWORD.0, XCONFIG_QWORD.1, value.as_ptr(), 8)
        }
        .0,
    )
}

/// The importer passes the 64-bit value in r3: copy it to r4, move its high
/// word down (`rldicl 3, 3, 32, 32`, encoded directly), and enter through
/// the bridge.
#[unsafe(naked)]
unsafe extern "C" fn export_set_xconfig_qword_entry() {
    core::arch::naked_asm!(
        "mr 4, 3",
        ".long 0x78630022",
        "lis 12, {function}@ha",
        "addi 12, 12, {function}@l",
        "b {bridge}",
        function = sym export_set_xconfig_qword,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(176, export_set_xconfig_qword_entry);

/// Export 194: `(transaction out, buffer, size in/out) -> HRESULT`; the
/// response of the last accepted registration.
extern "C" fn export_get_registration_response(transaction: u32, buffer: u32, size: u32) -> u32 {
    let capacity = if size == 0 {
        None
    } else {
        Some(read_word(size))
    };
    // A buffer needs a size pointer and a nonzero size needs a buffer.
    let rejected = match capacity {
        Some(capacity) => capacity != 0 && buffer == 0,
        None => buffer != 0,
    };
    if rejected {
        return BAD_PARAMETER.0;
    }
    let registration = *REGISTRATION.lock();
    let output = capacity.map(|capacity| {
        if buffer == 0 {
            &mut [][..]
        } else {
            // SAFETY: the caller's buffer holds `*size` bytes.
            unsafe {
                core::slice::from_raw_parts_mut(buffer as usize as *mut u8, capacity as usize)
            }
        }
    });
    let response = registration.export_response(output);
    if transaction != 0 {
        // SAFETY: the caller passes a 64-bit output; stock does not require
        // 8-byte alignment.
        unsafe {
            core::ptr::write_unaligned(transaction as usize as *mut u64, response.transaction)
        };
    }
    if size != 0 {
        write_word(size, response.length);
    }
    export_result(response.result).0
}
export!(194, export_get_registration_response);

/// Export 213: `(size out) -> HRESULT`; the debug memory size, 0 when the
/// statistics query fails.
extern "C" fn export_get_debug_memory_size(output: u32) -> u32 {
    store_word(
        output,
        memory_statistics().map_or(0, |statistics| statistics.debug_memory_size()),
    )
}
export!(213, export_get_debug_memory_size);

/// Export 214: `(configuration out) -> HRESULT`; the `consolemem` value.
extern "C" fn export_get_console_memory(output: u32) -> u32 {
    store_word(
        output,
        ConsoleMemory::of(kit_features(), memory_statistics).value(),
    )
}
export!(214, export_get_console_memory);

/// Export 220: `(features out) -> HRESULT`; the `consolefeatures` bits.
extern "C" fn export_get_console_features(output: u32) -> u32 {
    store_word(output, kit_features().mask())
}
export!(220, export_get_console_features);

/// The debug name the server published; readable on any thread.
pub(crate) fn debug_name() -> DebugName {
    *DEBUG_NAME.lock()
}

/// Whether startup marked the console as a test kit.
pub(crate) fn test_kit_marked() -> bool {
    TEST_KIT.load(Ordering::Acquire)
}

fn read_word(address: u32) -> u32 {
    // SAFETY: callers pass the address of a caller structure.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_word(address: u32, value: u32) {
    // SAFETY: callers pass the address of a caller structure.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

/// Control code 0x1e (stock export 92): store the caller's settings block
/// `{+0 size, +4 flags, +8 video standard}` and write the settings file.
pub(crate) fn service_set_system_settings(argument: u32) -> u32 {
    let length = (read_word(argument) as usize).min(SYSTEM_SETTINGS_SIZE);
    // SAFETY: the caller's block holds at least the size it states.
    let block = unsafe { core::slice::from_raw_parts(argument as usize as *const u8, length) };
    SYSTEM_SETTINGS.lock().store(block);
    super::dispatcher::request_settings_write();
    0
}

/// Control code 0x1f (stock export 91): copy the settings block into the
/// caller's, at most the size it states; its size field is kept.
pub(crate) fn service_get_system_settings(argument: u32) -> u32 {
    let size = read_word(argument);
    let length = (size as usize).min(SYSTEM_SETTINGS_SIZE);
    let settings = *SYSTEM_SETTINGS.lock();
    // SAFETY: the caller's block holds at least the size it states.
    unsafe {
        core::ptr::copy_nonoverlapping(settings.0.as_ptr(), argument as usize as *mut u8, length)
    };
    write_word(argument, size);
    0
}

/// Control code 0x33 (stock export 17): `{+0 buffer, +4 size pointer}`.
pub(crate) fn service_get_debug_name(argument: u32) -> u32 {
    get_debug_name(read_word(argument), read_word(argument + 4))
}

/// Stock export 17: copy the debug name into `buffer` of `*size` bytes.
fn get_debug_name(buffer: u32, size: u32) -> u32 {
    if buffer == 0 || size == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    // SAFETY: the caller's buffer holds `*size` bytes.
    let output = unsafe {
        core::slice::from_raw_parts_mut(buffer as usize as *mut u8, read_word(size) as usize)
    };
    match commands::console::copy_debug_name(&debug_name(), output) {
        Ok(()) => Hresult::OK.0,
        Err(error) => Hresult::from(error).0,
    }
}

/// Request state shared with the status callback (stock 0x91f9f638 states
/// 1 to 7), the body bytes still expected and received, and the failure
/// the callback recorded.
static HTTP_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_REMAINING: AtomicU32 = AtomicU32::new(0);
static HTTP_RECEIVED: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_KIND: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_ERROR: AtomicU32 = AtomicU32::new(0);
const FAILURE_TRUNCATED: u32 = 2;
const FAILURE_REQUEST: u32 = 1;

bridged!(http_status_entry, http_status);

/// Stock 0x91f2ffa0, called by `NetDll_XHttpDoWork` and the request functions
/// through [`http_status_entry`].
extern "C" fn http_status(
    _handle: u32,
    _context: u32,
    status: u32,
    information: *const u32,
    length: u32,
) -> u32 {
    match status {
        0x0002_0000 => HTTP_STATE.store(4, Ordering::Relaxed),
        0x0008_0000 => {
            if length == 0 {
                HTTP_FAILURE_KIND.store(FAILURE_TRUNCATED, Ordering::Relaxed);
                HTTP_STATE.store(7, Ordering::Relaxed);
            } else {
                HTTP_REMAINING.fetch_sub(length, Ordering::Relaxed);
                HTTP_RECEIVED.fetch_add(length, Ordering::Relaxed);
                HTTP_STATE.store(6, Ordering::Relaxed);
            }
        }
        0x0020_0000 => {
            HTTP_FAILURE_KIND.store(FAILURE_REQUEST, Ordering::Relaxed);
            HTTP_FAILURE_STATE.store(HTTP_STATE.load(Ordering::Relaxed), Ordering::Relaxed);
            // SAFETY: the request error information is {result, error}.
            let error = if information.is_null() {
                0
            } else {
                unsafe { core::ptr::read_volatile(information.add(1)) }
            };
            HTTP_FAILURE_ERROR.store(error, Ordering::Relaxed);
            HTTP_STATE.store(7, Ordering::Relaxed);
        }
        0x0040_0000 => HTTP_STATE.store(2, Ordering::Relaxed),
        _ => {}
    }
    0
}

impl Data {
    /// Stock 0x91f30480: close the request, connection and session, then
    /// shut the HTTP client down.
    fn close_http(&mut self) {
        for handle in [
            &mut self.http_request,
            &mut self.http_connection,
            &mut self.http_session,
        ] {
            if *handle != 0 {
                // SAFETY: nonzero handles were opened by `http_begin` and are
                // cleared after closing.
                unsafe { NetDll_XHttpCloseHandle(XnCaller::DebugMonitor, *handle) };
                *handle = 0;
            }
        }
        if core::mem::take(&mut self.http_started) {
            // SAFETY: matches the successful startup recorded in `http_started`.
            unsafe { NetDll_XHttpShutdown(XnCaller::DebugMonitor) };
        }
        HTTP_STATE.store(0, Ordering::Relaxed);
    }
}
