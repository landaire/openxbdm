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
use openxbdm_server::commands::console::BufferTooSmall;
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
use openxbdm_server::commands::hardware::SystemApp;
use openxbdm_server::commands::hardware::SystemMessage;
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
use xbox360_sys::value_enum;
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
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::SmcCommand;
use xbox360_sys::xboxkrnl::SmcI2cDevice;
use xbox360_sys::xboxkrnl::SmcMessage;
use xbox360_sys::xboxkrnl::XeKeysGetConsoleID;

use super::Console;
use crate::exports::bridged;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::version_words;
use crate::net;
use crate::net::XamNetwork;

/// Kernel export that atomically modifies a configuration dword.
const CONFIG_MODIFY_ORDINAL: Ordinal = Ordinal::new(700).unwrap();
/// System UI library export that switches a feature.
const FEATURE_SWITCH_ORDINAL: Ordinal = Ordinal::new(515).unwrap();
/// System message service of the network configuration and its message.
const NETWORK_APP: SystemApp = SystemApp(0xef);
const NETWORK_RA_MESSAGE: SystemMessage = SystemMessage(0x00a0_0004);
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
            let mut message = smc_i2c_message(address, SMC_I2C_CHUNK);
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
                http::SESSION_ASYNC,
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
                http::CONNECT_FLAGS,
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
        let mut value = http::MAX_REDIRECTS;
        // SAFETY: `http_status_entry` has the status callback signature and
        // `value` is a live 4-byte option buffer.
        unsafe {
            NetDll_XHttpSetStatusCallback(
                XnCaller::DebugMonitor,
                data.http_request,
                http_status_entry as *const () as usize as u32,
                http::ALL_NOTIFICATIONS,
                0,
            );
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                data.http_request,
                http::OPTION_MAX_REDIRECTS,
                &mut value,
                size_of::<u32>() as u32,
            );
            value = http::DISABLE_KEEP_ALIVE;
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                data.http_request,
                http::OPTION_DISABLE_FEATURE,
                &mut value,
                size_of::<u32>() as u32,
            );
        }
        HttpState::Sending.store();
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
        if HttpState::load() == HttpState::Sent as u32 {
            HttpState::Receiving.store();
            // SAFETY: the request handle was opened by `http_begin`.
            if unsafe { NetDll_XHttpReceiveResponse(XnCaller::DebugMonitor, data.http_request, 0) }
                == 0
            {
                return HttpProgress::Failed(HttpFailure::Receive {
                    error: last_error(),
                });
            }
        }
        if HttpState::load() == HttpState::HeadersAvailable as u32 {
            let mut code = 0u32;
            let mut length = size_of::<u32>() as u32;
            // SAFETY: `code` and `length` are live locals of the stated size.
            if unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    data.http_request,
                    http::QUERY_STATUS_CODE,
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
            if code != http::STATUS_OK {
                return HttpProgress::Failed(HttpFailure::Status { code });
            }
            let mut content = 0u32;
            length = size_of::<u32>() as u32;
            // SAFETY: `content` and `length` are live locals of the stated size.
            if unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    data.http_request,
                    http::QUERY_CONTENT_LENGTH,
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
            HttpState::ReadComplete.store();
        }
        if HttpState::load() == HttpState::ReadComplete as u32 {
            let remaining = HTTP_REMAINING.load(Ordering::Relaxed);
            let received = HTTP_RECEIVED.load(Ordering::Relaxed);
            if remaining == 0 {
                return HttpProgress::Complete(received as usize);
            }
            HttpState::Reading.store();
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
        if HttpState::load() == HttpState::Failed as u32 {
            let kind = HttpFailureKind::from_raw(HTTP_FAILURE_KIND.load(Ordering::Relaxed));
            let failure = match kind {
                Some(HttpFailureKind::Truncated) => HttpFailure::Truncated {
                    received: HTTP_RECEIVED.load(Ordering::Relaxed),
                    expected: HTTP_REMAINING.load(Ordering::Relaxed),
                },
                Some(HttpFailureKind::Request) | None => HttpFailure::Request {
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
/// XConfig setting of exports 175 and 176.
const XCONFIG_QWORD: ConfigSetting = ConfigSetting {
    category: 3,
    index: 8,
};

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
fn apply_setting(mut setting: ExportedSetting) -> Hresult {
    let _ = super::dispatcher::call_on_server_with(&mut setting, service_apply_setting);
    Hresult::OK
}

/// Export 43: NULL clears the name; at most 20 bytes are kept.
extern "C" fn export_set_debug_name(name: *const u8) -> Hresult {
    let mut bytes = [0u8; DEBUG_NAME_CAPACITY - 1];
    let mut length = 0;
    while !name.is_null() && length < bytes.len() {
        // SAFETY: export 43 takes NULL or a NUL-terminated string, and the
        // loop stops at its NUL.
        let byte = unsafe { name.add(length).read() };
        if byte == 0 {
            break;
        }
        bytes[length] = byte;
        length += 1;
    }
    apply_setting(ExportedSetting::DebugName(DebugName::new(&bytes[..length])))
}
export!(43, export_set_debug_name);

extern "C" fn export_set_dump_mode(mode: u32) -> Hresult {
    apply_setting(ExportedSetting::DumpMode(mode))
}
export!(118, export_set_dump_mode);

extern "C" fn export_set_dump_settings(block: *const [u8; DUMP_SETTINGS_SIZE]) -> Hresult {
    // SAFETY: export 120 takes a readable block of DUMP_SETTINGS_SIZE bytes.
    let copy = unsafe { block.read() };
    apply_setting(ExportedSetting::DumpSettings(copy))
}
export!(120, export_set_dump_settings);

extern "C" fn export_set_event_defer(mask: u32) -> Hresult {
    apply_setting(ExportedSetting::EventDefer(mask))
}
export!(122, export_set_event_defer);

/// Store `value` through the caller's output; NULL fails (stock exports
/// 117, 121, 140, 213, 214, 220).
///
/// # Safety
///
/// `output` is NULL or a writable dword at any alignment.
unsafe fn write_output(output: *mut u32, value: u32) -> Hresult {
    if output.is_null() {
        return BAD_PARAMETER;
    }
    // SAFETY: per the contract of this fn.
    unsafe { output.write_unaligned(value) };
    Hresult::OK
}

/// Export 17: copy the debug name into `buffer` of `*size` bytes.
extern "C" fn export_get_debug_name(buffer: *mut u8, size: *const u32) -> Hresult {
    // SAFETY: export 17 takes NULL or a readable size, and NULL or a buffer
    // of that many writable bytes.
    let output = unsafe { debug_name_output(buffer, size) };
    export_result(get_debug_name(output))
}
export!(17, export_get_debug_name);

/// Export 91 returns its argument (stock returns the copy's destination).
extern "C" fn export_get_system_settings(block: u32) -> u32 {
    // SAFETY: export 91 takes the caller's settings block, with the
    // contract of control code 0x1f.
    unsafe { service_get_system_settings(block) };
    block
}
export!(91, export_get_system_settings);

extern "C" fn export_set_system_settings(block: u32) -> u32 {
    // SAFETY: export 92 takes the caller's settings block, with the
    // contract of control code 0x1e.
    unsafe { service_set_system_settings(block) }
}
export!(92, export_set_system_settings);

/// Export 117: the crash dump mode.
extern "C" fn export_get_dump_mode(output: *mut u32) -> Hresult {
    // SAFETY: export 117 takes NULL or a writable dword, which stock does
    // not align.
    unsafe { write_output(output, DUMP_MODE.load(Ordering::Acquire)) }
}
export!(117, export_get_dump_mode);

/// Export 119: copy the crash dump settings block; the pointer is not
/// checked, as in stock.
extern "C" fn export_get_dump_settings(output: *mut [u8; DUMP_SETTINGS_SIZE]) -> Hresult {
    let block = *DUMP_SETTINGS.lock();
    // SAFETY: export 119 takes a writable block of DUMP_SETTINGS_SIZE bytes.
    unsafe { output.write(block) };
    Hresult::OK
}
export!(119, export_get_dump_settings);

/// Export 121: the event defer mask.
extern "C" fn export_get_event_defer(output: *mut u32) -> Hresult {
    // SAFETY: as export 117.
    unsafe { write_output(output, EVENT_DEFER.load(Ordering::Acquire)) }
}
export!(121, export_get_event_defer);

/// Export 140: whether the console is a test kit (stock 0x91f9f680).
extern "C" fn export_is_test_kit(output: *mut u32) -> Hresult {
    let test_kit = hardware_flags().contains(HardwareFlags::TEST_KIT) || test_kit_marked();
    // SAFETY: as export 117.
    unsafe { write_output(output, u32::from(test_kit)) }
}
export!(140, export_is_test_kit);

/// Block of export 161. The caller states its size, at least this
/// structure's, and the export clears the whole stated size first.
#[repr(C)]
struct SystemInfo {
    size: u32,
    base_kernel: [u16; 4],
    kernel: [u16; 4],
    xdk: [u16; 4],
    flags: HardwareFlags,
}

const _: () = {
    assert!(core::mem::offset_of!(SystemInfo, base_kernel) == 0x4);
    assert!(core::mem::offset_of!(SystemInfo, kernel) == 0xc);
    assert!(core::mem::offset_of!(SystemInfo, xdk) == 0x14);
    assert!(core::mem::offset_of!(SystemInfo, flags) == 0x1c);
    assert!(size_of::<SystemInfo>() == 0x20);
};

/// The flags word of export 161: the unnamed low bits, the generation with
/// unknown generations as 0xf, the hard disk flag, and the test kit flag.
fn system_info_flags(hardware: HardwareFlags) -> HardwareFlags {
    const LOW_BITS: u32 = 0x3;
    const GENERATION_SHIFT: u32 = 28;
    const UNKNOWN_GENERATION: u8 = 0xf;
    let generation = match hardware.generation().get() {
        generation @ (0..=6 | 8) => generation,
        _ => UNKNOWN_GENERATION,
    };
    let mut flags = HardwareFlags::from_bits_retain(
        hardware.bits() & LOW_BITS | u32::from(generation) << GENERATION_SHIFT,
    );
    if hardware.contains(HardwareFlags::HARD_DISK) {
        flags.insert(HardwareFlags::HARD_DISK);
    }
    if hardware.contains(HardwareFlags::TEST_KIT) || test_kit_marked() {
        flags.insert(HardwareFlags::TEST_KIT);
    }
    flags
}

/// Export 161: fill the caller's [`SystemInfo`].
extern "C" fn export_get_system_info(block: *mut SystemInfo) -> Hresult {
    if block.is_null() {
        return BAD_PARAMETER;
    }
    // SAFETY: export 161 takes NULL or a block whose first word states its
    // size, and which holds that many writable bytes; stock does not align
    // it.
    let size = unsafe { block.cast::<u32>().read_unaligned() };
    if (size as i32) < size_of::<SystemInfo>() as i32 {
        return BAD_PARAMETER;
    }
    // SAFETY: as above; `size` covers a whole `SystemInfo`.
    unsafe {
        core::ptr::write_bytes(block.cast::<u8>(), 0, size as usize);
        (&raw mut (*block).size).write_unaligned(size_of::<SystemInfo>() as u32);
        (&raw mut (*block).base_kernel)
            .write_unaligned(version_words(kernel::base_kernel_version()));
        (&raw mut (*block).kernel).write_unaligned(version_words(kernel_version()));
        (&raw mut (*block).xdk).write_unaligned(commands::console::XDK_VERSION.0);
        (&raw mut (*block).flags).write_unaligned(system_info_flags(hardware_flags()));
    }
    Hresult::OK
}
export!(161, export_get_system_info);

/// Exports 175 and 176: a failed setting call returns its status with the
/// NT facility bit.
fn xconfig_result(status: NtStatus) -> Hresult {
    export_result(status.result())
}

/// Export 175: read the 8-byte setting [`XCONFIG_QWORD`] into `output`.
extern "C" fn export_get_xconfig_qword(output: Option<&mut [u8; 8]>) -> Hresult {
    if !hardware_flags().contains(HardwareFlags::AUTO_PROFILE) {
        return ErrorCode::UnknownCommand.hresult();
    }
    let Some(output) = output else {
        return BAD_PARAMETER;
    };
    let mut length = 0u16;
    // SAFETY: `output` and `length` are live for the call.
    xconfig_result(unsafe {
        xboxkrnl::ExGetXConfigSetting(
            XCONFIG_QWORD.category,
            XCONFIG_QWORD.index,
            output.as_mut_ptr(),
            output.len() as u16,
            &mut length,
        )
    })
}
export!(175, export_get_xconfig_qword);

/// Export 176 with the 64-bit value split into its high and low words by
/// [`export_set_xconfig_qword_entry`].
extern "C" fn export_set_xconfig_qword(high: u32, low: u32) -> Hresult {
    if !hardware_flags().contains(HardwareFlags::AUTO_PROFILE) {
        return ErrorCode::UnknownCommand.hresult();
    }
    let value = (u64::from(high) << 32 | u64::from(low)).to_be_bytes();
    // SAFETY: `value` is a live 8-byte local.
    xconfig_result(unsafe {
        xboxkrnl::ExSetXConfigSetting(
            XCONFIG_QWORD.category,
            XCONFIG_QWORD.index,
            value.as_ptr(),
            value.len() as u16,
        )
    })
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
extern "C" fn export_get_registration_response(
    transaction: *mut u64,
    buffer: *mut u8,
    size: *mut u32,
) -> Hresult {
    // SAFETY: export 194 takes NULL or a size dword, which stock does not
    // align.
    let capacity = (!size.is_null()).then(|| unsafe { size.read_unaligned() });
    // A buffer needs a size pointer and a nonzero size needs a buffer.
    let rejected = match capacity {
        Some(capacity) => capacity != 0 && buffer.is_null(),
        None => !buffer.is_null(),
    };
    if rejected {
        return BAD_PARAMETER;
    }
    let registration = *REGISTRATION.lock();
    let output = capacity.map(|capacity| {
        if buffer.is_null() {
            &mut [][..]
        } else {
            // SAFETY: export 194 takes a buffer of `*size` writable bytes.
            unsafe { core::slice::from_raw_parts_mut(buffer, capacity as usize) }
        }
    });
    let response = registration.export_response(output);
    if !transaction.is_null() {
        // SAFETY: export 194 takes NULL or a writable 64-bit output; stock
        // does not require 8-byte alignment.
        unsafe { transaction.write_unaligned(response.transaction) };
    }
    if !size.is_null() {
        // SAFETY: as above.
        unsafe { size.write_unaligned(response.length) };
    }
    export_result(response.result)
}
export!(194, export_get_registration_response);

/// Export 213: `(size out) -> HRESULT`; the debug memory size, 0 when the
/// statistics query fails.
extern "C" fn export_get_debug_memory_size(output: *mut u32) -> Hresult {
    let size = memory_statistics().map_or(0, |statistics| statistics.debug_memory_size());
    // SAFETY: as export 117.
    unsafe { write_output(output, size) }
}
export!(213, export_get_debug_memory_size);

/// Export 214: `(configuration out) -> HRESULT`; the `consolemem` value.
extern "C" fn export_get_console_memory(output: *mut u32) -> Hresult {
    let memory = ConsoleMemory::of(kit_features(), memory_statistics).value();
    // SAFETY: as export 117.
    unsafe { write_output(output, memory) }
}
export!(214, export_get_console_memory);

/// Export 220: `(features out) -> HRESULT`; the `consolefeatures` bits.
extern "C" fn export_get_console_features(output: *mut u32) -> Hresult {
    // SAFETY: as export 117.
    unsafe { write_output(output, kit_features().mask()) }
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

/// Size field that leads a caller's settings block.
const SETTINGS_SIZE_FIELD: usize = size_of::<u32>();

/// Control code 0x1e (stock export 92): store the caller's settings block
/// `{+0 size, +4 flags, +8 video standard}` and write the settings file.
///
/// # Safety
///
/// `argument` must be the address of an aligned block whose first word
/// states its size and which holds at least that many readable bytes,
/// unchanged for the call.
pub(crate) unsafe fn service_set_system_settings(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let block = unsafe {
        let size = *kernel::object_at::<u32>(argument);
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u8>(argument as usize),
            (size as usize).min(SYSTEM_SETTINGS_SIZE),
        )
    };
    SYSTEM_SETTINGS.lock().store(block);
    super::dispatcher::request_settings_write();
    0
}

/// Control code 0x1f (stock export 91): copy the settings block into the
/// caller's, at most the size it states; its size field is kept.
///
/// # Safety
///
/// `argument` must be the address of an aligned block whose first word
/// states its size and which holds at least that many writable bytes, not
/// otherwise accessed for the call.
pub(crate) unsafe fn service_get_system_settings(argument: u32) -> u32 {
    let block = core::ptr::with_exposed_provenance_mut::<u8>(argument as usize);
    // SAFETY: the caller's contract.
    let size = unsafe { *kernel::object_at::<u32>(argument) };
    let length = (size as usize).min(SYSTEM_SETTINGS_SIZE);
    let settings = *SYSTEM_SETTINGS.lock();
    if length > SETTINGS_SIZE_FIELD {
        // SAFETY: the caller's contract; the size field is not part of the
        // slice.
        let output = unsafe {
            core::slice::from_raw_parts_mut(
                block.add(SETTINGS_SIZE_FIELD),
                length - SETTINGS_SIZE_FIELD,
            )
        };
        output.copy_from_slice(&settings.0[SETTINGS_SIZE_FIELD..length]);
    }
    0
}

/// Record of control code 0x33: the arguments of export 17.
#[repr(C)]
struct DebugNameRequest {
    buffer: u32,
    size: u32,
}

/// Control code 0x33 (stock export 17).
///
/// # Safety
///
/// `argument` must be the address of a readable `DebugNameRequest` that
/// holds export 17's arguments, with that export's contract.
pub(crate) unsafe fn service_get_debug_name(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at::<DebugNameRequest>(argument) };
    // SAFETY: the caller's contract.
    let output = unsafe {
        debug_name_output(
            core::ptr::with_exposed_provenance_mut(request.buffer as usize),
            core::ptr::with_exposed_provenance(request.size as usize),
        )
    };
    export_result(get_debug_name(output)).0
}

/// The output of stock export 17; `None` if either pointer is NULL.
///
/// # Safety
///
/// `size` is NULL or a readable dword at any alignment, and `buffer` is
/// NULL or holds `*size` writable bytes that stay unaliased for `'a`.
unsafe fn debug_name_output<'a>(buffer: *mut u8, size: *const u32) -> Option<&'a mut [u8]> {
    if buffer.is_null() || size.is_null() {
        return None;
    }
    // SAFETY: per the contract of this fn.
    Some(unsafe { core::slice::from_raw_parts_mut(buffer, size.read_unaligned() as usize) })
}

/// Why stock export 17 failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugNameError {
    /// The buffer or size pointer is NULL.
    MissingBuffer,
    BufferTooSmall,
}

impl core::fmt::Display for DebugNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingBuffer => "missing buffer",
            Self::BufferTooSmall => "buffer too small",
        })
    }
}

impl core::error::Error for DebugNameError {}

impl From<BufferTooSmall> for DebugNameError {
    fn from(_: BufferTooSmall) -> Self {
        Self::BufferTooSmall
    }
}

impl From<DebugNameError> for Hresult {
    fn from(error: DebugNameError) -> Self {
        match error {
            DebugNameError::MissingBuffer => Hresult::INVALID_ARGUMENT,
            DebugNameError::BufferTooSmall => BufferTooSmall.into(),
        }
    }
}

/// Stock export 17: copy the debug name into `output`.
fn get_debug_name(output: Option<&mut [u8]>) -> Result<(), DebugNameError> {
    let output = output.ok_or(DebugNameError::MissingBuffer)?;
    commands::console::copy_debug_name(&debug_name(), output)?;
    Ok(())
}

/// Request state shared with the status callback (stock 0x91f9f638).
#[repr(u32)]
#[derive(Clone, Copy)]
enum HttpState {
    Idle = 0,
    Sending = 1,
    Sent = 2,
    Receiving = 3,
    HeadersAvailable = 4,
    Reading = 5,
    ReadComplete = 6,
    Failed = 7,
}

impl HttpState {
    /// The raw state; the failure record reports it as is.
    fn load() -> u32 {
        HTTP_STATE.load(Ordering::Relaxed)
    }

    fn store(self) {
        HTTP_STATE.store(self as u32, Ordering::Relaxed);
    }
}

value_enum! {
    /// Failure the status callback recorded.
    pub enum HttpFailureKind: u32 {
        Request = 1,
        Truncated = 2,
    }
}

/// XHTTP values, which follow WinHTTP.
mod http {
    /// `XHttpOpen` flag of an asynchronous session.
    pub const SESSION_ASYNC: u32 = 0x1000_0000;
    /// `XHttpConnect` flags of the registration connection.
    pub const CONNECT_FLAGS: u32 = 1;
    /// Status callback notification mask: every notification.
    pub const ALL_NOTIFICATIONS: u32 = u32::MAX;
    pub const OPTION_MAX_REDIRECTS: u32 = 0x59;
    pub const MAX_REDIRECTS: u32 = 3;
    pub const OPTION_DISABLE_FEATURE: u32 = 0x3f;
    pub const DISABLE_KEEP_ALIVE: u32 = 8;
    /// Header queries with the number flag.
    pub const QUERY_STATUS_CODE: u32 = 0x2000_fffe;
    pub const QUERY_CONTENT_LENGTH: u32 = 0x2000_0009;
    pub const STATUS_OK: u32 = 200;
    /// Status callback notifications.
    pub const HEADERS_AVAILABLE: u32 = 0x0002_0000;
    pub const READ_COMPLETE: u32 = 0x0008_0000;
    pub const REQUEST_ERROR: u32 = 0x0020_0000;
    pub const SEND_REQUEST_COMPLETE: u32 = 0x0040_0000;
}

/// Raw [`HttpState`], the body bytes still expected and received, and the
/// failure the callback recorded: a raw [`HttpFailureKind`], the state it
/// failed in, and its Win32 error.
static HTTP_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_REMAINING: AtomicU32 = AtomicU32::new(0);
static HTTP_RECEIVED: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_KIND: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_ERROR: AtomicU32 = AtomicU32::new(0);

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
        http::HEADERS_AVAILABLE => HttpState::HeadersAvailable.store(),
        http::READ_COMPLETE => {
            if length == 0 {
                HTTP_FAILURE_KIND.store(HttpFailureKind::Truncated.raw(), Ordering::Relaxed);
                HttpState::Failed.store();
            } else {
                HTTP_REMAINING.fetch_sub(length, Ordering::Relaxed);
                HTTP_RECEIVED.fetch_add(length, Ordering::Relaxed);
                HttpState::ReadComplete.store();
            }
        }
        http::REQUEST_ERROR => {
            HTTP_FAILURE_KIND.store(HttpFailureKind::Request.raw(), Ordering::Relaxed);
            HTTP_FAILURE_STATE.store(HttpState::load(), Ordering::Relaxed);
            let error = if information.is_null() {
                0
            } else {
                // SAFETY: the request error information is {result, error}.
                unsafe { information.add(1).read() }
            };
            HTTP_FAILURE_ERROR.store(error, Ordering::Relaxed);
            HttpState::Failed.store();
        }
        http::SEND_REQUEST_COMPLETE => HttpState::Sent.store(),
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
        HttpState::Idle.store();
    }
}
