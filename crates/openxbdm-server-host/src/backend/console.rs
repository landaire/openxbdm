//! Simulated console identity and configuration.

use std::collections::BTreeMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::console;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::ConsoleId;
use openxbdm_server::commands::console::HttpFailure;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::HttpStartFailure;
use openxbdm_server::commands::console::KitFeatures;
use openxbdm_server::commands::console::MemoryStatistics;
use openxbdm_server::commands::console::NETWORK_ADDRESS_SIZE;
use openxbdm_server::commands::console::NetworkAddress;
use openxbdm_server::commands::console::NetworkRaRecord;
use openxbdm_server::commands::console::NetworkRaRequest;
use openxbdm_server::commands::console::Published;
use openxbdm_server::commands::console::REGISTRATION_RESPONSE_CAPACITY;
use openxbdm_server::commands::console::REGISTRATION_USER_AGENT;
use openxbdm_server::commands::console::SETTINGS_BLOCK_SIZE;
use openxbdm_server::commands::console::STATUS_PROCEDURE_NOT_FOUND;
use openxbdm_server::commands::console::SystemInformation;
use openxbdm_server::commands::console::SystemSettings;
use openxbdm_server::commands::console::Version;
use openxbdm_server::commands::console::XamStatus;

use super::MockBackend;

/// Simulated console configuration settings.
#[derive(Debug)]
pub struct XConfig {
    /// Stored values. A setting never written reads as zero bytes of the
    /// requested length, as the fixed-layout settings of a new console do.
    pub settings: BTreeMap<ConfigSetting, Vec<u8>>,
    /// Status returned by every read, write, or modify of a setting.
    pub failures: BTreeMap<ConfigSetting, NtStatus>,
    /// Whether the kernel provides the modify export (ordinal 700).
    pub modify_export: bool,
}

impl Default for XConfig {
    fn default() -> Self {
        Self {
            settings: BTreeMap::new(),
            failures: BTreeMap::new(),
            modify_export: true,
        }
    }
}

impl XConfig {
    /// The stored value of a setting, if written.
    pub fn value(&self, category: u16, index: u16) -> Option<&[u8]> {
        self.settings
            .get(&ConfigSetting::new(category, index))
            .map(Vec::as_slice)
    }

    /// The first four stored bytes of a setting as a big-endian dword; zero
    /// if never written.
    pub fn dword(&self, category: u16, index: u16) -> u32 {
        let mut bytes = [0u8; 4];
        if let Some(value) = self.value(category, index) {
            let length = value.len().min(4);
            bytes[..length].copy_from_slice(&value[..length]);
        }
        u32::from_be_bytes(bytes)
    }

    fn check(&self, setting: ConfigSetting) -> Result<(), NtStatus> {
        match self.failures.get(&setting) {
            Some(&status) => Err(status),
            None => Ok(()),
        }
    }
}

/// Simulated system network service (data-center configuration).
#[derive(Debug, Default)]
pub struct NetworkRaService {
    pub record: NetworkRaRecord,
    /// Status of every request while set.
    pub failure: Option<XamStatus>,
    pub resets: u32,
}

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub features: KitFeatures,
    pub xconfig: XConfig,
    /// SMC I2C settings block.
    pub settings_block: [u8; SETTINGS_BLOCK_SIZE],
    /// Every I2C read and write fails while set.
    pub i2c_failure: bool,
    pub memory_statistics: Option<MemoryStatistics>,
    pub system_information: SystemInformation,
    pub console_id: Result<ConsoleId, NtStatus>,
    pub debug_address: NetworkAddress,
    pub title_address: NetworkAddress,
    /// Times the inactivity configuration was applied.
    pub inactivity_updates: u32,
    pub network_ra: NetworkRaService,
    /// Calls of the system UI feature switch; `None` when the export is absent.
    pub feature_calls: Option<Vec<(u32, u32)>>,
    /// Status of loading the network file system client.
    pub network_client_status: NtStatus,
    /// System software version reported to the registration task.
    pub system_version: u32,
    /// Origin of the millisecond tick.
    pub boot: Instant,
    pub http: HttpClient,
    /// Server state readable by other threads.
    pub published: PublishedState,
    pub system_settings: SystemSettings,
    /// Startup found a test kit without the hardware flag; the simulated
    /// hardware flags do not change.
    pub marked_test_kit: bool,
    /// Thread object the trace texts name: the simulated server thread.
    pub current_thread: u32,
}

/// Server state the console publishes to other threads.
#[derive(Debug)]
pub struct PublishedState {
    pub name: Vec<u8>,
    pub dump_mode: u32,
    /// Export 119 block.
    pub dump_settings: Vec<u8>,
    pub event_defer: u32,
    pub trace_mask: u32,
    /// Export 194 view of the lab server registration.
    pub registration: console::RegistrationResult,
}

impl Default for PublishedState {
    /// The server's initial state.
    fn default() -> Self {
        let state = console::State::new();
        Self {
            name: Vec::new(),
            dump_mode: state.dump_mode.raw(),
            dump_settings: state.dump_settings.to_block().to_vec(),
            event_defer: state.event_defer.0,
            trace_mask: state.trace_mask.0,
            registration: state.http_registration.result(),
        }
    }
}

/// Simulated HTTP client of the registration task: an HTTP/1.1 exchange
/// over TCP on a worker thread, so the server polls it like the console's
/// asynchronous client. The request carries the user agent and the host;
/// the further headers of the console's HTTP stack are not known.
#[derive(Debug, Default)]
pub struct HttpClient {
    /// Result of the request in progress, delivered by its worker.
    pending: Option<Receiver<Result<Vec<u8>, HttpFailure>>>,
    /// Times the client was released.
    pub closes: u32,
}

/// Header lookup error of the console HTTP stack (header not found).
const HTTP_HEADER_NOT_FOUND: u32 = 12150;
/// Kernel address of the simulated server thread object.
pub const SERVER_THREAD: u32 = 0x8007_4a00;
/// Port of a request without one.
const HTTP_DEFAULT_PORT: u16 = 80;
/// Limit on each socket wait of a request.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

fn os_error(error: &io::Error) -> u32 {
    error.raw_os_error().map_or(0, |code| code as u32)
}

impl HttpClient {
    fn exchange(server: &str, port: u16, path: &[u8]) -> Result<Vec<u8>, HttpFailure> {
        let request_error = |state: u32, error: &io::Error| HttpFailure::Request {
            state,
            error: os_error(error),
        };
        let effective_port = if port == 0 { HTTP_DEFAULT_PORT } else { port };
        let mut stream = TcpStream::connect((server, effective_port))
            .map_err(|error| request_error(1, &error))?;
        let _ = stream.set_read_timeout(Some(HTTP_TIMEOUT));
        let _ = stream.set_write_timeout(Some(HTTP_TIMEOUT));
        let host = if port == 0 {
            server.to_owned()
        } else {
            format!("{server}:{port}")
        };
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(path);
        request.extend_from_slice(
            format!(" HTTP/1.1\r\nUser-Agent: {REGISTRATION_USER_AGENT}\r\nHost: {host}\r\n\r\n")
                .as_bytes(),
        );
        stream
            .write_all(&request)
            .map_err(|error| request_error(1, &error))?;

        let mut received = Vec::new();
        let header_end = loop {
            if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
            let mut chunk = [0u8; 512];
            match stream.read(&mut chunk) {
                Ok(0) => return Err(HttpFailure::Request { state: 3, error: 0 }),
                Ok(count) => received.extend_from_slice(&chunk[..count]),
                Err(error) => return Err(request_error(3, &error)),
            }
        };
        let head = String::from_utf8_lossy(&received[..header_end]).into_owned();
        let mut lines = head.split("\r\n");
        let code = lines
            .next()
            .and_then(|status| status.split(' ').nth(1))
            .and_then(|code| code.parse::<u32>().ok());
        let code = code.ok_or(HttpFailure::StatusQuery {
            error: HTTP_HEADER_NOT_FOUND,
        })?;
        if code != 200 {
            return Err(HttpFailure::Status { code });
        }
        let length = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u32>().ok())?
        });
        let length = length.ok_or(HttpFailure::ContentLength {
            error: HTTP_HEADER_NOT_FOUND,
        })?;
        if length as usize > REGISTRATION_RESPONSE_CAPACITY {
            return Err(HttpFailure::TooLarge { length });
        }
        let mut content = received[header_end + 4..].to_vec();
        while content.len() < length as usize {
            let mut chunk = [0u8; 512];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    let received = content.len() as u32;
                    return Err(HttpFailure::Truncated {
                        received,
                        expected: length - received,
                    });
                }
                Ok(count) => content.extend_from_slice(&chunk[..count]),
                Err(error) => return Err(request_error(5, &error)),
            }
        }
        content.truncate(length as usize);
        Ok(content)
    }
}

/// Address record of the reference console's debug interface.
const DEBUG_ADDRESS: [u8; NETWORK_ADDRESS_SIZE] = [
    0xc0, 0xa8, 0x01, 0x1a, 0, 0, 0, 0, 0, 0, 0x7c, 0xed, 0x8d, 0x74, 0xf5, 0xd7, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0,
];
/// Address record of the reference console's title interface.
const TITLE_ADDRESS: [u8; NETWORK_ADDRESS_SIZE] = [
    0xc0, 0xa8, 0x01, 0x19, 0, 0, 0, 0, 0, 0, 0x7c, 0xed, 0x8d, 0x74, 0xf5, 0xd6, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0,
];
/// Address query flags reported for a configured interface.
const ADDRESS_READY: u32 = 0x66;

impl Default for Mock {
    fn default() -> Self {
        Self {
            features: KitFeatures {
                debugging: true,
                secondary_nic: false,
                one_gigabyte_ram: true,
            },
            xconfig: XConfig::default(),
            settings_block: [0xff; SETTINGS_BLOCK_SIZE],
            i2c_failure: false,
            memory_statistics: Some(MemoryStatistics {
                physical_pages: 0x3_ff00,
                debug_memory: 0x0002_0000,
                page_threshold: 0x2_0000,
            }),
            system_information: SystemInformation {
                base_kernel: Version([2, 0, 1888, 0]),
                kernel: Version([2, 0, 17559, 0]),
                hardware_flags: 0x5001_0023,
            },
            console_id: Ok(ConsoleId(*b"012345678901")),
            debug_address: NetworkAddress {
                status: ADDRESS_READY,
                record: DEBUG_ADDRESS,
            },
            title_address: NetworkAddress {
                status: ADDRESS_READY,
                record: TITLE_ADDRESS,
            },
            inactivity_updates: 0,
            network_ra: NetworkRaService::default(),
            feature_calls: Some(Vec::new()),
            network_client_status: NtStatus::SUCCESS,
            system_version: 0x2045_5400,
            boot: Instant::now(),
            http: HttpClient::default(),
            published: PublishedState::default(),
            system_settings: SystemSettings::default(),
            marked_test_kit: false,
            current_thread: SERVER_THREAD,
        }
    }
}

impl console::Backend for MockBackend {
    fn kit_features(&mut self) -> KitFeatures {
        self.console.features
    }

    fn xconfig_get(
        &mut self,
        setting: ConfigSetting,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let xconfig = &self.console.xconfig;
        xconfig.check(setting)?;
        output.fill(0);
        match xconfig.settings.get(&setting) {
            Some(value) => {
                let length = value.len().min(output.len());
                output[..length].copy_from_slice(&value[..length]);
                Ok(value.len())
            }
            None => Ok(output.len()),
        }
    }

    fn xconfig_set(&mut self, setting: ConfigSetting, value: &[u8]) -> Result<(), NtStatus> {
        self.console.xconfig.check(setting)?;
        self.console
            .xconfig
            .settings
            .insert(setting, value.to_vec());
        Ok(())
    }

    fn xconfig_modify(
        &mut self,
        setting: ConfigSetting,
        and_mask: u32,
        or_mask: u32,
    ) -> Result<(), NtStatus> {
        let xconfig = &mut self.console.xconfig;
        if !xconfig.modify_export {
            return Err(STATUS_PROCEDURE_NOT_FOUND);
        }
        xconfig.check(setting)?;
        let value = (xconfig.dword(setting.category, setting.index) & and_mask) | or_mask;
        xconfig
            .settings
            .insert(setting, value.to_be_bytes().to_vec());
        Ok(())
    }

    fn read_settings_block(&mut self) -> Option<[u8; SETTINGS_BLOCK_SIZE]> {
        (!self.console.i2c_failure).then_some(self.console.settings_block)
    }

    fn write_settings_block(&mut self, block: &[u8; SETTINGS_BLOCK_SIZE]) -> bool {
        if self.console.i2c_failure {
            return false;
        }
        self.console.settings_block = *block;
        true
    }

    fn memory_statistics(&mut self) -> Option<MemoryStatistics> {
        self.console.memory_statistics
    }

    fn system_information(&mut self) -> SystemInformation {
        self.console.system_information
    }

    fn console_id(&mut self) -> Result<ConsoleId, NtStatus> {
        self.console.console_id
    }

    fn debug_network_address(&mut self) -> NetworkAddress {
        self.console.debug_address
    }

    fn title_network_address(&mut self) -> NetworkAddress {
        self.console.title_address
    }

    fn apply_inactivity_time(&mut self) {
        self.console.inactivity_updates += 1;
    }

    fn network_ra_request(&mut self, request: NetworkRaRequest<'_>) -> XamStatus {
        let service = &mut self.console.network_ra;
        if let Some(status) = service.failure {
            return status;
        }
        match request {
            NetworkRaRequest::Get(record) => *record = service.record,
            NetworkRaRequest::Set(record) => service.record = *record,
            NetworkRaRequest::Reset => service.resets += 1,
        }
        XamStatus(0)
    }

    fn feature_switch_present(&mut self) -> bool {
        self.console.feature_calls.is_some()
    }

    fn set_feature(&mut self, enable: u32, feature: u32) {
        if let Some(calls) = &mut self.console.feature_calls {
            calls.push((enable, feature));
        }
    }

    fn load_network_client(&mut self) -> NtStatus {
        self.console.network_client_status
    }

    fn tick_milliseconds(&mut self) -> u32 {
        self.console.boot.elapsed().as_millis() as u32
    }

    fn xam_version(&mut self) -> u32 {
        self.console.system_version
    }

    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure> {
        let server = String::from_utf8_lossy(request.server).into_owned();
        let (port, path) = (request.port, request.path.to_vec());
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(HttpClient::exchange(&server, port, &path));
        });
        self.console.http.pending = Some(receiver);
        Ok(())
    }

    fn http_poll(&mut self, body: &mut [u8; REGISTRATION_RESPONSE_CAPACITY]) -> HttpProgress {
        let Some(receiver) = &self.console.http.pending else {
            return HttpProgress::Failed(HttpFailure::Work { error: 0 });
        };
        match receiver.try_recv() {
            Err(TryRecvError::Empty) => HttpProgress::Pending,
            Err(TryRecvError::Disconnected) => HttpProgress::Failed(HttpFailure::Work { error: 0 }),
            Ok(Err(failure)) => HttpProgress::Failed(failure),
            Ok(Ok(content)) => {
                body.fill(0);
                body[..content.len()].copy_from_slice(&content);
                HttpProgress::Complete(content.len())
            }
        }
    }

    fn http_close(&mut self) {
        self.console.http.pending = None;
        self.console.http.closes += 1;
    }

    fn publish(&mut self, value: Published<'_>) {
        let published = &mut self.console.published;
        match value {
            Published::DebugName(name) => published.name = name.as_bytes().to_vec(),
            Published::DumpMode(mode) => published.dump_mode = mode.raw(),
            Published::DumpSettings(settings) => {
                published.dump_settings = settings.to_block().to_vec()
            }
            Published::EventDefer(mask) => published.event_defer = mask.0,
            Published::TraceMask(mask) => published.trace_mask = mask.0,
            Published::Registration(registration) => published.registration = registration.result(),
        }
    }

    fn system_settings(&mut self) -> SystemSettings {
        self.console.system_settings
    }

    fn set_system_settings(&mut self, settings: SystemSettings) {
        self.console.system_settings = settings;
    }

    fn mark_test_kit(&mut self) {
        self.console.marked_test_kit = true;
    }

    fn current_thread(&mut self) -> u32 {
        self.console.current_thread
    }

    fn trace_mask(&mut self) -> console::TraceMask {
        console::TraceMask(self.console.published.trace_mask)
    }
}
