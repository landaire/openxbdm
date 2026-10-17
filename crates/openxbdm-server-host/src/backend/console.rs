//! Simulated console identity and configuration.

mod http;

use std::collections::BTreeMap;
use std::time::Instant;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::console;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::ConsoleId;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::HttpStartFailure;
use openxbdm_server::commands::console::KitFeatures;
use openxbdm_server::commands::console::MemoryStatistics;
use openxbdm_server::commands::console::NETWORK_ADDRESS_SIZE;
use openxbdm_server::commands::console::NetworkAddress;
use openxbdm_server::commands::console::NetworkRaError;
use openxbdm_server::commands::console::NetworkRaRecord;
use openxbdm_server::commands::console::NetworkRaRequest;
use openxbdm_server::commands::console::Published;
use openxbdm_server::commands::console::SETTINGS_BLOCK_SIZE;
use openxbdm_server::commands::console::SystemInformation;
use openxbdm_server::commands::console::SystemSettings;
use openxbdm_server::commands::console::Version;
use xbox360_sys::xboxkrnl::HardwareFlags;

use super::MockBackend;

pub use self::http::HttpClient;

/// Kernel address of the simulated server thread object.
pub const SERVER_THREAD: u32 = 0x8007_4a00;

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
    pub console_id: Result<ConsoleId, KernelError>,

    pub debug_address: NetworkAddress,
    pub title_address: NetworkAddress,

    /// Times the inactivity configuration was applied.
    pub inactivity_updates: u32,
    pub network_ra: NetworkRaService,
    /// Calls of the system UI feature switch; `None` when the export is absent.
    pub feature_calls: Option<Vec<(u32, u32)>>,
    /// Failure of loading the network file system client; `None` loads it.
    pub network_client_failure: Option<KernelError>,

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

impl Default for Mock {
    fn default() -> Self {
        /// Address record of the reference console's debug interface.
        const DEBUG_ADDRESS: [u8; NETWORK_ADDRESS_SIZE] = [
            0xc0, 0xa8, 0x01, 0x1a, 0, 0, 0, 0, 0, 0, 0x7c, 0xed, 0x8d, 0x74, 0xf5, 0xd7, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0,
        ];
        /// Address record of the reference console's title interface.
        const TITLE_ADDRESS: [u8; NETWORK_ADDRESS_SIZE] = [
            0xc0, 0xa8, 0x01, 0x19, 0, 0, 0, 0, 0, 0, 0x7c, 0xed, 0x8d, 0x74, 0xf5, 0xd6, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0,
        ];
        /// Address query flags reported for a configured interface.
        const ADDRESS_READY: u32 = 0x66;

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
                hardware_flags: HardwareFlags::from_bits_retain(0x5001_0023),
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
            network_client_failure: None,
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

/// Simulated console configuration settings.
#[derive(Debug)]
pub struct XConfig {
    /// Stored values. A setting never written reads as zero bytes of the
    /// requested length, as the fixed-layout settings of a new console do.
    pub settings: BTreeMap<ConfigSetting, Vec<u8>>,
    /// Failure of every read, write, or modify of a setting.
    pub failures: BTreeMap<ConfigSetting, KernelError>,
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

    fn check(&self, setting: ConfigSetting) -> Result<(), KernelError> {
        match self.failures.get(&setting) {
            Some(&error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Simulated system network service (data-center configuration).
#[derive(Debug, Default)]
pub struct NetworkRaService {
    pub record: NetworkRaRecord,
    /// Failure of every request while set.
    pub failure: Option<NetworkRaError>,
    pub resets: u32,
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
            event_defer: state.event_defer.bits(),
            trace_mask: state.trace_mask.bits(),
            registration: console::RegistrationResult::EMPTY,
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
    ) -> Result<usize, KernelError> {
        let xconfig = &self.console.xconfig;
        xconfig.check(setting)?;

        output.fill(0);
        let Some(value) = xconfig.settings.get(&setting) else {
            return Ok(output.len());
        };

        let length = value.len().min(output.len());
        output[..length].copy_from_slice(&value[..length]);

        Ok(value.len())
    }

    fn xconfig_set(&mut self, setting: ConfigSetting, value: &[u8]) -> Result<(), KernelError> {
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
    ) -> Result<(), KernelError> {
        let xconfig = &mut self.console.xconfig;
        if !xconfig.modify_export {
            return Err(KernelError::OrdinalNotFound);
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

    fn console_id(&mut self) -> Result<ConsoleId, KernelError> {
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

    fn network_ra_request(&mut self, request: NetworkRaRequest<'_>) -> Result<(), NetworkRaError> {
        let service = &mut self.console.network_ra;
        if let Some(error) = service.failure {
            return Err(error);
        }

        match request {
            NetworkRaRequest::Get(record) => *record = service.record,
            NetworkRaRequest::Set(record) => service.record = *record,
            NetworkRaRequest::Reset => service.resets += 1,
        }

        Ok(())
    }

    fn feature_switch_present(&mut self) -> bool {
        self.console.feature_calls.is_some()
    }

    fn set_feature(&mut self, enable: u32, feature: u32) {
        if let Some(calls) = &mut self.console.feature_calls {
            calls.push((enable, feature));
        }
    }

    fn load_network_client(&mut self) -> Result<(), KernelError> {
        self.console.network_client_failure.map_or(Ok(()), Err)
    }

    fn tick_milliseconds(&mut self) -> u32 {
        self.console.boot.elapsed().as_millis() as u32
    }

    fn xam_version(&mut self) -> u32 {
        self.console.system_version
    }

    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure> {
        self.console.http.begin(request);

        Ok(())
    }

    fn http_poll(&mut self) -> HttpProgress {
        self.console.http.poll()
    }

    fn http_close(&mut self) {
        self.console.http.close();
    }

    fn publish(&mut self, value: Published<'_>) {
        let body = &self.console.http.body;
        let published = &mut self.console.published;
        match value {
            Published::DebugName(name) => published.name = name.as_bytes().to_vec(),
            Published::DumpMode(mode) => published.dump_mode = mode.raw(),
            Published::DumpSettings(settings) => {
                published.dump_settings = settings.to_block().to_vec()
            }
            Published::EventDefer(mask) => published.event_defer = mask.bits(),
            Published::TraceMask(mask) => published.trace_mask = mask.bits(),
            Published::Registration(registration) => {
                published.registration = console::RegistrationResult::new(registration, body)
            }
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
        console::TraceMask::from_bits_retain(self.console.published.trace_mask)
    }
}
