//! Simulated settings files, clock, and restart.

use std::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::system;
use openxbdm_server::commands::system::CreateSettingsError;
use openxbdm_server::commands::system::FlashOptions;
use openxbdm_server::commands::system::RebootKind;
use openxbdm_server::commands::system::SettingsCopy;
use openxbdm_server::commands::system::SettingsFile;
use openxbdm_server::commands::system::SettingsSource;
use xbox360_sys::xboxkrnl::HardwareFlags;

use super::MockBackend;

/// Settings file of a fresh simulated console.
const INITIAL_SETTINGS: &[u8] = b"[xbdm]\r\ndbgname name=openxbdm-mock\r\n";
/// Hardware flags of the simulated development kit: revision 4.
const HARDWARE_FLAGS: HardwareFlags = HardwareFlags::from_bits_retain(0x4000_0013);
/// Largest flash image buffer the simulated console can allocate.
const FLASH_MEMORY: u32 = 0x0400_0000;
/// Buffer through which a settings copy reaches the caller's file.
const COPY_FILE_BUFFER: usize = 0x1000;

/// A programmed flash image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashWrite {
    pub image: Vec<u8>,
    pub options: FlashOptions,
}

/// A finished copy of the settings text and the bytes its destination
/// received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopiedSettings {
    pub copy: SettingsCopy,
    pub bytes: Vec<u8>,
}

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    /// `\SystemRoot\MobileJ.dat`, the settings file the monitor writes;
    /// `None` when the file does not exist.
    pub settings: Option<Vec<u8>>,
    /// `\SystemRoot\xbdm.ini`, read at startup instead of `settings` when
    /// present.
    pub ini_override: Option<Vec<u8>>,
    /// `\SystemRoot\recint.ini`, read at startup after the saved settings.
    pub recint: Option<Vec<u8>>,
    /// The console booted from disc; the settings file cannot be written.
    pub cd_boot: bool,
    /// The settings write or wipe in progress comes from a thread of the
    /// title process.
    pub title_process_caller: bool,
    /// Restarts requested, in order.
    pub reboots: Vec<RebootKind>,
    /// Difference between the set clock and the simulated clock, in
    /// FILETIME units.
    pub clock_adjustment: u64,
    /// Clock values set, in order.
    pub clock_sets: Vec<u64>,
    /// Kernel hardware flags; the test-kit bit comes from
    /// `MockBackend::test_kit`.
    pub hardware_flags: HardwareFlags,
    /// The system registered a title launch routine.
    pub relaunch_routine: bool,
    /// In-place title relaunches performed.
    pub relaunches: u32,
    /// A settings copy can allocate its buffer.
    pub copy_buffer_available: bool,
    /// Settings copies made, in order.
    pub copies: Vec<CopiedSettings>,
    /// Largest image buffer `flash` can allocate.
    pub flash_memory: u32,
    /// Result the flash writer reports.
    pub flash_result: Result<(), Win32Error>,
    /// Images programmed, in order. The simulation stores them instead of
    /// writing a flash device.
    pub flash_writes: Vec<FlashWrite>,
    flash_buffer: Option<Vec<u8>>,
    open: Vec<Option<OpenFile>>,
}

#[derive(Debug)]
enum OpenFile {
    Write,
    Read { data: Vec<u8>, position: usize },
    Copy { copy: SettingsCopy, bytes: Vec<u8> },
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            settings: Some(INITIAL_SETTINGS.to_vec()),
            ini_override: None,
            recint: None,
            cd_boot: false,
            title_process_caller: false,
            reboots: Vec::new(),
            clock_adjustment: 0,
            clock_sets: Vec::new(),
            hardware_flags: HARDWARE_FLAGS,
            relaunch_routine: false,
            relaunches: 0,
            copy_buffer_available: true,
            copies: Vec::new(),
            flash_memory: FLASH_MEMORY,
            flash_result: Ok(()),
            flash_writes: Vec::new(),
            flash_buffer: None,
            open: Vec::new(),
        }
    }
}

impl Mock {
    fn insert(&mut self, file: OpenFile) -> SettingsFile {
        let slot = match self.open.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                self.open.push(None);
                self.open.len() - 1
            }
        };
        self.open[slot] = Some(file);
        SettingsFile(slot as u32)
    }
}

impl system::Backend for MockBackend {
    fn create_settings(&mut self) -> Result<SettingsFile, CreateSettingsError> {
        self.system.settings = Some(Vec::new());
        Ok(self.system.insert(OpenFile::Write))
    }

    fn booted_from_disc(&mut self) -> bool {
        self.system.cd_boot
    }

    fn title_process_caller(&mut self) -> bool {
        self.system.title_process_caller
    }

    fn settings_file_size(&mut self, file: SettingsFile) -> Result<u32, KernelError> {
        match self.system.open.get(file.0 as usize) {
            Some(Some(OpenFile::Read { data, .. })) => Ok(data.len() as u32),
            _ => Err(KernelError::InvalidHandle),
        }
    }

    fn begin_settings_copy(&mut self, copy: SettingsCopy) -> Option<SettingsFile> {
        if !self.system.copy_buffer_available {
            return None;
        }
        Some(self.system.insert(OpenFile::Copy {
            copy,
            bytes: Vec::new(),
        }))
    }

    /// A memory copy keeps what fits; a padded file copy is followed by
    /// zeros up to the end of the last buffer.
    fn end_settings_copy(&mut self, file: SettingsFile) -> u32 {
        let Some(OpenFile::Copy { copy, mut bytes }) = self
            .system
            .open
            .get_mut(file.0 as usize)
            .and_then(Option::take)
        else {
            panic!("settings copy {file:?} is not open");
        };
        let length = match copy {
            SettingsCopy::Memory { capacity, .. } => {
                bytes.truncate(capacity as usize);
                bytes.len()
            }
            SettingsCopy::File { pad, .. } => {
                let length = bytes.len();
                if pad {
                    bytes.resize(length.next_multiple_of(COPY_FILE_BUFFER), 0);
                }
                length
            }
        };
        self.system.copies.push(CopiedSettings { copy, bytes });
        length as u32
    }

    fn open_settings(&mut self, source: SettingsSource) -> Option<SettingsFile> {
        let data = match source {
            SettingsSource::Saved => self
                .system
                .ini_override
                .as_ref()
                .or(self.system.settings.as_ref()),
            SettingsSource::Recint => self.system.recint.as_ref(),
        }?
        .clone();
        Some(self.system.insert(OpenFile::Read { data, position: 0 }))
    }

    fn write_settings(&mut self, file: SettingsFile, bytes: &[u8]) {
        match self.system.open.get_mut(file.0 as usize) {
            Some(Some(OpenFile::Write)) => {
                if let Some(settings) = self.system.settings.as_mut() {
                    settings.extend_from_slice(bytes);
                }
            }
            Some(Some(OpenFile::Copy { bytes: copied, .. })) => copied.extend_from_slice(bytes),
            _ => {}
        }
    }

    fn read_settings(&mut self, file: SettingsFile, buffer: &mut [u8]) -> Option<usize> {
        let Some(Some(OpenFile::Read { data, position })) =
            self.system.open.get_mut(file.0 as usize)
        else {
            return None;
        };
        let count = buffer.len().min(data.len() - *position);
        if count == 0 {
            return None;
        }
        buffer[..count].copy_from_slice(&data[*position..*position + count]);
        *position += count;
        Some(count)
    }

    fn close_settings(&mut self, file: SettingsFile) {
        if let Some(slot) = self.system.open.get_mut(file.0 as usize) {
            *slot = None;
        }
    }

    fn sleep_milliseconds(&mut self, milliseconds: u32) {
        std::thread::sleep(Duration::from_millis(u64::from(milliseconds)));
    }

    fn reboot(&mut self, kind: RebootKind) {
        self.system.reboots.push(kind);
    }

    fn set_system_time(&mut self, file_time: u64) {
        let current = self.unadjusted_system_time();
        self.system.clock_adjustment = file_time.wrapping_sub(current);
        self.system.clock_sets.push(file_time);
    }

    fn hardware_flags(&mut self) -> HardwareFlags {
        let mut flags = self.system.hardware_flags;
        if self.test_kit {
            flags.insert(HardwareFlags::TEST_KIT);
        }
        flags
    }

    fn title_launch_registered(&mut self) -> bool {
        self.system.relaunch_routine
    }

    fn launch_title(&mut self) {
        self.system.relaunches += 1;
    }

    fn flash_begin(&mut self, rounded_size: u32) -> bool {
        if rounded_size > self.system.flash_memory {
            return false;
        }
        self.system.flash_buffer = Some(vec![0xcd; rounded_size as usize]);
        true
    }

    /// Bytes past the rounded buffer, possible when the rounding wrapped,
    /// are not simulated.
    fn flash_write(&mut self, offset: u32, bytes: &[u8]) {
        if let Some(tail) = self
            .system
            .flash_buffer
            .as_mut()
            .and_then(|buffer| buffer.get_mut(offset as usize..))
        {
            let count = bytes.len().min(tail.len());
            tail[..count].copy_from_slice(&bytes[..count]);
        }
    }

    fn flash_commit(&mut self, length: u32, options: FlashOptions) -> Result<(), Win32Error> {
        let Some(mut image) = self.system.flash_buffer.take() else {
            return self.system.flash_result;
        };
        let length = (length as usize).min(image.len());
        image[length..].fill(0);
        if self.system.flash_result.is_ok() {
            self.system.flash_writes.push(FlashWrite { image, options });
        }
        self.system.flash_result
    }

    fn flash_abort(&mut self) {
        self.system.flash_buffer = None;
    }
}
