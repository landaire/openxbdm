//! Simulated virtual memory, loaded modules, flash, and allocation
//! tracking.

use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::memory;
use openxbdm_server::commands::memory::CodeView;
use openxbdm_server::commands::memory::ModuleIndex;
use openxbdm_server::commands::memory::ModuleInfo;
use openxbdm_server::commands::memory::ModuleName;
use openxbdm_server::commands::memory::NoSuchModule;
use openxbdm_server::commands::memory::SectionIndex;
use openxbdm_server::commands::memory::SectionInfo;
use openxbdm_server::commands::memory::TrackingFlags;
use openxbdm_server::commands::memory::XexFieldError;
use openxbdm_server::commands::memory::XexFieldKey;
use openxbdm_server::commands::memory::detour as engine;

use super::MockBackend;

pub mod detour;

/// Base of the primary simulated region.
pub const MEMORY_BASE: u32 = 0x8000_0000;
/// Bytes of the primary simulated region.
pub const MEMORY_SIZE: usize = 1024 * 1024;
/// Granularity of the address checks; regions are mapped in whole pages.
pub const PAGE_SIZE: usize = 0x1000;

/// A mapped range. Mapped addresses equal virtual addresses, so reads of
/// device ranges fail as they do through the debugger mapping.
#[derive(Debug, Clone)]
pub struct Region {
    pub base: u32,
    pub bytes: Vec<u8>,
}

impl Region {
    /// A range filled with the low byte of each offset.
    pub fn patterned(base: u32, size: usize) -> Self {
        Self {
            base,
            bytes: (0..size).map(|offset| offset as u8).collect(),
        }
    }
}

/// Loader list a module is linked into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleList {
    Primary,
    Secondary,
}

/// An XEX optional header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XexField {
    /// Value stored in the key slot (key low byte 0).
    Inline(u32),
    Data(Vec<u8>),
}

/// A loaded module.
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub list: ModuleList,
    /// Loader flag 0x100000; `modules` lists only flagged modules.
    pub flagged: bool,
    /// Whether the image has an NT header.
    pub nt_header: bool,
    pub base: u32,
    pub size: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub pdata: u32,
    pub pdata_size: u32,
    pub dll: bool,
    pub image_size: u32,
    pub sections: Vec<SectionInfo>,
    pub code_view: Option<CodeView>,
    pub xex_fields: Vec<(u32, XexField)>,
}

impl Module {
    fn units(&self) -> impl Iterator<Item = u16> + '_ {
        self.name.encode_utf16()
    }

    fn field(&self, key: XexFieldKey) -> Option<&XexField> {
        self.xex_fields
            .iter()
            .find(|(field, _)| *field == key.0)
            .map(|(_, value)| value)
    }
}

/// Simulated memory and module state.
#[derive(Debug)]
pub struct Mock {
    pub regions: Vec<Region>,
    pub modules: Vec<Module>,
    /// Base name of the running title's module.
    pub title_module: Option<String>,
    /// Object path of the running executable.
    pub executable_path: Vec<u8>,
    /// Raw flash device content.
    pub flash: Vec<u8>,
    pub flash_read_failure: Option<KernelError>,
    pub flash_write_failure: Option<KernelError>,
    /// Module names the kernel accepts for import tracing.
    pub traceable_modules: Vec<String>,
    /// Import tracing requests the kernel accepted, in order.
    pub traced_modules: Vec<(Vec<u8>, bool)>,
    pub tracking_flags: TrackingFlags,
    /// Allocation tracking records, newest first, as written to a file.
    pub tracking_records: Vec<Vec<u8>>,
    pub detour: detour::Mock,
}

fn section(name: &[u8], address: u32, size: u32, characteristics: u32) -> SectionInfo {
    let mut padded = [0u8; memory::SECTION_NAME_LENGTH];
    padded[..name.len()].copy_from_slice(name);
    SectionInfo {
        name: padded,
        address,
        size,
        characteristics,
    }
}

impl Default for Mock {
    fn default() -> Self {
        let mut flash = vec![0u8; 0x100];
        flash[memory::ADVANCED_MEMORY_FLASH_OFFSET as usize..][..2]
            .copy_from_slice(&0x0100u16.to_be_bytes());
        Self {
            regions: vec![
                Region::patterned(0x3000_0000, 0x2000),
                Region::patterned(0x3000_3000, 0x1000),
                Region::patterned(0x4000_0000, 0x2_0000),
                Region::patterned(0x7fe9_0000, 0x2_0000),
                Region::patterned(MEMORY_BASE, MEMORY_SIZE),
                Region::patterned(0x9000_0000, 0x3000),
                detour::trampoline_region(),
            ],
            modules: vec![
                Module {
                    name: "xboxkrnl.exe".to_owned(),
                    list: ModuleList::Primary,
                    flagged: true,
                    nt_header: true,
                    base: 0x8004_0000,
                    size: 0x0023_0000,
                    checksum: 0x0024_1d5e,
                    timestamp: 0x4b6f_0a10,
                    pdata: 0x8004_6000,
                    pdata_size: 0x8_c4a0,
                    dll: false,
                    image_size: 0x0023_0000,
                    sections: vec![
                        section(b".text", 0x8004_1000, 0x1_8000, 0x6000_0020),
                        section(b".data", 0x8005_9000, 0x2000, 0xc000_0040),
                    ],
                    code_view: None,
                    xex_fields: Vec::new(),
                },
                Module {
                    name: "bootanim.xex".to_owned(),
                    list: ModuleList::Primary,
                    flagged: false,
                    nt_header: true,
                    base: 0x9800_0000,
                    size: 0x1_0000,
                    checksum: 0,
                    timestamp: 0x4b6f_0a11,
                    pdata: 0,
                    pdata_size: 0,
                    dll: true,
                    image_size: 0x1_0000,
                    sections: vec![section(b".text", 0x9800_1000, 0x8000, 0x6000_0020)],
                    code_view: None,
                    xex_fields: Vec::new(),
                },
                Module {
                    name: "xam.xex".to_owned(),
                    list: ModuleList::Primary,
                    flagged: true,
                    nt_header: true,
                    base: 0x8170_0000,
                    size: 0x0080_0000,
                    checksum: 0x007f_1a2b,
                    timestamp: 0x4b6f_0a12,
                    pdata: 0x8170_2000,
                    pdata_size: 0x3_1000,
                    dll: true,
                    image_size: 0x0078_0000,
                    sections: vec![
                        section(b".rdata", 0x8170_1000, 0x1000, 0x4000_0040),
                        section(b".text", 0x8170_2000, 0x40_0000, 0x6000_0020),
                        section(b".bss", 0x81b0_2000, 0x2_0000, 0xc000_0080),
                    ],
                    code_view: Some(CodeView::new(
                        [
                            0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5,
                            0xc6, 0xd7, 0xe8, 0xf9,
                        ],
                        [0x02, 0x00, 0x00, 0x00],
                        b"e:\\build\\xam.pdb",
                    )),
                    xex_fields: vec![
                        (0x10100, XexField::Inline(0x0000_1234)),
                        (0x10001, XexField::Data(vec![0xde, 0xad, 0xbe, 0xef])),
                        (
                            0x18002,
                            XexField::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                        ),
                        (
                            0x183ff,
                            XexField::Data({
                                let mut blob = 0x28u32.to_be_bytes().to_vec();
                                blob.extend((0..0x24).map(|offset| 0xa0 + offset as u8));
                                blob
                            }),
                        ),
                        (0x30000, XexField::Inline(0)),
                        (0x20000, XexField::Inline(7)),
                    ],
                },
                Module {
                    name: "default.xex".to_owned(),
                    list: ModuleList::Secondary,
                    flagged: true,
                    nt_header: true,
                    base: 0x8200_0000,
                    size: 0x0010_0000,
                    checksum: 0,
                    timestamp: 0x5e1f_2a3b,
                    pdata: 0x8200_1000,
                    pdata_size: 0x400,
                    dll: false,
                    image_size: 0x000f_0000,
                    sections: vec![section(b".text", 0x8200_1000, 0x8000, 0x6000_0020)],
                    code_view: Some(CodeView::new(
                        [0x11; 16],
                        [0x01, 0x00, 0x00, 0x00],
                        b"d:\\title\\default.pdb",
                    )),
                    xex_fields: vec![(
                        0x40801,
                        XexField::Data(0x0400_0000u32.to_be_bytes().to_vec()),
                    )],
                },
            ],
            title_module: Some("default.xex".to_owned()),
            executable_path: b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\title\\default.xex"
                .to_vec(),
            flash,
            flash_read_failure: None,
            flash_write_failure: None,
            traceable_modules: vec!["xam.xex".to_owned()],
            traced_modules: Vec::new(),
            tracking_flags: TrackingFlags::default(),
            tracking_records: Vec::new(),
            detour: detour::Mock::default(),
        }
    }
}

impl Mock {
    fn byte(&self, address: u32) -> Option<&u8> {
        self.regions
            .iter()
            .find_map(|region| region.bytes.get(address.checked_sub(region.base)? as usize))
    }

    fn byte_mut(&mut self, address: u32) -> Option<&mut u8> {
        self.regions.iter_mut().find_map(|region| {
            region
                .bytes
                .get_mut(address.checked_sub(region.base)? as usize)
        })
    }

    /// Whether every byte of the page holding `address` is mapped.
    fn page_mapped(&self, address: u32) -> bool {
        let page = address & !(PAGE_SIZE as u32 - 1);
        self.regions.iter().any(|region| {
            page.checked_sub(region.base)
                .is_some_and(|offset| offset as usize + PAGE_SIZE <= region.bytes.len())
        })
    }

    /// Modules in loader order: the primary list, then the secondary list.
    fn loader_order(&self) -> impl Iterator<Item = &Module> {
        let primary = self
            .modules
            .iter()
            .filter(|module| module.list == ModuleList::Primary);
        primary.chain(
            self.modules
                .iter()
                .filter(|module| module.list == ModuleList::Secondary),
        )
    }

    fn find(&self, name: &[u8]) -> Option<&Module> {
        self.loader_order()
            .find(|module| memory::module_name_matches(module.units(), name, true))
    }
}

impl memory::Backend for MockBackend {
    fn is_address_valid(&mut self, address: u32) -> bool {
        self.memory.page_mapped(address)
    }

    fn read_byte(&mut self, address: u32) -> Option<u8> {
        if memory::is_device_address(address) {
            return None;
        }
        self.memory.byte(address).copied()
    }

    fn write_byte(&mut self, address: u32, value: u8) -> bool {
        if memory::is_device_address(address) {
            return false;
        }
        self.memory
            .byte_mut(address)
            .map(|byte| *byte = value)
            .is_some()
    }

    fn is_readable(&mut self, address: u32) -> bool {
        !memory::is_device_address(address) && self.memory.page_mapped(address)
    }

    fn read_memory(&mut self, address: u32, output: &mut [u8]) {
        for (offset, byte) in output.iter_mut().enumerate() {
            *byte = *self
                .memory
                .byte(address.wrapping_add(offset as u32))
                .expect("read of a page reported readable");
        }
    }

    fn module(&mut self, index: ModuleIndex) -> Option<ModuleInfo> {
        let module = self
            .memory
            .loader_order()
            .filter(|module| module.flagged && module.nt_header)
            .nth(index.0 as usize)?;
        Some(ModuleInfo {
            name: ModuleName::from_units(module.units()),
            base: module.base,
            size: module.size,
            checksum: module.checksum,
            timestamp: module.timestamp,
            pdata: module.pdata,
            pdata_size: module.pdata_size,
            dll: module.dll,
            image_size: module.image_size,
        })
    }

    fn module_section(
        &mut self,
        name: &[u8],
        index: SectionIndex,
    ) -> Result<Option<SectionInfo>, NoSuchModule> {
        let module = self
            .memory
            .find(name)
            .filter(|module| module.nt_header)
            .ok_or(NoSuchModule)?;
        Ok(usize::from(index.0)
            .checked_sub(1)
            .and_then(|index| module.sections.get(index))
            .copied())
    }

    fn code_view(&mut self, base: u32) -> Option<CodeView> {
        self.memory
            .loader_order()
            .filter(|module| module.base == base)
            .find_map(|module| module.code_view)
    }

    fn xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
    ) -> Result<u32, XexFieldError> {
        let module = self
            .memory
            .find(module)
            .ok_or(XexFieldError::NoSuchModule)?;
        match module.field(field) {
            Some(XexField::Inline(value)) if *value != 0 => Ok(*value),
            // Field data lives in the module's header page.
            Some(XexField::Data(_)) => Ok(module.base + 0x400),
            _ => Err(XexFieldError::FieldAbsent),
        }
    }

    fn read_xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
        offset: u32,
        output: &mut [u8],
    ) -> Result<(), XexFieldError> {
        let module = self
            .memory
            .find(module)
            .ok_or(XexFieldError::NoSuchModule)?;
        let Some(XexField::Data(data)) = module.field(field) else {
            return Err(XexFieldError::FieldAbsent);
        };
        // Bytes past the stored data read as the zeros that follow it.
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = data.get(offset as usize + index).copied().unwrap_or(0);
        }
        Ok(())
    }

    fn title_xex_dword(&mut self, field: XexFieldKey) -> Result<Option<u32>, NoSuchModule> {
        let name = self.memory.title_module.clone().ok_or(NoSuchModule)?;
        let module = self.memory.find(name.as_bytes()).ok_or(NoSuchModule)?;
        Ok(match module.field(field) {
            Some(XexField::Data(data)) => Some(u32::from_be_bytes(
                data[..4].try_into().expect("field data holds a dword"),
            )),
            Some(XexField::Inline(_)) | None => None,
        })
    }

    fn running_executable_path(&mut self, output: &mut [u8]) -> usize {
        let count = self.memory.executable_path.len().min(output.len());
        output[..count].copy_from_slice(&self.memory.executable_path[..count]);
        count
    }

    fn read_flash(&mut self, offset: u32, output: &mut [u8]) -> Result<(), KernelError> {
        if let Some(error) = self.memory.flash_read_failure {
            return Err(error);
        }
        output.copy_from_slice(&self.memory.flash[offset as usize..][..output.len()]);
        Ok(())
    }

    fn write_flash(&mut self, offset: u32, data: &[u8]) -> Result<(), KernelError> {
        if let Some(error) = self.memory.flash_write_failure {
            return Err(error);
        }
        self.memory.flash[offset as usize..][..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn trace_imports(&mut self, module: &[u8], enable: bool) -> bool {
        let accepted = self
            .memory
            .traceable_modules
            .iter()
            .any(|name| name.as_bytes().eq_ignore_ascii_case(module));
        if accepted {
            self.memory.traced_modules.push((module.to_vec(), enable));
        }
        accepted
    }

    fn tracking_flags(&mut self) -> TrackingFlags {
        self.memory.tracking_flags
    }

    fn set_tracking_flags(&mut self, flags: TrackingFlags) {
        self.memory.tracking_flags = flags;
    }

    fn write_tracking_records(&mut self, file: filesystem::FileHandle) -> Result<(), KernelError> {
        let records = self.memory.tracking_records.clone();
        for record in &records {
            self.write_file(file, None, filesystem::FileData::Bytes(record))?;
        }
        Ok(())
    }

    /// The kernel table entries the simulated console produces.
    fn dos_error_from_nt_status(&mut self, error: KernelError) -> Option<Win32Error> {
        let code = match error {
            KernelError::AccessDenied => 5,
            KernelError::ObjectNameInvalid => 123,
            KernelError::NoSuchFile | KernelError::ObjectNameNotFound => 2,
            KernelError::ObjectPathNotFound => 3,
            KernelError::DiskFull => 112,
            _ => 317,
        };
        Win32Error::new(code)
    }

    fn detour(&mut self, operation: &mut dyn FnMut(&engine::Engine, &dyn engine::Platform)) {
        self.detour_operation(operation);
    }

    fn start_detour_log(&mut self, log: Option<&[u8]>) -> Result<(), KernelError> {
        self.start_detour_writer(log)
    }

    fn stop_detour_log(&mut self, log: Option<&[u8]>) {
        self.stop_detour_writer(log);
    }

    fn read_detour_record(&mut self, output: &mut [u8; engine::RECORD_SIZE]) -> bool {
        self.read_detour_log(output)
    }
}
