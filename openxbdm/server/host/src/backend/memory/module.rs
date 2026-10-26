//! Simulated loaded modules and their XEX header fields.

use openxbdm_server::commands::memory;
use openxbdm_server::commands::memory::CodeView;
use openxbdm_server::commands::memory::SectionInfo;
use xbox360_sys::image::XexHeaderKey;

use super::Mock;

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
    pub xex_fields: Vec<(XexHeaderKey, XexField)>,
}

impl Module {
    pub(super) fn units(&self) -> impl Iterator<Item = u16> + '_ {
        self.name.encode_utf16()
    }

    pub(super) fn field(&self, key: XexHeaderKey) -> Option<&XexField> {
        self.xex_fields
            .iter()
            .find(|(field, _)| *field == key)
            .map(|(_, value)| value)
    }
}

impl Mock {
    /// Modules in loader order: the primary list, then the secondary list.
    pub(super) fn loader_order(&self) -> impl Iterator<Item = &Module> {
        let primary = self
            .modules
            .iter()
            .filter(|module| module.list == ModuleList::Primary);
        let secondary = self
            .modules
            .iter()
            .filter(|module| module.list == ModuleList::Secondary);

        primary.chain(secondary)
    }

    pub(super) fn find(&self, name: &[u8]) -> Option<&Module> {
        self.loader_order()
            .find(|module| memory::module_name_matches(module.units(), name, true))
    }
}
