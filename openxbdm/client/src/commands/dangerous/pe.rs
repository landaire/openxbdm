//! Tiny PE/COFF header reader for xbdm loaded in memory.
//!
//! xbdm.xex is an encrypted XEX on disk, but once the loader decrypts
//! and maps it, the in-memory image is a perfectly ordinary PE: `MZ`
//! DOS stub, `PE\0\0` signature, COFF header, optional header, section
//! table. We parse just enough to enumerate sections by name so that
//! signature scanners can operate on authoritative ranges rather than
//! guessing at text/data boundaries.

use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;

use crate::client::Client;
use crate::client::Connected;
pub use crate::commands::dangerous::PeError;
use crate::commands::dangerous::sigscan::read;
use crate::error::Error;

/// One section-table entry from the PE image.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Virtual address, relative to the module base.
    pub rva: u32,
    /// Virtual size as declared by the header.
    pub virtual_size: u32,
}

impl Section {
    pub fn address(&self, module_base: u32) -> u32 {
        module_base.wrapping_add(self.rva)
    }

    pub fn end(&self, module_base: u32) -> u32 {
        self.address(module_base).wrapping_add(self.virtual_size)
    }
}

/// Parsed PE layout for an xbdm module image in memory.
#[derive(Debug, Clone)]
pub struct PeLayout {
    pub module_base: u32,
    pub sections: Vec<Section>,
}

impl PeLayout {
    /// Locate a section by case-insensitive ASCII name (e.g. `.text`).
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.name.eq_ignore_ascii_case(name))
    }

    pub fn module_end(&self) -> u32 {
        // An image without sections ends where it starts.
        self.sections
            .iter()
            .map(|section| section.end(self.module_base))
            .max()
            .unwrap_or(self.module_base)
    }
}

/// Walk xbdm's in-memory PE and return its section layout. `base` is
/// the VA at which xbdm is loaded (e.g. `0x91f00000`).
pub async fn read_layout<T>(
    client: &mut Client<T, Connected>,
    base: u32,
) -> Result<PeLayout, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// POWERPCBE machine constant in the PE header. Xenon uses it even
    /// though the PPC variant is actually PPC64-BE-32; the kernel loads
    /// it as a 32-bit image.
    const IMAGE_FILE_MACHINE_POWERPCBE: u16 = 0x01F2;
    /// PE signature plus COFF header.
    const PE_HEADER_LEN: u32 = 24;
    const SECTION_ENTRY_LEN: usize = 40;

    let dos = read(client, base, 64).await?;
    if &dos[..2] != b"MZ" {
        return Err(
            rootcause::Report::new(Error::from(PeError::MissingDosSignature)).attach(format!(
                "read back bytes: {:02x?}",
                &dos[..16.min(dos.len())]
            )),
        );
    }

    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap());

    let pe_header = read(client, base.wrapping_add(e_lfanew), PE_HEADER_LEN).await?;
    if &pe_header[..4] != b"PE\0\0" {
        return Err(
            rootcause::Report::new(Error::from(PeError::MissingPeSignature)).attach(format!(
                "bytes at e_lfanew: {:02x?}",
                &pe_header[..16.min(pe_header.len())]
            )),
        );
    }

    let machine = u16::from_le_bytes(pe_header[4..6].try_into().unwrap());
    if machine != IMAGE_FILE_MACHINE_POWERPCBE {
        return Err(rootcause::Report::new(Error::from(
            PeError::UnexpectedMachine(machine),
        )));
    }

    let section_count = u16::from_le_bytes(pe_header[6..8].try_into().unwrap());
    if !(1..=64).contains(&section_count) {
        return Err(rootcause::Report::new(Error::from(
            PeError::AbsurdSectionCount(section_count),
        )));
    }

    let size_of_optional = u16::from_le_bytes(pe_header[20..22].try_into().unwrap());

    // The section table follows the optional header.
    let section_table_rva = e_lfanew
        .wrapping_add(PE_HEADER_LEN)
        .wrapping_add(size_of_optional as u32);
    let section_table_size = section_count as u32 * SECTION_ENTRY_LEN as u32;
    let raw = read(
        client,
        base.wrapping_add(section_table_rva),
        section_table_size,
    )
    .await?;

    let mut sections = Vec::with_capacity(section_count as usize);
    for entry in raw.as_chunks::<SECTION_ENTRY_LEN>().0 {
        let name_bytes = &entry[0..8];
        // A name of exactly eight bytes has no NUL terminator.
        let name_end = name_bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let virtual_size = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let rva = u32::from_le_bytes(entry[12..16].try_into().unwrap());

        sections.push(Section {
            name,
            rva,
            virtual_size,
        });
    }

    Ok(PeLayout {
        module_base: base,
        sections,
    })
}
