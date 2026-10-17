//! Loaded module subcommands.

use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::GetMem;
use openxbdm_client::commands::ModuleSections;
use openxbdm_client::commands::Modules;
use openxbdm_client::commands::SectionFlags;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use tabled::Tabled;
use tokio::io::AsyncWriteExt;

use crate::ui::UiOptions;
use crate::ui::ok_tag;
use crate::ui::print_table;

/// Section permissions as `rwxu`, with `-` for each flag that is clear.
struct Permissions(SectionFlags);

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.0;
        for (set, letter) in [
            (flags.readable(), 'r'),
            (flags.writable(), 'w'),
            (flags.executable(), 'x'),
            (flags.uninitialized(), 'u'),
        ] {
            f.write_char(if set { letter } else { '-' })?;
        }

        Ok(())
    }
}

pub async fn modules<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let modules = client.run(Modules).await?;

    if !ui.is_pretty() {
        for module in modules {
            println!(
                "{}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{}\t{:#010x}",
                module.name,
                module.base,
                module.base.wrapping_add(module.size),
                module.size,
                module.checksum,
                module.is_dll,
                module.osize
            );
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        name: String,
        base: String,
        end: String,
        size: String,
        check: String,
        #[tabled(rename = "dll")]
        dll: &'static str,
        osize: String,
    }

    let rows: Vec<Row> = modules
        .iter()
        .map(|module| Row {
            name: module.name.clone(),
            base: format!("{:#010x}", module.base),
            end: format!("{:#010x}", module.base.wrapping_add(module.size)),
            size: format!("{:#010x}", module.size),
            check: format!("{:#010x}", module.checksum),
            dll: if module.is_dll { "yes" } else { "no" },
            osize: format!("{:#010x}", module.osize),
        })
        .collect();
    print_table(&ui.heading("modules"), rows);

    Ok(())
}

pub async fn dump_module<T>(
    client: &mut Client<T, Connected>,
    module: &str,
    output: &Path,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const CHUNK_LEN: u32 = 0x1000;

    let modules = client.run(Modules).await?;
    let Some(module_info) = modules
        .into_iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(module))
    else {
        return Err(Report::new(Error::ModuleNotFound {
            name: module.to_owned(),
        }));
    };

    if module_info.size == 0 {
        return Err(Report::new(Error::EmptyModule {
            name: module_info.name,
        }));
    }

    // Reject a range that wraps the address space before reading any of it.
    module_info
        .base
        .checked_add(module_info.size - 1)
        .ok_or_else(|| {
            Report::new(Error::ModuleRangeOverflow {
                base: module_info.base,
                size: module_info.size,
            })
        })?;

    let mut file = tokio::fs::File::create(output)
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating module dump {output:?}"))?;
    let bar = ui.progress(u64::from(module_info.size), "read");

    let mut offset = 0u32;
    while offset < module_info.size {
        let length = (module_info.size - offset).min(CHUNK_LEN);
        let address = module_info
            .base
            .checked_add(offset)
            .expect("module range was validated");

        let snapshot = client.run(GetMem { address, length }).await?;
        if let Some(relative) = snapshot.unmapped_offsets.first() {
            return Err(Report::new(Error::UnmappedModuleMemory {
                address: address + relative,
            }));
        }

        file.write_all(&snapshot.data)
            .await
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("writing module dump {output:?}"))?;
        offset += length;
        bar.set_position(u64::from(offset));
    }

    file.flush()
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("flushing module dump {output:?}"))?;
    bar.finish_and_clear();
    eprintln!(
        "{} {} bytes from {} at {:#010x}",
        ok_tag("dumped"),
        module_info.size,
        module_info.name,
        module_info.base
    );

    Ok(())
}

pub async fn module_sections<T>(
    client: &mut Client<T, Connected>,
    module: &str,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let sections = client
        .run(ModuleSections {
            module: module.to_owned(),
        })
        .await?;

    if !ui.is_pretty() {
        for section in sections {
            println!(
                "{}\t{:#010x}\t{:#010x}\t{}\t{:#x}\t{}",
                section.name,
                section.base,
                section.size,
                section.index,
                section.flags.0,
                Permissions(section.flags),
            );
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        name: String,
        base: String,
        size: String,
        idx: u32,
        flags: String,
        #[tabled(rename = "rwxu")]
        perms: String,
    }

    let rows: Vec<Row> = sections
        .iter()
        .map(|section| Row {
            name: section.name.clone(),
            base: format!("{:#010x}", section.base),
            size: format!("{:#010x}", section.size),
            idx: section.index,
            flags: format!("{:#x}", section.flags.0),
            perms: Permissions(section.flags).to_string(),
        })
        .collect();
    print_table(&ui.heading(&format!("modsections {module}")), rows);

    Ok(())
}
