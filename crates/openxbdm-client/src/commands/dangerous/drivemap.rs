//! Runtime toggle for `drivemap internal=1`.
//!
//! xbdm's ini parser copies the literal `drivemap internal=1` value into
//! a single global word; the init continuation reads it and, if set,
//! calls `sub_91f2ecb0` which registers the full set of internal-drive
//! symbolic links (FLASH:, HDDSYSEXT:, HDDSYSAUX:, INTUSB:, INTMMC:,
//! HDDVD:, plus a long tail). We can reproduce the runtime effect
//! without touching flash by:
//!
//! 1. Locating that function and the flag global through structural
//!    signatures anchored on stable string literals.
//! 2. Borrowing a low-stakes command-table handler pointer (`altaddr`
//!    by default), swapping it to point at the drivemap function, and
//!    invoking the command. xbdm jumps to drivemap-setup, runs the full
//!    symlink registration chain, and returns.
//! 3. Immediately restoring the original handler.
//! 4. Setting the flag global so later runtime checks take the
//!    "internal drives enabled" branch as well.
//!
//! Every step is guarded: each discovery is cross-checked two ways, the
//! patch is reversed even on error, and the result is verified by
//! observing that `drivelist` now returns at least one of the newly
//! registered names.

use core::future::Future;
use std::time::Duration;

use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;

use crate::client::Client;
use crate::client::Connected;
use crate::commands::FileUploadKind;
use crate::commands::ModuleInfo;
use crate::commands::Modules;
pub use crate::commands::dangerous::DrivemapError;
use crate::commands::dangerous::pe::PeLayout;
use crate::commands::dangerous::pe::Section;
use crate::commands::dangerous::pe::read_layout;
use crate::commands::dangerous::ppc::addi_operands;
use crate::commands::dangerous::ppc::address_halves;
use crate::commands::dangerous::ppc::as_addi;
use crate::commands::dangerous::ppc::as_li;
use crate::commands::dangerous::ppc::as_lis;
use crate::commands::dangerous::ppc::combine_halves;
use crate::commands::dangerous::ppc::decode;
use crate::commands::dangerous::ppc::is_mflr_r12;
use crate::commands::dangerous::ppc::lis_operands;
use crate::commands::dangerous::sigscan::find_bytes_all;
use crate::commands::dangerous::sigscan::find_cstr;
use crate::commands::dangerous::sigscan::read;
use crate::commands::dangerous::sigscan::read_u32_be;
use crate::commands::dangerous::sigscan::write_u32_be;
use crate::commands::info::DriveList;
use crate::error::Error;

#[derive(Debug, Clone)]
pub struct XbdmLayout {
    pub module: ModuleInfo,
    pub pe: PeLayout,
    pub drivemap_fn: u32,
    pub flag_global: u32,
    pub altaddr_entry: AltaddrEntry,
}

#[derive(Debug, Clone, Copy)]
pub struct AltaddrEntry {
    /// Address of the `name_ptr` field of the dispatch-table entry.
    pub name_ptr_addr: u32,
    /// Address of the `handler_ptr` field (entry + 8 bytes).
    pub handler_ptr_addr: u32,
    /// Currently-installed handler (read during discovery).
    pub current_handler: u32,
}

#[derive(Debug, Clone)]
pub struct DrivemapStatus {
    pub layout: XbdmLayout,
    pub flag_value: u32,
    pub visible_drives: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DrivemapEnableReport {
    pub layout: XbdmLayout,
    pub drives_before: Vec<String>,
    pub drives_after: Vec<String>,
    /// `true` if `flag_global` was already set when `enable` ran, so
    /// the hijack was skipped as a no-op to avoid re-registering
    /// symlinks that xbdm's setup routine may not tolerate.
    pub already_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DrivemapPersistReport {
    pub path: String,
    pub bytes_written: u64,
}

/// Walk xbdm's PE, locate the drivemap function, flag global, and
/// altaddr dispatch entry. All three are found by structural signatures
/// anchored on stable string literals; addresses differ across builds
/// but the shapes don't.
pub async fn discover<T>(
    client: &mut Client<T, Connected>,
) -> Result<XbdmLayout, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let modules = client.run(Modules).await?;
    let module = modules
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case("xbdm.xex"))
        .ok_or_else(|| rootcause::Report::new(Error::from(DrivemapError::XbdmModuleMissing)))?;

    let pe = read_layout(client, module.base).await?;

    let text = pe.section(".text").cloned().ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".text")))
    })?;
    let rdata = pe.section(".rdata").cloned().ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".rdata")))
    })?;
    let data = pe.section(".data").cloned().ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".data")))
    })?;

    let rdata_bytes = read(client, rdata.address(pe.module_base), rdata.virtual_size).await?;
    let text_bytes = read(client, text.address(pe.module_base), text.virtual_size).await?;
    let data_bytes = read(client, data.address(pe.module_base), data.virtual_size).await?;

    let drivemap_fn = locate_drivemap_fn(&pe, &rdata, &rdata_bytes, &text, &text_bytes)?;
    let flag_global = locate_flag_global(&pe, &rdata, &rdata_bytes, &data, &text_bytes)?;
    let altaddr_entry = locate_altaddr_entry(&pe, &rdata, &rdata_bytes, &text, &data, &data_bytes)?;

    Ok(XbdmLayout {
        module,
        pe,
        drivemap_fn,
        flag_global,
        altaddr_entry,
    })
}

/// Locate the drivemap-setup function via its first call shape. We
/// anchor on `"DEVICE"` and `"\Device"` (two stable literals whose
/// addresses we compute from the .rdata dump) and walk .text looking
/// for two `lis` / `addi` pairs that load both, followed by `li r5, 0`
/// and a `bl`. Having found that shape, we walk back to the nearest
/// `mflr r12` -- that's the function prologue.
fn locate_drivemap_fn(
    pe: &PeLayout,
    rdata: &Section,
    rdata_bytes: &[u8],
    text: &Section,
    text_bytes: &[u8],
) -> Result<u32, rootcause::Report<Error>> {
    let dev_off = find_cstr(rdata_bytes, "DEVICE").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::DrivemapFunctionNotFound))
            .attach("literal \"DEVICE\" not found in xbdm .rdata")
    })?;
    let ntdev_off = find_cstr(rdata_bytes, "\\Device").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::DrivemapFunctionNotFound))
            .attach("literal \"\\Device\" not found in xbdm .rdata")
    })?;
    let dev_addr = rdata.address(pe.module_base).wrapping_add(dev_off as u32);
    let ntdev_addr = rdata.address(pe.module_base).wrapping_add(ntdev_off as u32);

    let (dev_hi, dev_lo) = address_halves(dev_addr);
    let (ntdev_hi, ntdev_lo) = address_halves(ntdev_addr);

    let text_base = text.address(pe.module_base);
    let call_site = (0..text_bytes.len().saturating_sub(24))
        .step_by(4)
        .find(|&offset| {
            is_drivemap_call_site(&text_bytes[offset..], dev_hi, dev_lo, ntdev_hi, ntdev_lo)
        });
    let Some(call_site) = call_site else {
        return Err(rootcause::Report::new(Error::from(
            DrivemapError::DrivemapFunctionNotFound,
        )));
    };

    let Some(prologue) = find_prologue(text_bytes, call_site) else {
        let call_site_addr = text_base.wrapping_add(call_site as u32);
        return Err(
            rootcause::Report::new(Error::from(DrivemapError::DrivemapPrologueMismatch)).attach(
                format!(
                    "signature at {call_site_addr:#010x} but no prologue within 64 bytes before"
                ),
            ),
        );
    };

    Ok(text_base.wrapping_add(prologue as u32))
}

fn is_drivemap_call_site(
    window: &[u8],
    dev_hi: u16,
    dev_lo: i16,
    ntdev_hi: u16,
    ntdev_lo: i16,
) -> bool {
    if window.len() < 24 {
        return false;
    }

    let instruction_at = |offset: usize| {
        decode(u32::from_be_bytes(
            window[offset..offset + 4].try_into().unwrap(),
        ))
    };
    let lis1 = instruction_at(0);
    let lis2 = instruction_at(4);
    let addi1 = instruction_at(8);
    let addi2 = instruction_at(12);
    let li5 = instruction_at(16);
    let bl = instruction_at(20);

    // In this xbdm the two strings share an upper half (0x91f0), so
    // both `lis` may target either string's upper half.
    let lis_rt1 = [dev_hi, ntdev_hi].iter().find_map(|&hi| as_lis(&lis1, hi));
    let lis_rt2 = [dev_hi, ntdev_hi].iter().find_map(|&hi| as_lis(&lis2, hi));
    let (Some(rt1), Some(rt2)) = (lis_rt1, lis_rt2) else {
        return false;
    };

    // Each `addi` must add one string's low half to one of the two
    // `lis` destinations, and together they must cover both strings.
    let lo_a = match_addi_to_string(&addi1, rt1, rt2, dev_lo, ntdev_lo);
    let lo_b = match_addi_to_string(&addi2, rt1, rt2, dev_lo, ntdev_lo);
    let (Some(lo_a), Some(lo_b)) = (lo_a, lo_b) else {
        return false;
    };

    let mut matched = [lo_a, lo_b];
    matched.sort();
    let mut expected = [dev_lo, ntdev_lo];
    expected.sort();
    if matched != expected {
        return false;
    }

    // `li r5, 0` sets the third argument (flags = 0).
    if as_li(&li5, 0) != Some(5) {
        return false;
    }

    matches!(bl.op, powerpc::Opcode::B) && bl.code & 1 == 1
}

/// If `ins` is `addi _, ra, simm` with `ra` one of `rt1`, `rt2` and
/// `simm` one of `dev_lo`, `ntdev_lo`, return the `simm` matched.
fn match_addi_to_string(
    ins: &powerpc::Ins,
    rt1: u8,
    rt2: u8,
    dev_lo: i16,
    ntdev_lo: i16,
) -> Option<i16> {
    [dev_lo, ntdev_lo]
        .into_iter()
        .find(|&candidate| as_addi(ins, candidate).is_some_and(|(_, ra)| ra == rt1 || ra == rt2))
}

/// Search up to 64 bytes before the call site for `mflr r12`.
fn find_prologue(text_bytes: &[u8], call_site_byte_off: usize) -> Option<usize> {
    let start = call_site_byte_off.saturating_sub(64);

    (start..call_site_byte_off)
        .step_by(4)
        .rev()
        .find(|&offset| {
            let word = u32::from_be_bytes(text_bytes[offset..offset + 4].try_into().unwrap());
            is_mflr_r12(&decode(word))
        })
}

/// Locate the drivemap internal flag global. The ini parser
/// `sub_91f30d70` contains a call pattern roughly like
/// `sub_91f40eb0(arg1, "internal", &drivemap_flag, ...)`. We anchor on
/// `"internal\0"` in .rdata, find any instruction sequence in .text
/// that loads `"internal"`'s address into a register, and interpret the
/// next `lis`/`addi` pair as loading the flag address. We then verify
/// by checking the address falls inside xbdm's `.data` range.
fn locate_flag_global(
    pe: &PeLayout,
    rdata: &Section,
    rdata_bytes: &[u8],
    data: &Section,
    text_bytes: &[u8],
) -> Result<u32, rootcause::Report<Error>> {
    const WINDOW_INSNS: usize = 16;

    let internal_off = find_cstr(rdata_bytes, "internal").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::DrivemapFlagNotFound))
            .attach("literal \"internal\" not found in xbdm .rdata")
    })?;
    let internal_addr = rdata
        .address(pe.module_base)
        .wrapping_add(internal_off as u32);
    let (_, internal_lo) = address_halves(internal_addr);

    let total_insns = text_bytes.len() / 4;
    let instruction_at = |idx: usize| {
        decode(u32::from_be_bytes(
            text_bytes[idx * 4..idx * 4 + 4].try_into().unwrap(),
        ))
    };

    // For every `addi` that completes a reference to "internal", pair
    // each other `addi` in a small window with the most recent `lis` of
    // its source register. The first combined address inside .data is
    // the flag.
    for anchor in 0..total_insns {
        if as_addi(&instruction_at(anchor), internal_lo).is_none() {
            continue;
        }

        let window_start = anchor.saturating_sub(WINDOW_INSNS);
        let window_end = (anchor + WINDOW_INSNS).min(total_insns);

        for candidate in window_start..window_end {
            if candidate == anchor {
                continue;
            }

            let Some((ra, lo_imm)) = addi_operands(&instruction_at(candidate)) else {
                continue;
            };

            let upper = (window_start..candidate).rev().find_map(|idx| {
                lis_operands(&instruction_at(idx))
                    .filter(|&(rt, _)| rt == ra)
                    .map(|(_, hi_imm)| hi_imm)
            });
            let Some(upper) = upper else {
                continue;
            };

            let flag_addr = combine_halves(upper, lo_imm);
            if flag_addr >= data.address(pe.module_base)
                && flag_addr < data.end(pe.module_base)
                && flag_addr != internal_addr
            {
                return Ok(flag_addr);
            }
        }
    }

    Err(rootcause::Report::new(Error::from(
        DrivemapError::DrivemapFlagNotFound,
    )))
}

/// Find the altaddr command-table entry by scanning .data for any
/// u32 big-endian that equals the "altaddr" string's address, then
/// verify the handler pointer eight bytes later falls inside .text.
fn locate_altaddr_entry(
    pe: &PeLayout,
    rdata: &Section,
    rdata_bytes: &[u8],
    text: &Section,
    data: &Section,
    data_bytes: &[u8],
) -> Result<AltaddrEntry, rootcause::Report<Error>> {
    let alt_off = find_cstr(rdata_bytes, "altaddr").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::AltaddrEntryNotFound))
            .attach("literal \"altaddr\" not found in xbdm .rdata")
    })?;
    let alt_addr = rdata.address(pe.module_base).wrapping_add(alt_off as u32);
    let needle = alt_addr.to_be_bytes();

    for offset in find_bytes_all(data_bytes, &needle, 4) {
        if offset + 12 > data_bytes.len() {
            continue;
        }

        let entry_addr = data.address(pe.module_base).wrapping_add(offset as u32);
        let handler_addr = entry_addr.wrapping_add(8);
        let handler = u32::from_be_bytes(data_bytes[offset + 8..offset + 12].try_into().unwrap());
        if handler >= text.address(pe.module_base) && handler < text.end(pe.module_base) {
            return Ok(AltaddrEntry {
                name_ptr_addr: entry_addr,
                handler_ptr_addr: handler_addr,
                current_handler: handler,
            });
        }
    }

    Err(rootcause::Report::new(Error::from(
        DrivemapError::AltaddrEntryNotFound,
    )))
}

/// Query the current state: is the flag set, what drives are currently
/// visible, where are the structural anchors.
pub async fn status<T>(
    client: &mut Client<T, Connected>,
) -> Result<DrivemapStatus, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let layout = discover(client).await?;
    let flag_value = read_u32_be(client, layout.flag_global).await?;
    let visible_drives = client.run(DriveList).await.unwrap_or_default();

    Ok(DrivemapStatus {
        layout,
        flag_value,
        visible_drives,
    })
}

/// The main event: swap altaddr's handler pointer to drivemap_fn,
/// invoke altaddr to drive the symlink registration, and restore.
///
/// The drivemap setup function isn't a real command handler, so the
/// response it leaves behind never terminates with `\r\n` and the
/// invoke socket wedges. We cap it with `invoke_timeout` and then
/// abandon that connection entirely. A fresh connection (supplied by
/// `reconnect`) handles the restore + flag-set, so a hung invoke can't
/// strand the console with altaddr pointing at drivemap_fn.
pub async fn enable<T, R, Fut>(
    mut hijack_client: Client<T, Connected>,
    reconnect: R,
    invoke_timeout: Duration,
) -> Result<DrivemapEnableReport, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
    R: FnOnce() -> Fut,
    Fut: Future<Output = Result<Client<T, Connected>, rootcause::Report<Error>>>,
{
    let layout = discover(&mut hijack_client).await?;
    let drives_before = hijack_client.run(DriveList).await.unwrap_or_default();

    // Short-circuit if the flag is already set. We don't know that
    // xbdm's setup routine is idempotent -- it calls ObCreateSymbolicLink
    // for every internal drive and the NT return for a duplicate is
    // STATUS_OBJECT_NAME_COLLISION. Re-running it is almost certainly
    // fine but not confirmed, so make double-invocation a no-op.
    let flag_value = read_u32_be(&mut hijack_client, layout.flag_global).await?;
    if flag_value != 0 {
        return Ok(DrivemapEnableReport {
            layout,
            drives_after: drives_before.clone(),
            drives_before,
            already_enabled: true,
        });
    }

    // The handler we're about to overwrite has to currently live inside
    // .text. If it doesn't, we're probably looking at a console that
    // was left in a broken state from a prior run and we'd just be
    // moving the damage around.
    let text = layout.pe.section(".text").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".text")))
    })?;
    if layout.altaddr_entry.current_handler < text.address(layout.pe.module_base)
        || layout.altaddr_entry.current_handler >= text.end(layout.pe.module_base)
    {
        return Err(rootcause::Report::new(Error::from(
            DrivemapError::AltaddrHandlerOutsideText {
                got: layout.altaddr_entry.current_handler,
            },
        )));
    }

    write_u32_be(
        &mut hijack_client,
        layout.altaddr_entry.handler_ptr_addr,
        layout.drivemap_fn,
    )
    .await?;

    // Fire altaddr. This is expected to hit the timeout: drivemap_fn
    // doesn't format a valid xbdm response, so we never see CRLF. The
    // symlink registration itself runs synchronously inside the
    // call, so by the time the timeout fires the drives are registered
    // regardless of what the response looks like.
    let _ = tokio::time::timeout(invoke_timeout, hijack_client.send_raw("altaddr")).await;
    drop(hijack_client);

    let mut restore_client = reconnect().await?;

    write_u32_be(
        &mut restore_client,
        layout.altaddr_entry.handler_ptr_addr,
        layout.altaddr_entry.current_handler,
    )
    .await?;

    let observed = read_u32_be(&mut restore_client, layout.altaddr_entry.handler_ptr_addr).await?;
    if observed != layout.altaddr_entry.current_handler {
        return Err(rootcause::Report::new(Error::from(
            DrivemapError::RestoreMismatch {
                expected: layout.altaddr_entry.current_handler,
                observed,
            },
        )));
    }

    write_u32_be(&mut restore_client, layout.flag_global, 1).await?;

    let drives_after = restore_client.run(DriveList).await.unwrap_or_default();

    Ok(DrivemapEnableReport {
        layout,
        drives_before,
        drives_after,
        already_enabled: false,
    })
}

/// Write `\SystemRoot\recint.ini` so that `drivemap internal=1` sticks
/// across reboots. Requires `enable` to have been run in the current
/// session (otherwise the path isn't reachable).
pub async fn persist<T>(
    client: &mut Client<T, Connected>,
) -> Result<DrivemapPersistReport, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const BODY: &[u8] = b"[xbdm]\r\ndrivemap internal=1\r\n";
    const PATH: &str = "FLASH:\\recint.ini";

    let upload = client
        .send_file(
            PATH,
            FileUploadKind::Create {
                size: BODY.len() as u32,
            },
        )
        .await?;
    upload.send_all(BODY).await?;

    Ok(DrivemapPersistReport {
        path: PATH.to_owned(),
        bytes_written: BODY.len() as u64,
    })
}
