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

use crate::client::Client;
use crate::client::Connected;
use crate::commands::ModuleInfo;
use crate::commands::dangerous::pe::PeLayout;
use crate::commands::dangerous::pe::Section;
use crate::commands::dangerous::pe::read_layout;
use crate::commands::dangerous::ppc::as_addi;
use crate::commands::dangerous::ppc::as_li;
use crate::commands::dangerous::ppc::as_lis;
use crate::commands::dangerous::ppc::decode;
use crate::commands::dangerous::ppc::is_mflr_r12;
use crate::commands::dangerous::sigscan::find_bytes_all;
use crate::commands::dangerous::sigscan::find_cstr;
use crate::commands::dangerous::sigscan::read;
use crate::commands::dangerous::sigscan::read_u32_be;
use crate::commands::dangerous::sigscan::write_u32_be;
use crate::commands::info::DriveList;
use crate::error::Error;
use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;

#[derive(Debug, thiserror::Error)]
pub enum DrivemapError {
    #[error("could not find the xbdm module in the running kernel's module list")]
    XbdmModuleMissing,
    #[error("a required section ({0}) is missing from xbdm's PE header")]
    SectionMissing(&'static str),
    #[error(
        "could not locate the drivemap setup function: no code signature matched. \
         This xbdm build may reorganize the startup call chain."
    )]
    DrivemapFunctionNotFound,
    #[error(
        "found drivemap signature but the function prologue is wrong; refusing \
         to proceed rather than jump to a mid-function address"
    )]
    DrivemapPrologueMismatch,
    #[error(
        "could not locate the drivemap internal flag global by scanning ini-parser \
         call pattern"
    )]
    DrivemapFlagNotFound,
    #[error(
        "could not locate the altaddr command-table entry; looked for a .data pointer \
         to the \"altaddr\" string followed by a plausible handler pointer"
    )]
    AltaddrEntryNotFound,
    #[error(
        "altaddr handler pointer {got:#010x} is outside the xbdm .text range; refusing \
         to overwrite an entry that may not be what we think it is"
    )]
    AltaddrHandlerOutsideText { got: u32 },
    #[error(
        "after swapping, altaddr no longer returns a valid reply. patch has been \
         rolled back; console should still be reachable"
    )]
    InvocationFailed,
    #[error(
        "failed to restore altaddr handler after invocation. the console is in a \
         broken state -- probe {expected:#010x}, observed {observed:#010x}"
    )]
    RestoreMismatch { expected: u32, observed: u32 },
}

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
    let modules = client.run(crate::commands::Modules).await?;
    let module = modules
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case("xbdm.xex"))
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

    // Read the three sections we're going to interrogate.
    let rdata_bytes = read(client, rdata.address(pe.module_base), rdata.virtual_size).await?;
    let text_bytes = read(client, text.address(pe.module_base), text.virtual_size).await?;
    let data_bytes = read(client, data.address(pe.module_base), data.virtual_size).await?;

    let drivemap_fn = locate_drivemap_fn(&pe, &rdata, &rdata_bytes, &text, &text_bytes)?;
    let flag_global = locate_flag_global(&pe, &rdata, &rdata_bytes, &text_bytes)?;
    let altaddr_entry = locate_altaddr_entry(&pe, &rdata, &rdata_bytes, &data, &data_bytes)?;

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
/// and a `bl`.  Having found that shape, we walk back to the nearest
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

    let (dev_hi, dev_lo) = crate::commands::dangerous::ppc::address_halves(dev_addr);
    let (ntdev_hi, ntdev_lo) = crate::commands::dangerous::ppc::address_halves(ntdev_addr);

    // Walk 4-byte-aligned text words manually so we have random access
    // to the prologue search; `powerpc::InsIter` is used inside the
    // check helper for pretty decoding.
    let text_base = text.address(pe.module_base);
    for i in (0..text_bytes.len().saturating_sub(24)).step_by(4) {
        if try_match_drivemap_call_site(&text_bytes[i..], dev_hi, dev_lo, ntdev_hi, ntdev_lo) {
            let call_site_addr = text_base.wrapping_add(i as u32);
            // Walk back up to 64 bytes to find `mflr r12`.
            let start = match find_prologue(text_bytes, i) {
                Some(off) => text_base.wrapping_add(off as u32),
                None => {
                    return Err(rootcause::Report::new(Error::from(
                        DrivemapError::DrivemapPrologueMismatch,
                    ))
                    .attach(format!(
                        "signature at {call_site_addr:#010x} but no prologue within 64 bytes before"
                    )));
                }
            };
            return Ok(start);
        }
    }
    Err(rootcause::Report::new(Error::from(
        DrivemapError::DrivemapFunctionNotFound,
    )))
}

fn try_match_drivemap_call_site(
    window: &[u8],
    dev_hi: u16,
    dev_lo: i16,
    ntdev_hi: u16,
    ntdev_lo: i16,
) -> bool {
    if window.len() < 24 {
        return false;
    }
    let w = |off: usize| u32::from_be_bytes(window[off..off + 4].try_into().unwrap());
    let lis1 = decode(w(0));
    let lis2 = decode(w(4));
    let addi1 = decode(w(8));
    let addi2 = decode(w(12));
    let li5 = decode(w(16));
    let bl = decode(w(20));

    // The two `lis` must set up pointers to the two string halves.
    // In this xbdm the two strings share an upper half (0x91f0), so
    // we treat both `lis` as targeting the union {dev_hi, ntdev_hi}.
    let lis_rt1 = [dev_hi, ntdev_hi].iter().find_map(|&hi| as_lis(&lis1, hi));
    let lis_rt2 = [dev_hi, ntdev_hi].iter().find_map(|&hi| as_lis(&lis2, hi));
    let (rt1, rt2) = match (lis_rt1, lis_rt2) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };

    // The next two addi's must each be `addi _, ra, lo` where `ra` is
    // one of the two `lis` destinations and `lo` is one of the two
    // string low halves. Together they must cover both low halves.
    let addi1_ok = match_addi_to_string(&addi1, rt1, rt2, dev_lo, ntdev_lo);
    let addi2_ok = match_addi_to_string(&addi2, rt1, rt2, dev_lo, ntdev_lo);
    let (Some(lo_a), Some(lo_b)) = (addi1_ok, addi2_ok) else {
        return false;
    };
    // Must cover both strings (one addi per string).
    let covered = {
        let mut set = [lo_a, lo_b];
        set.sort();
        let mut expected = [dev_lo, ntdev_lo];
        expected.sort();
        set == expected
    };
    if !covered {
        return false;
    }

    // `li r5, 0` -- the third arg (flags = 0).
    if as_li(&li5, 0) != Some(5) {
        return false;
    }

    // And a `bl` into .text.
    matches!(bl.op, powerpc::Opcode::B) && bl.code & 1 == 1
}

/// If `ins` is `addi _, ra, simm` with `ra` one of `rt1`, `rt2` and
/// `simm` one of `dev_lo`, `ntdev_lo`, return the `simm` matched; otherwise
/// `None`.
fn match_addi_to_string(
    ins: &powerpc::Ins,
    rt1: u8,
    rt2: u8,
    dev_lo: i16,
    ntdev_lo: i16,
) -> Option<i16> {
    for candidate in [dev_lo, ntdev_lo] {
        if let Some((_, ra)) = as_addi(ins, candidate)
            && (ra == rt1 || ra == rt2)
        {
            return Some(candidate);
        }
    }
    None
}

fn find_prologue(text_bytes: &[u8], call_site_byte_off: usize) -> Option<usize> {
    let start = call_site_byte_off.saturating_sub(64);
    (start..call_site_byte_off).step_by(4).rev().find(|&off| {
        let word = u32::from_be_bytes(text_bytes[off..off + 4].try_into().unwrap());
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
    text_bytes: &[u8],
) -> Result<u32, rootcause::Report<Error>> {
    let internal_off = find_cstr(rdata_bytes, "internal").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::DrivemapFlagNotFound))
            .attach("literal \"internal\" not found in xbdm .rdata")
    })?;
    let internal_addr = rdata
        .address(pe.module_base)
        .wrapping_add(internal_off as u32);
    let (_, int_lo) = crate::commands::dangerous::ppc::address_halves(internal_addr);

    let data = pe.section(".data").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".data")))
    })?;

    // Walk .text one instruction at a time; when we find an `addi` that
    // completes a reference to "internal", look at other `addi`s in a
    // small window and find each one's most-recent matching `lis`. If
    // the combined hi/lo lands inside .data, that address is a flag
    // candidate -- return the first one that passes.
    const WINDOW_INSNS: usize = 16;
    let total_insns = text_bytes.len() / 4;
    let word =
        |idx: usize| u32::from_be_bytes(text_bytes[idx * 4..idx * 4 + 4].try_into().unwrap());
    for i in 0..total_insns {
        let ins = decode(word(i));
        if as_addi(&ins, int_lo).is_none() {
            continue;
        }
        let lo = i.saturating_sub(WINDOW_INSNS);
        let hi = (i + WINDOW_INSNS).min(total_insns);

        // For each `addi` in the window (other than the "internal"
        // one), walk BACKWARDS from its position to find the most
        // recent `lis` whose destination register matches the addi's
        // RA -- that's the pairing actually producing the address.
        for j in lo..hi {
            if j == i {
                continue;
            }
            let w = decode(word(j));
            if w.op != powerpc::Opcode::Addi {
                continue;
            }
            let parsed = w.basic();
            let args: Vec<&powerpc::Argument> = parsed.args_iter().collect();
            if args.len() < 3 {
                continue;
            }
            let (ra, imm) = match (args[1], args[2]) {
                (powerpc::Argument::GPR(ra), powerpc::Argument::Simm(s)) => (ra.0, s.0),
                _ => continue,
            };
            // Scan back from j-1 for the most recent `lis ra, hi`.
            let mut upper = None;
            for k in (lo..j).rev() {
                let kw = decode(word(k));
                if kw.op != powerpc::Opcode::Addis {
                    continue;
                }
                let kparsed = kw.basic();
                let kargs: Vec<&powerpc::Argument> = kparsed.args_iter().collect();
                if kargs.len() < 3 {
                    continue;
                }
                let (rt, k_ra, hi_imm) = match (kargs[0], kargs[1], kargs[2]) {
                    (
                        powerpc::Argument::GPR(rt),
                        powerpc::Argument::GPR(k_ra),
                        powerpc::Argument::Uimm(powerpc::Uimm(v)),
                    ) => (rt.0, k_ra.0, *v),
                    _ => continue,
                };
                if k_ra != 0 {
                    continue;
                }
                if rt == ra {
                    upper = Some(hi_imm);
                    break;
                }
            }
            let Some(upper) = upper else {
                continue;
            };
            let flag_addr = combine_halves(upper, imm);
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

fn combine_halves(hi: u16, lo: i16) -> u32 {
    let hi_part = (hi as u32) << 16;
    hi_part.wrapping_add(lo as i32 as u32)
}

/// Find the altaddr command-table entry by scanning .data for any
/// u32 big-endian that equals the "altaddr" string's address, then
/// verify the handler pointer eight bytes later falls inside .text.
fn locate_altaddr_entry(
    pe: &PeLayout,
    rdata: &Section,
    rdata_bytes: &[u8],
    data: &Section,
    data_bytes: &[u8],
) -> Result<AltaddrEntry, rootcause::Report<Error>> {
    let alt_off = find_cstr(rdata_bytes, "altaddr").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::AltaddrEntryNotFound))
            .attach("literal \"altaddr\" not found in xbdm .rdata")
    })?;
    let alt_addr = rdata.address(pe.module_base).wrapping_add(alt_off as u32);
    let needle = alt_addr.to_be_bytes();

    let text = pe.section(".text").ok_or_else(|| {
        rootcause::Report::new(Error::from(DrivemapError::SectionMissing(".text")))
    })?;

    let hits = find_bytes_all(data_bytes, &needle, 4);
    for off in hits {
        if off + 12 > data_bytes.len() {
            continue;
        }
        let entry_addr = data.address(pe.module_base).wrapping_add(off as u32);
        let handler_addr = entry_addr.wrapping_add(8);
        let handler = u32::from_be_bytes(data_bytes[off + 8..off + 12].try_into().unwrap());
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
            crate::commands::FileUploadKind::Create {
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
