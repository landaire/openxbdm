//! Kernel debugger routing (`kd`, `kdlite`, `kdnet`), debugger extension
//! modules (`dbgextld`), and the `threadstat` handle parameter.

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use super::ExtensionHandle;
use super::HARDWARE_KD_ENABLED;
use super::HARDWARE_KD_LITE;
use super::context::strtoul;
use super::events;
use crate::backend::Backend as AnyBackend;
use crate::commands::console::ConfigSetting;
use crate::invocation::Invocation;
use crate::state::ServerState;
use crate::text::Text;

/// Offset of the kdnet settings record in the raw flash device.
pub const KDNET_RECORD_OFFSET: u32 = 0x80;
pub const KDNET_RECORD_SIZE: usize = 0x80;
const KDNET_SIGNATURE: u16 = 0xca4a;
/// Facility bit the monitor ORs into flash read and write results.
const FLASH_RESULT_BIT: u32 = 0x1000_0000;
const BAD_PARAMETER: Hresult = Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
/// Console configuration value of the kd lite flag.
const KD_LITE_SETTING: ConfigSetting = ConfigSetting::new(2, 6);
const KD_LITE_BIT: u32 = 0x2;
/// Console configuration value of the console MAC address.
const MAC_SETTING: ConfigSetting = ConfigSetting::new(2, 1);
const EXTENSION_DIRECTORY: &[u8] = b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\DMEXT\\";
/// Characters kept of an extension path.
const EXTENSION_PATH_LIMIT: usize = 0x6b;
pub const EXTENSION_NAME_CAPACITY: usize = 0x3f;

/// The loaded debugger extension.
#[derive(Debug, Clone)]
pub struct Extension {
    pub name: Text<EXTENSION_NAME_CAPACITY>,
    pub handle: ExtensionHandle,
    pub references: u32,
}

fn improper(invocation: &mut Invocation<'_>) -> Hresult {
    invocation.set_text(format_args!("improper command"));
    Hresult::FAIL
}

/// `kd enable|disable|except|exceptif`.
pub(super) fn kernel_debugger(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    if line.has("enable") {
        invocation.state.debugger.kernel_debugger = Some(true);
        invocation.set_text(format_args!("kd enabled"));
        return Hresult::OK;
    }
    if line.has("disable") {
        invocation.state.debugger.kernel_debugger = Some(false);
        invocation.set_text(format_args!("kd disabled"));
        return Hresult::OK;
    }
    let except = if line.has("except") {
        true
    } else if line.has("exceptif") {
        invocation.backend.hardware_flags() & HARDWARE_KD_ENABLED != 0
    } else {
        return improper(invocation);
    };
    if except {
        invocation.state.debugger.kernel_debugger = Some(true);
        events::release_all(invocation.state, invocation.backend, invocation.network);
    }
    Hresult::OK
}

/// `kdlite enable|disable`.
pub(super) fn kernel_debugger_lite(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.backend.hardware_flags() & HARDWARE_KD_LITE == 0 {
        return improper(invocation);
    }
    let enable = if invocation.line.has("enable") {
        true
    } else if invocation.line.has("disable") {
        false
    } else {
        return improper(invocation);
    };
    let mut value = [0u8; 4];
    if invocation
        .backend
        .xconfig_get(KD_LITE_SETTING, &mut value)
        .is_err()
    {
        return improper(invocation);
    }
    let mut flags = u32::from_be_bytes(value);
    if enable {
        flags |= KD_LITE_BIT;
    } else {
        flags &= !KD_LITE_BIT;
    }
    if invocation
        .backend
        .xconfig_set(KD_LITE_SETTING, &flags.to_be_bytes())
        .is_err()
    {
        return improper(invocation);
    }
    invocation.state.debugger.kd_lite = enable;
    invocation.set_text(format_args!(
        "kd lite {}",
        if enable { "enabled" } else { "disabled" }
    ));
    Hresult::OK
}

/// The kdnet settings record.
struct KdnetRecord([u8; KDNET_RECORD_SIZE]);

impl KdnetRecord {
    const ENABLE: usize = 0x10;
    const TARGET_IP: usize = 0x14;
    const TARGET_MAC: usize = 0x18;
    const HOST_PORT: usize = 0x1e;
    const HOST_IP: usize = 0x20;
    const ENCRYPTED: usize = 0x24;

    fn word(&self, offset: usize) -> u32 {
        u32::from_be_bytes([
            self.0[offset],
            self.0[offset + 1],
            self.0[offset + 2],
            self.0[offset + 3],
        ])
    }

    fn set_word(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn port(&self) -> u16 {
        u16::from_be_bytes([self.0[Self::HOST_PORT], self.0[Self::HOST_PORT + 1]])
    }

    fn mac(&self) -> &[u8] {
        &self.0[Self::TARGET_MAC..Self::TARGET_MAC + 6]
    }

    fn is_valid(&self) -> bool {
        self.word(Self::HOST_IP) != 0
            && self.mac().iter().any(|&byte| byte != 0)
            && self.port() != 0
    }
}

fn flash_result(result: Result<(), NtStatus>) -> u32 {
    match result {
        Ok(()) => FLASH_RESULT_BIT,
        Err(status) => status.0 | FLASH_RESULT_BIT,
    }
}

const fn is_failure(status: u32) -> bool {
    (status as i32) < 0
}

/// `kdnet enable|disable|show|set [IP=] [Port=] [Mac=]`.
pub(super) fn kernel_debugger_network(invocation: &mut Invocation<'_>) -> Hresult {
    let build = invocation.backend.kernel_build();
    if build < 10914 || (11000..12902).contains(&build) {
        invocation
            .text
            .set_bytes(b"kdnet is not supported on this flash version.\x1e");
        return Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND);
    }
    let mut record = KdnetRecord([0; KDNET_RECORD_SIZE]);
    let load = flash_result(
        invocation
            .backend
            .read_flash(KDNET_RECORD_OFFSET, &mut record.0),
    );
    let line = invocation.line;
    if line.has("enable") || line.has("disable") {
        let enable = line.has("enable");
        if is_failure(load) {
            invocation.set_text(format_args!(
                "kdnet: unable to load current kdnet settings: 0x{load:08x}"
            ));
            return Hresult::OK;
        }
        if enable && !record.is_valid() {
            invocation.set_text(format_args!(
                "kdnet: can't enable kdnet without setting the parameters."
            ));
            return Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND);
        }
        record.set_word(KdnetRecord::ENABLE, u32::from(enable));
        let save = flash_result(
            invocation
                .backend
                .write_flash(KDNET_RECORD_OFFSET, &record.0),
        );
        invocation.set_text(format_args!(
            "kdnet {}: 0x{save:08x}",
            if enable { "enabled" } else { "disabled" }
        ));
        return Hresult::OK;
    }
    if line.has("show") {
        if is_failure(load) {
            invocation.set_text(format_args!(
                "kdnet: failed to load current settings: 0x{load:08X}"
            ));
            return Hresult::OK;
        }
        let r = &record.0;
        let t = KdnetRecord::TARGET_IP;
        let m = KdnetRecord::TARGET_MAC;
        let h = KdnetRecord::HOST_IP;
        invocation.set_text(format_args!(
            "kdnet settings:\x1e\tEnable={}\x1e\tTarget IP: {}.{}.{}.{}\x1e\tTarget MAC: {:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}\x1e\tHost IP: {}.{}.{}.{}\x1e\tHost Port: {}\x1e\tEncrypted: {}\x1e",
            record.word(KdnetRecord::ENABLE) as i32,
            r[t],
            r[t + 1],
            r[t + 2],
            r[t + 3],
            r[m],
            r[m + 1],
            r[m + 2],
            r[m + 3],
            r[m + 4],
            r[m + 5],
            r[h],
            r[h + 1],
            r[h + 2],
            r[h + 3],
            record.port(),
            record.word(KdnetRecord::ENCRYPTED) as i32,
        ));
        return Hresult::OK;
    }
    if line.has("set") {
        let error = kdnet_set(invocation, &mut record);
        return match error {
            None => {
                invocation.set_text(format_args!("kdnet set succeeded."));
                Hresult::OK
            }
            Some(error) => {
                invocation.set_text(format_args!("kdnet set failed: error code 0x{error:08x}"));
                if error == BAD_PARAMETER.0 {
                    BAD_PARAMETER
                } else {
                    Hresult::FAIL
                }
            }
        };
    }
    BAD_PARAMETER
}

/// Apply the `set` parameters and save; returns the error value.
fn kdnet_set(invocation: &mut Invocation<'_>, record: &mut KdnetRecord) -> Option<u32> {
    let line = invocation.line;
    record.0[0..2].copy_from_slice(&KDNET_SIGNATURE.to_be_bytes());
    record.set_word(8, 0x10);
    record.set_word(0xc, 0x48);
    record.set_word(KdnetRecord::ENABLE, 1);
    let mut error = None;
    let mut supplied = false;
    if let Some(value) = line.param("IP") {
        supplied = true;
        let mut buffer = [0u8; 0x20];
        match inet_addr(value.copy_into(&mut buffer)) {
            Some(address) => {
                record.0[KdnetRecord::HOST_IP..KdnetRecord::HOST_IP + 4].copy_from_slice(&address)
            }
            None => error = Some(BAD_PARAMETER.0),
        }
    }
    if line.has("Port") {
        supplied = true;
        match line.dword("Port").filter(|&port| port <= 0xffff) {
            Some(port) => record.0[KdnetRecord::HOST_PORT..KdnetRecord::HOST_PORT + 2]
                .copy_from_slice(&(port as u16).to_be_bytes()),
            None => error = Some(BAD_PARAMETER.0),
        }
    }
    let mac = line.param("Mac");
    let mut default_mac = false;
    match mac {
        Some(value) => {
            supplied = true;
            let mut buffer = [0u8; 0x20];
            let text = value.copy_into(&mut buffer);
            if text.is_empty() {
                default_mac = true;
            } else if let Some(failed) = parse_mac(
                text,
                &mut record.0[KdnetRecord::TARGET_MAC..KdnetRecord::TARGET_MAC + 6],
            ) {
                if failed {
                    error = Some(BAD_PARAMETER.0);
                }
            } else {
                error = Some(BAD_PARAMETER.0);
            }
        }
        None => default_mac = record.mac().iter().all(|&byte| byte == 0),
    }
    if default_mac {
        let mut console_mac = [0u8; 6];
        match invocation
            .backend
            .xconfig_get(MAC_SETTING, &mut console_mac)
        {
            Ok(_) => {
                console_mac[5] = console_mac[5].wrapping_sub(1);
                record.0[KdnetRecord::TARGET_MAC..KdnetRecord::TARGET_MAC + 6]
                    .copy_from_slice(&console_mac);
            }
            Err(status) => error = Some(status.0 | FLASH_RESULT_BIT),
        }
    }
    if !supplied || !record.is_valid() {
        error = Some(BAD_PARAMETER.0);
    }
    if error.is_some() {
        return error;
    }
    let save = flash_result(
        invocation
            .backend
            .write_flash(KDNET_RECORD_OFFSET, &record.0),
    );
    is_failure(save).then_some(save)
}

/// Six `-`-separated hex octets. Returns `None` for fewer than six parts,
/// else whether any octet had trailing characters or exceeded 0xff (the low
/// byte is stored anyway).
fn parse_mac(text: &[u8], out: &mut [u8]) -> Option<bool> {
    let mut parts = text.split(|&byte| byte == b'-');
    let mut failed = false;
    for slot in out.iter_mut() {
        let part = parts.next()?;
        let mut value: u32 = 0;
        let mut consumed = 0;
        for &byte in part {
            let Some(digit) = (byte as char).to_digit(16) else {
                break;
            };
            value = value.wrapping_mul(16).wrapping_add(digit);
            consumed += 1;
        }
        if consumed != part.len() || value > 0xff {
            failed = true;
        }
        *slot = value as u8;
    }
    Some(failed)
}

/// BSD `inet_addr`: one to four parts with C base-0 numbers. `None` for
/// malformed text and for 255.255.255.255, which it cannot distinguish.
fn inet_addr(text: &[u8]) -> Option<[u8; 4]> {
    let mut parts = [0u32; 4];
    let mut count = 0;
    let mut position = 0;
    loop {
        let rest = &text[position..];
        if !rest.first().is_some_and(u8::is_ascii_digit) || count == 4 {
            return None;
        }
        let (value, consumed) = strtoul(rest);
        parts[count] = value;
        count += 1;
        position += consumed;
        match text.get(position) {
            Some(b'.') => position += 1,
            None => break,
            Some(byte) if byte.is_ascii_whitespace() => break,
            Some(_) => return None,
        }
    }
    let value = match count {
        1 => parts[0],
        2 if parts[0] <= 0xff && parts[1] <= 0xff_ffff => parts[0] << 24 | parts[1],
        3 if parts[0] <= 0xff && parts[1] <= 0xff && parts[2] <= 0xffff => {
            parts[0] << 24 | parts[1] << 16 | parts[2]
        }
        4 if parts.iter().all(|&part| part <= 0xff) => {
            parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]
        }
        _ => return None,
    };
    (value != u32::MAX).then_some(value.to_be_bytes())
}

/// Load the extension `name` from the DMEXT directory, or count another
/// reference to the loaded one (stock export 178, 0x91f2e5e0). Only one
/// extension can be loaded; another name fails with 0x82da002b.
pub fn load_extension(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
) -> Result<ExtensionHandle, Hresult> {
    if let Some(extension) = state.debugger.extension.as_mut() {
        if !extension.name.as_bytes().eq_ignore_ascii_case(name) {
            return Err(Hresult::error(0x2b));
        }
        extension.references += 1;
        return Ok(extension.handle);
    }
    let mut path = Text::<EXTENSION_PATH_LIMIT>::new();
    let _ = path.push_bytes(EXTENSION_DIRECTORY);
    let _ = path.push_bytes(name);
    let handle = backend
        .load_extension(path.as_bytes())
        .map_err(|status| Hresult::from_nt_status(status, Hresult::FAIL))?;
    let mut stored = Text::new();
    stored.set_bytes(name);
    state.debugger.extension = Some(Extension {
        name: stored,
        handle,
        references: 1,
    });
    Ok(handle)
}

/// Drop a reference to the loaded extension, unloading it with the last
/// (stock export 179, 0x91f2e6e0).
pub fn release_extension(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    handle: ExtensionHandle,
) -> Hresult {
    let Some(extension) = state
        .debugger
        .extension
        .as_mut()
        .filter(|extension| extension.handle == handle)
    else {
        return BAD_PARAMETER;
    };
    extension.references -= 1;
    if extension.references != 0 {
        return Hresult::OK;
    }
    state.debugger.extension = None;
    match backend.unload_extension(handle) {
        Ok(()) => Hresult::OK,
        Err(status) => Hresult::from_nt_status(status, Hresult::FAIL),
    }
}

/// `dbgextld name=` or `dbgextld unload module=`.
pub(super) fn debugger_extension(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    if line.has("unload") {
        let Some(module) = line.dword("module") else {
            invocation.set_text(format_args!("missing module"));
            return BAD_PARAMETER;
        };
        return release_extension(
            invocation.state,
            invocation.backend,
            ExtensionHandle(module),
        );
    }
    let Some(value) = line.param("name") else {
        invocation.set_text(format_args!("missing name"));
        return BAD_PARAMETER;
    };
    let mut buffer = [0u8; EXTENSION_NAME_CAPACITY + 1];
    let name = value.copy_into(&mut buffer);
    match load_extension(invocation.state, invocation.backend, name) {
        Ok(handle) => {
            invocation.set_text(format_args!("module=0x{:08x}", handle.0));
            Hresult::OK
        }
        Err(result) => result,
    }
}

/// The number after a `name` token, as the monitor reads it: located like a
/// flag (so `name` and `name=` both match) and parsed with C `strtoul`
/// base 0 from the byte after the key. A bare token is followed by its
/// delimiter, so parsing continues into the next token.
pub(super) fn flag_number(line: &CommandLine<'_>, buffer: &[u8], name: &str) -> Option<u32> {
    if !line.has(name) {
        return None;
    }
    let end = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    let bytes = &buffer[..end];
    let key = name.as_bytes();
    let separator = |byte: u8| matches!(byte, b' ' | b'\r' | 0);
    let mut position = bytes
        .iter()
        .position(|&byte| separator(byte))
        .unwrap_or(bytes.len());
    let mut quoted = false;
    while position < bytes.len() {
        while position < bytes.len() && separator(bytes[position]) {
            position += 1;
        }
        let start = position;
        while position < bytes.len() && !separator(bytes[position]) && bytes[position] != b'=' {
            position += 1;
        }
        if bytes[start..position].eq_ignore_ascii_case(key) && !quoted {
            let value = bytes.get(position + 1..).unwrap_or_default();
            return Some(strtoul(value).0);
        }
        while position < bytes.len() && (quoted || !separator(bytes[position])) {
            if bytes[position] == b'"' {
                quoted = !quoted;
            }
            position += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_addr_forms() {
        assert_eq!(inet_addr(b"10.0.0.2"), Some([10, 0, 0, 2]));
        assert_eq!(inet_addr(b"0x0a.1"), Some([10, 0, 0, 1]));
        assert_eq!(inet_addr(b"167772162"), Some([10, 0, 0, 2]));
        assert_eq!(inet_addr(b"255.255.255.255"), None);
        assert_eq!(inet_addr(b"1.2.3.256"), None);
        assert_eq!(inet_addr(b"1.2.x"), None);
    }

    #[test]
    fn mac_parts_store_low_bytes() {
        let mut out = [0u8; 6];
        assert_eq!(parse_mac(b"00-11-22-33-44-55", &mut out), Some(false));
        assert_eq!(out, [0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(parse_mac(b"00-11-22-33-44-1ff", &mut out), Some(true));
        assert_eq!(out[5], 0xff);
        assert_eq!(parse_mac(b"00-11-22", &mut out), None);
    }

    #[test]
    fn flag_number_reads_after_key() {
        let check = |text: &[u8]| flag_number(&CommandLine::new(text), text, "handle");
        assert_eq!(check(b"threadstat handle=0x10"), Some(0x10));
        assert_eq!(check(b"threadstat handle 0x10"), Some(0x10));
        assert_eq!(check(b"threadstat HANDLE=010"), Some(8));
        assert_eq!(check(b"threadstat handle"), Some(0));
        assert_eq!(check(b"threadstat"), None);
    }
}
