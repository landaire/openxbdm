//! Kernel debugger routing (`kd`, `kdlite`, `kdnet`), debugger extension
//! modules (`dbgextld`), and the `threadstat` handle parameter.

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::XbdmHresult;

use super::ExtensionHandle;
use super::context::strtoul;
use super::events;
use crate::backend::Backend as AnyBackend;
use crate::commands::console::ConfigSetting;
use crate::commands::console::ConsoleConfigFlags;
use crate::commands::system::hardware_flags;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;
use xbox360_sys::xboxkrnl::HardwareFlags;

/// Offset of the kdnet settings record in the raw flash device.
pub const KDNET_RECORD_OFFSET: u32 = 0x80;
pub const KDNET_RECORD_SIZE: usize = 0x80;
const KDNET_SIGNATURE: u16 = 0xca4a;
/// Value of a successful flash access in the `kdnet` texts; a failure
/// prints its status as an NT-facility result.
const FLASH_SUCCESS: Hresult = Hresult::from_nt(NtStatus::SUCCESS);
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

fn improper(invocation: &mut Invocation<'_>) -> CommandResult {
    invocation.set_text(format_args!("improper command"));
    Err(CommandError::Fail)
}

/// `kd enable|disable|except|exceptif`.
pub(super) fn kernel_debugger(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    if line.has("enable") {
        invocation.state.debugger.kernel_debugger = Some(true);
        invocation.set_text(format_args!("kd enabled"));
        return Ok(Reply::Ok);
    }
    if line.has("disable") {
        invocation.state.debugger.kernel_debugger = Some(false);
        invocation.set_text(format_args!("kd disabled"));
        return Ok(Reply::Ok);
    }
    let except = if line.has("except") {
        true
    } else if line.has("exceptif") {
        hardware_flags(invocation.backend).contains(HardwareFlags::KERNEL_DEBUGGER_ENABLED)
    } else {
        return improper(invocation);
    };
    if except {
        invocation.state.debugger.kernel_debugger = Some(true);
        events::release_all(invocation.state, invocation.backend, invocation.network);
    }
    Ok(Reply::Ok)
}

/// `kdlite enable|disable`.
pub(super) fn kernel_debugger_lite(invocation: &mut Invocation<'_>) -> CommandResult {
    // Kd lite exists only on test kits.
    if !hardware_flags(invocation.backend).contains(HardwareFlags::TEST_KIT) {
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
        .xconfig_get(ConfigSetting::CONSOLE_FLAGS, &mut value)
        .is_err()
    {
        return improper(invocation);
    }
    let mut flags = ConsoleConfigFlags::from_bits_retain(u32::from_be_bytes(value));
    if enable {
        flags.insert(ConsoleConfigFlags::KD_LITE);
    } else {
        flags.remove(ConsoleConfigFlags::KD_LITE);
    }
    if invocation
        .backend
        .xconfig_set(ConfigSetting::CONSOLE_FLAGS, &flags.bits().to_be_bytes())
        .is_err()
    {
        return improper(invocation);
    }
    invocation.state.debugger.kd_lite = enable;
    invocation.set_text(format_args!(
        "kd lite {}",
        if enable { "enabled" } else { "disabled" }
    ));
    Ok(Reply::Ok)
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

/// A flash access result as the `kdnet` texts print it.
fn flash_code(result: Result<(), KernelError>) -> Hresult {
    match result {
        Ok(()) => FLASH_SUCCESS,
        Err(error) => Hresult::from(error),
    }
}

/// `kdnet enable|disable|show|set [IP=] [Port=] [Mac=]`.
pub(super) fn kernel_debugger_network(invocation: &mut Invocation<'_>) -> CommandResult {
    let build = invocation.backend.kernel_build();
    if build < 10914 || (11000..12902).contains(&build) {
        invocation
            .text
            .set_bytes(b"kdnet is not supported on this flash version.\x1e");
        return Err(ErrorCode::UnknownCommand.into());
    }
    let mut record = KdnetRecord([0; KDNET_RECORD_SIZE]);
    let load = invocation
        .backend
        .read_flash(KDNET_RECORD_OFFSET, &mut record.0);
    let line = invocation.line;
    if line.has("enable") || line.has("disable") {
        let enable = line.has("enable");
        if load.is_err() {
            invocation.set_text(format_args!(
                "kdnet: unable to load current kdnet settings: 0x{:08x}",
                flash_code(load).0
            ));
            return Ok(Reply::Ok);
        }
        if enable && !record.is_valid() {
            invocation.set_text(format_args!(
                "kdnet: can't enable kdnet without setting the parameters."
            ));
            return Err(ErrorCode::UnknownCommand.into());
        }
        record.set_word(KdnetRecord::ENABLE, u32::from(enable));
        let save = invocation
            .backend
            .write_flash(KDNET_RECORD_OFFSET, &record.0);
        invocation.set_text(format_args!(
            "kdnet {}: 0x{:08x}",
            if enable { "enabled" } else { "disabled" },
            flash_code(save).0
        ));
        return Ok(Reply::Ok);
    }
    if line.has("show") {
        if load.is_err() {
            invocation.set_text(format_args!(
                "kdnet: failed to load current settings: 0x{:08X}",
                flash_code(load).0
            ));
            return Ok(Reply::Ok);
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
        return Ok(Reply::Ok);
    }
    if line.has("set") {
        return match kdnet_set(invocation, &mut record) {
            Ok(()) => {
                invocation.set_text(format_args!("kdnet set succeeded."));
                Ok(Reply::Ok)
            }
            Err(error) => {
                invocation.set_text(format_args!(
                    "kdnet set failed: error code 0x{:08x}",
                    error.code().0
                ));
                Err(match error {
                    KdnetSetError::BadParameter => ErrorCode::BadParameter.into(),
                    KdnetSetError::ConsoleAddress(_) | KdnetSetError::Save(_) => CommandError::Fail,
                })
            }
        };
    }
    Err(ErrorCode::BadParameter.into())
}

/// Why `kdnet set` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdnetSetError {
    /// A parameter is malformed, or the settings are incomplete.
    BadParameter,
    /// The console MAC address for a default target address is unreadable.
    ConsoleAddress(KernelError),
    /// The settings record could not be written.
    Save(KernelError),
}

impl KdnetSetError {
    /// The error code the failure text prints.
    fn code(self) -> Hresult {
        match self {
            Self::BadParameter => ErrorCode::BadParameter.hresult(),
            Self::ConsoleAddress(error) | Self::Save(error) => Hresult::from(error),
        }
    }
}

/// Apply the `set` parameters and save. The last failing step decides the
/// error, as in the monitor.
fn kdnet_set(
    invocation: &mut Invocation<'_>,
    record: &mut KdnetRecord,
) -> Result<(), KdnetSetError> {
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
            None => error = Some(KdnetSetError::BadParameter),
        }
    }
    if line.has("Port") {
        supplied = true;
        match line.dword("Port").filter(|&port| port <= 0xffff) {
            Some(port) => record.0[KdnetRecord::HOST_PORT..KdnetRecord::HOST_PORT + 2]
                .copy_from_slice(&(port as u16).to_be_bytes()),
            None => error = Some(KdnetSetError::BadParameter),
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
                    error = Some(KdnetSetError::BadParameter);
                }
            } else {
                error = Some(KdnetSetError::BadParameter);
            }
        }
        None => default_mac = record.mac().iter().all(|&byte| byte == 0),
    }
    if default_mac {
        let mut console_mac = [0u8; 6];
        match invocation
            .backend
            .xconfig_get(ConfigSetting::MAC_ADDRESS, &mut console_mac)
        {
            Ok(_) => {
                console_mac[5] = console_mac[5].wrapping_sub(1);
                record.0[KdnetRecord::TARGET_MAC..KdnetRecord::TARGET_MAC + 6]
                    .copy_from_slice(&console_mac);
            }
            Err(failure) => error = Some(KdnetSetError::ConsoleAddress(failure)),
        }
    }
    if !supplied || !record.is_valid() {
        error = Some(KdnetSetError::BadParameter);
    }
    if let Some(error) = error {
        return Err(error);
    }
    invocation
        .backend
        .write_flash(KDNET_RECORD_OFFSET, &record.0)
        .map_err(KdnetSetError::Save)
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

/// A debugger extension load or release failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionError {
    /// `443-`: another extension is loaded.
    OtherLoaded,
    /// The handle is not the loaded extension's.
    UnknownHandle,
    /// The loader or the unload failed.
    Kernel(KernelError),
}

impl From<ExtensionError> for Hresult {
    fn from(error: ExtensionError) -> Self {
        match error {
            ExtensionError::OtherLoaded => Hresult::EXTENSION_LOADED,
            ExtensionError::UnknownHandle => ErrorCode::BadParameter.hresult(),
            ExtensionError::Kernel(error) => {
                CommandError::from_kernel(error, CommandError::Fail).into()
            }
        }
    }
}

impl From<ExtensionError> for CommandError {
    fn from(error: ExtensionError) -> Self {
        Self::Extension(error)
    }
}

/// Load the extension `name` from the DMEXT directory, or count another
/// reference to the loaded one (stock export 178, 0x91f2e5e0). Only one
/// extension can be loaded.
pub fn load_extension(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
) -> Result<ExtensionHandle, ExtensionError> {
    if let Some(extension) = state.debugger.extension.as_mut() {
        if !extension.name.as_bytes().eq_ignore_ascii_case(name) {
            return Err(ExtensionError::OtherLoaded);
        }
        extension.references += 1;
        return Ok(extension.handle);
    }
    let mut path = Text::<EXTENSION_PATH_LIMIT>::new();
    let _ = path.push_bytes(EXTENSION_DIRECTORY);
    let _ = path.push_bytes(name);
    let handle = backend
        .load_extension(path.as_bytes())
        .map_err(ExtensionError::Kernel)?;
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
) -> Result<(), ExtensionError> {
    let Some(extension) = state
        .debugger
        .extension
        .as_mut()
        .filter(|extension| extension.handle == handle)
    else {
        return Err(ExtensionError::UnknownHandle);
    };
    extension.references -= 1;
    if extension.references != 0 {
        return Ok(());
    }
    state.debugger.extension = None;
    backend
        .unload_extension(handle)
        .map_err(ExtensionError::Kernel)
}

/// `dbgextld name=` or `dbgextld unload module=`.
pub(super) fn debugger_extension(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    if line.has("unload") {
        let Some(module) = line.dword("module") else {
            invocation.set_text(format_args!("missing module"));
            return Err(ErrorCode::BadParameter.into());
        };
        release_extension(
            invocation.state,
            invocation.backend,
            ExtensionHandle(module),
        )?;
        return Ok(Reply::Ok);
    }
    let Some(value) = line.param("name") else {
        invocation.set_text(format_args!("missing name"));
        return Err(ErrorCode::BadParameter.into());
    };
    let mut buffer = [0u8; EXTENSION_NAME_CAPACITY + 1];
    let name = value.copy_into(&mut buffer);
    let handle = load_extension(invocation.state, invocation.backend, name)?;
    invocation.set_text(format_args!("module=0x{:08x}", handle.0));
    Ok(Reply::Ok)
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
