//! Console identity and configuration exports, and the control codes that
//! share their implementation.

use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::ConsoleMemory;
use openxbdm_server::commands::console::DEBUG_NAME_CAPACITY;
use openxbdm_server::commands::console::DUMP_SETTINGS_SIZE;
use openxbdm_server::commands::console::DebugName;
use openxbdm_server::commands::console::ExportedSetting;
use openxbdm_server::commands::console::SYSTEM_SETTINGS_SIZE;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360_sys::export_raw;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::HardwareFlags;

use super::Console;
use super::DUMP_MODE;
use super::DUMP_SETTINGS;
use super::EVENT_DEFER;
use super::REGISTRATION;
use super::SYSTEM_SETTINGS;
use super::debug_name;
use super::error::DebugNameError;
use super::kit_features;
use super::memory_statistics;
use super::test_kit_marked;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::version_words;
use crate::net::XamNetwork;

/// Result of a NULL output pointer.
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();
/// XConfig setting of exports 175 and 176.
const XCONFIG_QWORD: ConfigSetting = ConfigSetting {
    category: 3,
    index: 8,
};

/// Block of export 161. The caller states its size, at least this
/// structure's, and the export clears the whole stated size first.
#[repr(C)]
struct SystemInfo {
    size: u32,
    base_kernel: [u16; 4],
    kernel: [u16; 4],
    xdk: [u16; 4],
    flags: HardwareFlags,
}

const _: () = {
    assert!(core::mem::offset_of!(SystemInfo, base_kernel) == 0x4);
    assert!(core::mem::offset_of!(SystemInfo, kernel) == 0xc);
    assert!(core::mem::offset_of!(SystemInfo, xdk) == 0x14);
    assert!(core::mem::offset_of!(SystemInfo, flags) == 0x1c);
    assert!(size_of::<SystemInfo>() == 0x20);
};

/// Record of control code 0x33: the arguments of export 17.
#[repr(C)]
struct DebugNameRequest {
    buffer: u32,
    size: u32,
}

/// Apply an exported setting of a waiting caller on the server thread.
fn service_apply_setting(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    setting: &mut ExportedSetting,
) -> u32 {
    let setting = *setting;
    commands::console::apply_exported_setting(&mut server.state, console, setting);

    0
}

/// Exports 43, 118, 120, 122. Off the server thread at passive level the
/// setting is applied before the export returns, as stock does; otherwise
/// the server cannot be reached and the setting is dropped.
fn apply_setting(mut setting: ExportedSetting) -> Hresult {
    let _ = dispatcher::call_on_server_with(&mut setting, service_apply_setting);

    Hresult::OK
}

/// Export 43: NULL clears the name; at most 20 bytes are kept.
extern "C" fn export_set_debug_name(name: *const u8) -> Hresult {
    let mut bytes = [0u8; DEBUG_NAME_CAPACITY - 1];
    let mut length = 0;
    while !name.is_null() && length < bytes.len() {
        // SAFETY: export 43 takes NULL or a NUL-terminated string, and the
        // loop stops at its NUL.
        let byte = unsafe { name.add(length).read() };
        if byte == 0 {
            break;
        }

        bytes[length] = byte;
        length += 1;
    }

    apply_setting(ExportedSetting::DebugName(DebugName::new(&bytes[..length])))
}
export!(43, export_set_debug_name);

extern "C" fn export_set_dump_mode(mode: u32) -> Hresult {
    apply_setting(ExportedSetting::DumpMode(mode))
}
export!(118, export_set_dump_mode);

extern "C" fn export_set_dump_settings(block: *const [u8; DUMP_SETTINGS_SIZE]) -> Hresult {
    // SAFETY: export 120 takes a readable block of DUMP_SETTINGS_SIZE bytes.
    let settings = unsafe { block.read() };

    apply_setting(ExportedSetting::DumpSettings(settings))
}
export!(120, export_set_dump_settings);

extern "C" fn export_set_event_defer(mask: u32) -> Hresult {
    apply_setting(ExportedSetting::EventDefer(mask))
}
export!(122, export_set_event_defer);

/// Store `value` through the caller's output; NULL fails (stock exports
/// 117, 121, 140, 213, 214, 220).
///
/// # Safety
///
/// `output` is NULL or a writable dword at any alignment.
unsafe fn write_output(output: *mut u32, value: u32) -> Hresult {
    if output.is_null() {
        return BAD_PARAMETER;
    }

    // SAFETY: per the contract of this fn.
    unsafe { output.write_unaligned(value) };

    Hresult::OK
}

/// Export 17: copy the debug name into `buffer` of `*size` bytes.
extern "C" fn export_get_debug_name(buffer: *mut u8, size: *const u32) -> Hresult {
    // SAFETY: export 17 takes NULL or a readable size, and NULL or a buffer
    // of that many writable bytes.
    let output = unsafe { debug_name_output(buffer, size) };

    export_result(get_debug_name(output))
}
export!(17, export_get_debug_name);

/// Export 91 returns its argument (stock returns the copy's destination).
extern "C" fn export_get_system_settings(block: u32) -> u32 {
    // SAFETY: export 91 takes the caller's settings block, with the
    // contract of control code 0x1f.
    unsafe { service_get_system_settings(block) };

    block
}
export!(91, export_get_system_settings);

extern "C" fn export_set_system_settings(block: u32) -> u32 {
    // SAFETY: export 92 takes the caller's settings block, with the
    // contract of control code 0x1e.
    unsafe { service_set_system_settings(block) }
}
export!(92, export_set_system_settings);

/// Export 117: the crash dump mode.
extern "C" fn export_get_dump_mode(output: *mut u32) -> Hresult {
    // SAFETY: export 117 takes NULL or a writable dword, which stock does
    // not align.
    unsafe { write_output(output, DUMP_MODE.load(Ordering::Acquire)) }
}
export!(117, export_get_dump_mode);

/// Export 119: copy the crash dump settings block; the pointer is not
/// checked, as in stock.
extern "C" fn export_get_dump_settings(output: *mut [u8; DUMP_SETTINGS_SIZE]) -> Hresult {
    let block = *DUMP_SETTINGS.lock();
    // SAFETY: export 119 takes a writable block of DUMP_SETTINGS_SIZE bytes.
    unsafe { output.write(block) };

    Hresult::OK
}
export!(119, export_get_dump_settings);

/// Export 121: the event defer mask.
extern "C" fn export_get_event_defer(output: *mut u32) -> Hresult {
    // SAFETY: as export 117.
    unsafe { write_output(output, EVENT_DEFER.load(Ordering::Acquire)) }
}
export!(121, export_get_event_defer);

/// Export 140: whether the console is a test kit (stock 0x91f9f680).
extern "C" fn export_is_test_kit(output: *mut u32) -> Hresult {
    let test_kit = hardware_flags().contains(HardwareFlags::TEST_KIT) || test_kit_marked();

    // SAFETY: as export 117.
    unsafe { write_output(output, u32::from(test_kit)) }
}
export!(140, export_is_test_kit);

/// The flags word of export 161: the unnamed low bits, the generation with
/// unknown generations as 0xf, the hard disk flag, and the test kit flag.
fn system_info_flags(hardware: HardwareFlags) -> HardwareFlags {
    const LOW_BITS: u32 = 0x3;
    const GENERATION_SHIFT: u32 = 28;
    const UNKNOWN_GENERATION: u8 = 0xf;

    let generation = match hardware.generation().get() {
        generation @ (0..=6 | 8) => generation,
        _ => UNKNOWN_GENERATION,
    };

    let mut flags = HardwareFlags::from_bits_retain(
        hardware.bits() & LOW_BITS | u32::from(generation) << GENERATION_SHIFT,
    );
    if hardware.contains(HardwareFlags::HARD_DISK) {
        flags.insert(HardwareFlags::HARD_DISK);
    }
    if hardware.contains(HardwareFlags::TEST_KIT) || test_kit_marked() {
        flags.insert(HardwareFlags::TEST_KIT);
    }

    flags
}

/// Export 161: fill the caller's [`SystemInfo`].
extern "C" fn export_get_system_info(block: *mut SystemInfo) -> Hresult {
    if block.is_null() {
        return BAD_PARAMETER;
    }

    // SAFETY: export 161 takes NULL or a block whose first word states its
    // size, and which holds that many writable bytes; stock does not align
    // it.
    let size = unsafe { block.cast::<u32>().read_unaligned() };
    if (size as i32) < size_of::<SystemInfo>() as i32 {
        return BAD_PARAMETER;
    }

    // SAFETY: as above; `size` covers a whole `SystemInfo`.
    unsafe {
        core::ptr::write_bytes(block.cast::<u8>(), 0, size as usize);
        (&raw mut (*block).size).write_unaligned(size_of::<SystemInfo>() as u32);
        (&raw mut (*block).base_kernel)
            .write_unaligned(version_words(kernel::base_kernel_version()));
        (&raw mut (*block).kernel).write_unaligned(version_words(kernel_version()));
        (&raw mut (*block).xdk).write_unaligned(commands::console::XDK_VERSION.0);
        (&raw mut (*block).flags).write_unaligned(system_info_flags(hardware_flags()));
    }

    Hresult::OK
}
export!(161, export_get_system_info);

/// Exports 175 and 176: a failed setting call returns its status with the
/// NT facility bit.
fn xconfig_result(status: NtStatus) -> Hresult {
    export_result(status.result())
}

/// Export 175: read the 8-byte setting [`XCONFIG_QWORD`] into `output`.
extern "C" fn export_get_xconfig_qword(output: Option<&mut [u8; 8]>) -> Hresult {
    if !hardware_flags().contains(HardwareFlags::AUTO_PROFILE) {
        return ErrorCode::UnknownCommand.hresult();
    }

    let Some(output) = output else {
        return BAD_PARAMETER;
    };

    let mut length = 0u16;
    // SAFETY: `output` and `length` are live for the call.
    xconfig_result(unsafe {
        xboxkrnl::ExGetXConfigSetting(
            XCONFIG_QWORD.category,
            XCONFIG_QWORD.index,
            output.as_mut_ptr(),
            output.len() as u16,
            &mut length,
        )
    })
}
export!(175, export_get_xconfig_qword);

/// Export 176 with the 64-bit value split into its high and low words by
/// [`export_set_xconfig_qword_entry`].
extern "C" fn export_set_xconfig_qword(high: u32, low: u32) -> Hresult {
    if !hardware_flags().contains(HardwareFlags::AUTO_PROFILE) {
        return ErrorCode::UnknownCommand.hresult();
    }

    let value = (u64::from(high) << 32 | u64::from(low)).to_be_bytes();
    // SAFETY: `value` is a live 8-byte local.
    xconfig_result(unsafe {
        xboxkrnl::ExSetXConfigSetting(
            XCONFIG_QWORD.category,
            XCONFIG_QWORD.index,
            value.as_ptr(),
            value.len() as u16,
        )
    })
}

/// The importer passes the 64-bit value in r3: copy it to r4, move its high
/// word down (`rldicl 3, 3, 32, 32`, encoded directly), and enter through
/// the bridge.
#[unsafe(naked)]
unsafe extern "C" fn export_set_xconfig_qword_entry() {
    core::arch::naked_asm!(
        "mr 4, 3",
        ".long 0x78630022",
        "lis 12, {function}@ha",
        "addi 12, 12, {function}@l",
        "b {bridge}",
        function = sym export_set_xconfig_qword,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(176, export_set_xconfig_qword_entry);

/// Export 194: `(transaction out, buffer, size in/out) -> HRESULT`; the
/// response of the last accepted registration.
extern "C" fn export_get_registration_response(
    transaction: *mut u64,
    buffer: *mut u8,
    size: *mut u32,
) -> Hresult {
    // SAFETY: export 194 takes NULL or a size dword, which stock does not
    // align.
    let capacity = (!size.is_null()).then(|| unsafe { size.read_unaligned() });

    // A buffer needs a size pointer and a nonzero size needs a buffer.
    let rejected = match capacity {
        Some(capacity) => capacity != 0 && buffer.is_null(),
        None => !buffer.is_null(),
    };
    if rejected {
        return BAD_PARAMETER;
    }

    let registration = *REGISTRATION.lock();
    let output = capacity.map(|capacity| {
        if buffer.is_null() {
            &mut [][..]
        } else {
            // SAFETY: export 194 takes a buffer of `*size` writable bytes.
            unsafe { core::slice::from_raw_parts_mut(buffer, capacity as usize) }
        }
    });
    let response = registration.export_response(output);

    if !transaction.is_null() {
        // SAFETY: export 194 takes NULL or a writable 64-bit output; stock
        // does not require 8-byte alignment.
        unsafe { transaction.write_unaligned(response.transaction) };
    }
    if !size.is_null() {
        // SAFETY: as above.
        unsafe { size.write_unaligned(response.length) };
    }

    export_result(response.result)
}
export!(194, export_get_registration_response);

/// Export 213: `(size out) -> HRESULT`; the debug memory size, 0 when the
/// statistics query fails.
extern "C" fn export_get_debug_memory_size(output: *mut u32) -> Hresult {
    let size = memory_statistics().map_or(0, |statistics| statistics.debug_memory_size());

    // SAFETY: as export 117.
    unsafe { write_output(output, size) }
}
export!(213, export_get_debug_memory_size);

/// Export 214: `(configuration out) -> HRESULT`; the `consolemem` value.
extern "C" fn export_get_console_memory(output: *mut u32) -> Hresult {
    let memory = ConsoleMemory::of(kit_features(), memory_statistics).value();

    // SAFETY: as export 117.
    unsafe { write_output(output, memory) }
}
export!(214, export_get_console_memory);

/// Export 220: `(features out) -> HRESULT`; the `consolefeatures` bits.
extern "C" fn export_get_console_features(output: *mut u32) -> Hresult {
    // SAFETY: as export 117.
    unsafe { write_output(output, kit_features().mask()) }
}
export!(220, export_get_console_features);

/// Control code 0x1e (stock export 92): store the caller's settings block
/// `{+0 size, +4 flags, +8 video standard}` and write the settings file.
///
/// # Safety
///
/// `argument` must be the address of an aligned block whose first word
/// states its size and which holds at least that many readable bytes,
/// unchanged for the call.
pub(crate) unsafe fn service_set_system_settings(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let block = unsafe {
        let size = *kernel::object_at::<u32>(argument);
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u8>(argument as usize),
            (size as usize).min(SYSTEM_SETTINGS_SIZE),
        )
    };
    SYSTEM_SETTINGS.lock().store(block);
    dispatcher::request_settings_write();

    0
}

/// Control code 0x1f (stock export 91): copy the settings block into the
/// caller's, at most the size it states; its size field is kept.
///
/// # Safety
///
/// `argument` must be the address of an aligned block whose first word
/// states its size and which holds at least that many writable bytes, not
/// otherwise accessed for the call.
pub(crate) unsafe fn service_get_system_settings(argument: u32) -> u32 {
    // Size field that leads a caller's settings block.
    const SETTINGS_SIZE_FIELD: usize = size_of::<u32>();

    let block = core::ptr::with_exposed_provenance_mut::<u8>(argument as usize);
    // SAFETY: the caller's contract.
    let size = unsafe { *kernel::object_at::<u32>(argument) };
    let length = (size as usize).min(SYSTEM_SETTINGS_SIZE);
    let settings = *SYSTEM_SETTINGS.lock();
    if length <= SETTINGS_SIZE_FIELD {
        return 0;
    }

    // SAFETY: the caller's contract; the size field is not part of the
    // slice.
    let output = unsafe {
        core::slice::from_raw_parts_mut(
            block.add(SETTINGS_SIZE_FIELD),
            length - SETTINGS_SIZE_FIELD,
        )
    };
    output.copy_from_slice(&settings.0[SETTINGS_SIZE_FIELD..length]);

    0
}

/// Control code 0x33 (stock export 17).
///
/// # Safety
///
/// `argument` must be the address of a readable `DebugNameRequest` that
/// holds export 17's arguments, with that export's contract.
pub(crate) unsafe fn service_get_debug_name(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at::<DebugNameRequest>(argument) };
    // SAFETY: the caller's contract.
    let output = unsafe {
        debug_name_output(
            core::ptr::with_exposed_provenance_mut(request.buffer as usize),
            core::ptr::with_exposed_provenance(request.size as usize),
        )
    };

    export_result(get_debug_name(output)).0
}

/// The output of stock export 17; `None` if either pointer is NULL.
///
/// # Safety
///
/// `size` is NULL or a readable dword at any alignment, and `buffer` is
/// NULL or holds `*size` writable bytes that stay unaliased for `'a`.
unsafe fn debug_name_output<'a>(buffer: *mut u8, size: *const u32) -> Option<&'a mut [u8]> {
    if buffer.is_null() || size.is_null() {
        return None;
    }

    // SAFETY: per the contract of this fn.
    Some(unsafe { core::slice::from_raw_parts_mut(buffer, size.read_unaligned() as usize) })
}

/// Stock export 17: copy the debug name into `output`.
fn get_debug_name(output: Option<&mut [u8]>) -> Result<(), DebugNameError> {
    let output = output.ok_or(DebugNameError::MissingBuffer)?;
    commands::console::copy_debug_name(&debug_name(), output)?;

    Ok(())
}
