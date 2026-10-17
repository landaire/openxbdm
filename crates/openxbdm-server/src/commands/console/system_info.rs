//! `systeminfo` reply and kernel version information.

use core::fmt::Write as _;

use xbox360_sys::xboxkrnl::HardwareFlags;

use super::Continuation;
use crate::continuation::Continuation as AnyContinuation;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::LineText;

/// XDK version reported by `systeminfo`.
pub const XDK_VERSION: Version = Version([2, 0, 21256, 0]);

/// Lines of the `systeminfo` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInfoLine {
    Disk,
    KitType,
    Hardware,
    Versions,
    End,
}

/// A four-part version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Version(pub [u16; 4]);

/// Kernel versions and hardware flags for `systeminfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemInformation {
    pub base_kernel: Version,
    pub kernel: Version,
    /// First dword of the kernel hardware information export.
    pub hardware_flags: HardwareFlags,
}

/// `systeminfo`: four lines. Stock sends uninitialized stack text on the
/// 202 line; an empty text gives the default `multiline response follows`.
pub(super) fn system_info(invocation: &mut Invocation<'_>) -> CommandResult {
    let info = invocation.backend.system_information();
    let test_kit = invocation.backend.is_test_kit();
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.receive_remaining = None;
    session.continuation = AnyContinuation::Console(Continuation::SystemInfo {
        next: SystemInfoLine::Disk,
        info,
        test_kit,
    });
    invocation.text.clear();

    Ok(Reply::Multiline)
}

fn platform_name(flags: HardwareFlags) -> &'static str {
    match flags.bits() & 3 {
        0 => "Alpha",
        1 => "Mongrel",
        2 => "Shiva",
        _ => "Waternoose",
    }
}

fn system_name(flags: HardwareFlags) -> &'static str {
    match flags.generation().get() {
        0 => "Xenon",
        1 => "Zephyr",
        2 => "Falcon",
        3 => "Jasper",
        4 => "Trinity",
        5 => "Corona",
        6 => "Winchester",
        8 => "Ridgeway",
        _ => "Unknown",
    }
}

pub(super) fn system_info_line(
    next: &mut SystemInfoLine,
    info: &SystemInformation,
    test_kit: bool,
    line: &mut LineText,
) -> CommandResult {
    line.clear();

    let flags = info.hardware_flags;
    let _ = match *next {
        SystemInfoLine::Disk => {
            *next = SystemInfoLine::KitType;
            line.write_str(if flags.contains(HardwareFlags::HARD_DISK) {
                "HDD=Enabled"
            } else {
                "HDD=Disabled"
            })
        }
        SystemInfoLine::KitType => {
            *next = SystemInfoLine::Hardware;
            line.write_str(if test_kit {
                "Type=TestKit"
            } else {
                "Type=DevKit"
            })
        }
        SystemInfoLine::Hardware => {
            *next = SystemInfoLine::Versions;
            write!(
                line,
                "Platform={} System={}",
                platform_name(flags),
                system_name(flags)
            )
        }
        SystemInfoLine::Versions => {
            *next = SystemInfoLine::End;
            let (Version(base), Version(kernel), Version(xdk)) =
                (info.base_kernel, info.kernel, XDK_VERSION);
            write!(
                line,
                "BaseKrnl={}.{}.{}.{} Krnl={}.{}.{}.{} XDK={}.{}.{}.{}",
                base[0],
                base[1],
                base[2],
                base[3],
                kernel[0],
                kernel[1],
                kernel[2],
                kernel[3],
                xdk[0],
                xdk[1],
                xdk[2],
                xdk[3]
            )
        }
        SystemInfoLine::End => return Err(CommandError::EndOfData),
    };

    Ok(Reply::Ok)
}
