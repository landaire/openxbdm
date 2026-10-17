//! Security descriptors of QUERY_INFO (MS-DTYP 2.4.6).

use crate::server::create::share_maximum;
use crate::server::error::RequestError;
use crate::server::info::Built;
use crate::server::info::SCRATCH;
use crate::server::request::Failure;
use crate::server::wire;

/// Parts of a security descriptor a query asks for (MS-DTYP 2.4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SecurityInformation(pub(super) u32);

impl SecurityInformation {
    const OWNER: Self = Self(0x1);
    const GROUP: Self = Self(0x2);
    const DACL: Self = Self(0x4);
    const SACL: Self = Self(0x8);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Control bits of a security descriptor (MS-DTYP 2.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityControl(u16);

impl SecurityControl {
    const DACL_PRESENT: Self = Self(0x0004);
    const SELF_RELATIVE: Self = Self(0x8000);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// AceType of an ACE header (MS-DTYP 2.4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AceType(u8);

impl AceType {
    const ACCESS_ALLOWED: Self = Self(0);
}

/// AceFlags of an ACE header (MS-DTYP 2.4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AceFlags(u8);

impl AceFlags {
    const NONE: Self = Self(0);
    const OBJECT_INHERIT: Self = Self(0x1);
    const CONTAINER_INHERIT: Self = Self(0x2);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A self-relative security descriptor of the requested parts: Everyone
/// owns every file and holds the share's rights on it.
pub(super) fn security_descriptor(
    requested: SecurityInformation,
    writable: bool,
    directory: bool,
    output: &mut [u8; SCRATCH],
) -> Result<Built, Failure> {
    /// S-1-1-0, Everyone.
    const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

    if requested.contains(SecurityInformation::SACL) {
        return Err(Failure::Error(RequestError::PrivilegeNotHeld));
    }

    // Revision 1; the offsets of the parts follow the 20-byte header.
    let mut control = SecurityControl::SELF_RELATIVE;
    let mut length = 20;
    output[0] = 1;

    if requested.contains(SecurityInformation::OWNER) {
        wire::put_u32(output, 4, length as u32);
        output[length..length + 12].copy_from_slice(&EVERYONE);
        length += 12;
    }

    if requested.contains(SecurityInformation::GROUP) {
        wire::put_u32(output, 8, length as u32);
        output[length..length + 12].copy_from_slice(&EVERYONE);
        length += 12;
    }

    if requested.contains(SecurityInformation::DACL) {
        control = control.union(SecurityControl::DACL_PRESENT);
        wire::put_u32(output, 16, length as u32);
        let acl = length;
        output[acl] = 2;
        wire::put_u16(output, acl + 2, 28);
        wire::put_u16(output, acl + 4, 1);
        let ace = acl + 8;
        output[ace] = AceType::ACCESS_ALLOWED.0;
        output[ace + 1] = if directory {
            AceFlags::OBJECT_INHERIT.union(AceFlags::CONTAINER_INHERIT)
        } else {
            AceFlags::NONE
        }
        .0;
        wire::put_u16(output, ace + 2, 20);
        wire::put_u32(output, ace + 4, share_maximum(writable).0);
        output[ace + 8..ace + 20].copy_from_slice(&EVERYONE);
        length += 28;
    }

    wire::put_u16(output, 2, control.0);

    Ok(Built::fixed(length))
}
