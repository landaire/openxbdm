//! Identification of the first bytes of a device.

use core::fmt;

/// What the first sector of a device starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// An XTAF volume header: magic `XTAF`, then the big-endian volume
    /// serial number.
    Xtaf { serial: u32 },
    /// The first 16 bytes, for data without a recognized magic.
    Unrecognized([u8; 16]),
}

impl Signature {
    /// `None` when `sector` is shorter than 16 bytes.
    pub fn from_sector(sector: &[u8]) -> Option<Self> {
        let head: [u8; 16] = sector.get(..16)?.try_into().ok()?;
        if head[..4] != *b"XTAF" {
            return Some(Self::Unrecognized(head));
        }

        let serial = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

        Some(Self::Xtaf { serial })
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xtaf { serial } => write!(f, "XTAF serial {serial:08x}"),
            Self::Unrecognized(head) => {
                for byte in head {
                    write!(f, "{byte:02x}")?;
                }

                Ok(())
            }
        }
    }
}
