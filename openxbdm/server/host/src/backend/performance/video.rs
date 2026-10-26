//! Simulated video encoder and GPU registers.

use std::collections::BTreeMap;

use openxbdm_server::commands::performance::EDID_BLOCK_SIZE;

/// Simulated video encoder and GPU registers.
#[derive(Debug, Clone)]
pub struct Video {
    pub encoder: Vec<u32>,
    pub extended: bool,
    /// Extended bank writes, in order.
    pub extended_writes: Vec<(u32, u8)>,

    pub gpu: BTreeMap<u32, u32>,

    /// EDID blocks; `None` when the kernel lacks the EDID export.
    pub edid: Option<Vec<[u8; EDID_BLOCK_SIZE]>>,
}

impl Default for Video {
    fn default() -> Self {
        Self {
            encoder: (0..0x300u32)
                .map(|register| register.wrapping_mul(0x0101_0101))
                .collect(),
            extended: true,
            extended_writes: Vec::new(),
            gpu: BTreeMap::new(),
            edid: Some(vec![std::array::from_fn(|index| index as u8 ^ 0xa5)]),
        }
    }
}
