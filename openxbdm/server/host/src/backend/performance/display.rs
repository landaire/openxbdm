//! Simulated front buffer.

use openxbdm_server::commands::performance::DisplayCapture;
use openxbdm_server::commands::performance::DisplayInformation;
use openxbdm_server::commands::performance::TILE_SIZE;

/// Difference between the front buffer address the display controller
/// register names and the physical address of the memory behind it.
const FRONT_BUFFER_OFFSET: u32 = 0x4000_0000;

/// Simulated front buffer: tiled memory at the address the display
/// controller register names.
#[derive(Debug, Clone, Default)]
pub struct Display {
    pub capture: DisplayCapture,
    pub memory: Vec<u8>,
    /// Pages read by screenshots, by address.
    pub reads: Vec<u32>,
}

impl Display {
    /// A front buffer of `display` geometry at physical `address` whose
    /// pixel at (x, y) holds `pixel(x, y)` in memory byte order.
    pub fn new(
        display: DisplayInformation,
        address: u32,
        pixel: impl Fn(u32, u32) -> [u8; 4],
    ) -> Self {
        let surface_width = (u32::from(display.surface_width) + 31) & !31;
        let rows = (display.bottom + 31) & !31;
        let mut memory = vec![0u8; (surface_width * rows * 4) as usize];

        for y in 0..rows {
            for x in 0..surface_width {
                let offset = tiled_offset(x, y, surface_width) as usize;
                memory[offset..offset + 4].copy_from_slice(&pixel(x, y));
            }
        }

        let capture = DisplayCapture {
            display,
            front_buffer: address.wrapping_add(FRONT_BUFFER_OFFSET),
            gamma: false,
        };

        Self {
            capture,
            memory,
            reads: Vec::new(),
        }
    }

    /// Copy the page at physical `address`; pages outside the simulated
    /// memory read as zeros.
    pub(super) fn read_page(&mut self, address: u32, page: &mut [u8; TILE_SIZE as usize]) {
        self.reads.push(address);

        let base = self.capture.front_buffer.wrapping_sub(FRONT_BUFFER_OFFSET);
        let start = address.wrapping_sub(base) as usize;
        match self.memory.get(start..start + TILE_SIZE as usize) {
            Some(bytes) => page.copy_from_slice(bytes),
            None => page.fill(0),
        }
    }
}

/// Byte offset of pixel (x, y) in a 32-bit tiled surface `width` pixels
/// wide: 32 by 32 pixel tiles of 4 KiB in row-major order.
pub fn tiled_offset(x: u32, y: u32, width: u32) -> u32 {
    let aligned_width = (width + 31) & !31;
    let macro_offset = ((x >> 5) + (y >> 5) * (aligned_width >> 5)) << 9;
    let micro = ((x & 7) + ((y & 6) << 2)) << 2;
    let offset =
        macro_offset + ((micro & !0xf) << 1) + (micro & 0xf) + ((y & 8) << 5) + ((y & 1) << 4);

    ((offset & !0x1ff) << 3)
        + ((y & 16) << 7)
        + ((offset & 0x1c0) << 2)
        + ((((y & 8) >> 2) + (x >> 3)) & 3) * 64
        + (offset & 0x3f)
}
