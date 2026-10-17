//! Screenshot capture.
//!
//! Wire shape of the monitor's screenshot transfer:
//!
//! ```text
//! 203- binary response follows\r\n
//! pitch=0x... width=0x... height=0x... format=0x... offsetx=0x... offsety=0x...,
//!   framebuffersize=0x... sw=0x... sh=0x... colorspace=0x...\r\n
//! <framebuffersize bytes of front buffer tiles>
//! ```
//!
//! The body is the front buffer exactly as the GPU stores it: 4 KiB tiles
//! of 32x32 pixels, row-major, covering the displayed rectangle widened to
//! tile boundaries. `offsetx`/`offsety` locate the first displayed pixel
//! inside the first tile, and each tile row holds
//! `ceil((offsetx + width) / 32)` tiles.
//!
//! Format variants we explicitly recognise are documented in
//! [`PixelFormat`]; everything else is surfaced as
//! `PixelFormat::Unknown(u32)` so callers can still access the raw bytes
//! and decide how to interpret them.

mod error;

use bytes::BytesMut;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use futures_util::io::AsyncReadExt;
use rootcause::prelude::ResultExt;

use crate::client::Client;
use crate::client::Connected;
use crate::commands::error::report_parse;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::error::Error;
use crate::error::FramingError;
use crate::error::ParseError;

pub use error::DecodeError;

/// Metadata XBDM emits before the framebuffer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenshotMetadata {
    /// Bytes per pixel row of the whole front buffer surface.
    pub pitch: u32,
    /// Displayed width in pixels.
    pub width: u32,
    /// Displayed height in pixels.
    pub height: u32,
    /// Raw XBDM format enum. High bit `0x80000000` is an internal marker
    /// we preserve so round-trips are faithful.
    pub format: PixelFormat,

    /// Column of the first displayed pixel inside the first tile.
    pub offset_x: u32,
    /// Row of the first displayed pixel inside the first tile.
    pub offset_y: u32,
    /// Body size: the tiles covering the displayed rectangle, 4 KiB each.
    pub framebuffer_size: u32,

    /// "Shown" width reported separately from tile-aligned width.
    pub shown_width: u32,
    /// "Shown" height reported separately from tile-aligned height.
    pub shown_height: u32,
    /// Colorspace index; almost always 0 in practice.
    pub colorspace: u32,
}

/// Typed surface pixel format. We recognise the handful of shapes XBDM
/// emits on retail/devkit hardware; everything else is preserved raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// `0x98280186` / `0x18280186`: little-endian `X8R8G8B8`, meaning
    /// memory layout is `B G R X` per pixel. Typical for HDMI scanout.
    LeX8R8G8B8,
    /// `0x982801B6` / `0x182801B6`: gamma-corrected sibling of the
    /// format above. Same memory layout, different colorspace.
    LeX8R8G8B8Gamma,
    /// Any other value we haven't explicitly modelled.
    Unknown(u32),
}

impl PixelFormat {
    fn from_u32(raw: u32) -> Self {
        // XBDM ORs 0x80000000 with the base format as a "ready" marker.
        let base = raw & 0x7FFF_FFFF;

        match base {
            0x1828_0186 => Self::LeX8R8G8B8,
            0x1828_01B6 => Self::LeX8R8G8B8Gamma,
            _ => Self::Unknown(base),
        }
    }

    /// Raw 32-bit value the kernel reported, high bit stripped.
    pub fn raw(self) -> u32 {
        match self {
            Self::LeX8R8G8B8 => 0x1828_0186,
            Self::LeX8R8G8B8Gamma => 0x1828_01B6,
            Self::Unknown(raw) => raw,
        }
    }

    /// Whether the format is a known linear 32-bit XRGB layout we can
    /// convert to an RGB / RGBA image without further de-tiling.
    pub fn is_linear_xrgb8888(self) -> bool {
        matches!(self, Self::LeX8R8G8B8 | Self::LeX8R8G8B8Gamma)
    }
}

/// Collected screenshot, holding both the parsed metadata and the raw
/// bytes off the wire. Converters (e.g. PNG encoders in the CLI) run on
/// top of this type.
#[derive(Debug, Clone)]
pub struct Screenshot {
    pub metadata: ScreenshotMetadata,
    pub data: Vec<u8>,
}

impl Screenshot {
    /// Decode the framebuffer into a linear `RGBA` byte buffer with
    /// `stride == width * 4`, converting from the in-memory `B G R X` byte
    /// order with opaque alpha.
    pub fn to_rgba8(&self) -> Result<Vec<u8>, DecodeError> {
        let metadata = &self.metadata;
        if !metadata.format.is_linear_xrgb8888() {
            return Err(DecodeError::UnsupportedFormat {
                format: metadata.format,
            });
        }

        let linear = detile_32bpp(
            &self.data,
            metadata.width,
            metadata.height,
            metadata.offset_x,
            metadata.offset_y,
        )
        .ok_or(DecodeError::BodyTooShort {
            length: self.data.len(),
        })?;

        let mut rgba = Vec::with_capacity(linear.len());
        for &[blue, green, red, _] in linear.as_chunks::<4>().0 {
            rgba.extend_from_slice(&[red, green, blue, 0xFF]);
        }

        Ok(rgba)
    }
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Take a screenshot of the front buffer. Returns the typed metadata
    /// plus the raw tile bytes.
    pub async fn screenshot(&mut self) -> Result<Screenshot, rootcause::Report<Error>> {
        // 203 head; engine parks in StreamingBody after this.
        let _head_text = self.submit_streaming("screenshot").await?;
        let (transport, engine) = self.split_streaming();
        let mut leftover = engine.take_inbox();

        // Right after the 203 head, XBDM sends a single ASCII metadata
        // line terminated by CRLF, followed by the raw framebuffer.
        // On any failure before the body is drained, the rest of the
        // framebuffer is still queued on the wire and the connection
        // can no longer be framed: fail the engine rather than return
        // it to `Idle`.
        let metadata_line = match read_line_buffered(transport, &mut leftover).await {
            Ok(line) => line,
            Err(e) => {
                engine.abort_stream(None);
                return Err(e);
            }
        };
        let metadata = match parse_metadata_line(&metadata_line) {
            Ok(metadata) => metadata,
            Err(e) => {
                engine.abort_stream(None);
                return Err(report_parse(e));
            }
        };

        let total = u64::from(metadata.framebuffer_size);
        let mut data = vec![0u8; metadata.framebuffer_size as usize];
        match read_framebuffer(transport, &mut leftover, &mut data).await {
            Ok(()) => {
                // Body drained; anything still buffered belongs to the
                // next response.
                engine.end_stream(&leftover);
            }
            Err(e) => {
                engine.abort_stream(Some(total));
                return Err(e);
            }
        }

        Ok(Screenshot { metadata, data })
    }
}

/// Linearize a screenshot body: `width * height` pixels of 4 bytes,
/// starting at (`offset_x`, `offset_y`) of the first tile. `None` when the
/// body does not hold every tile of the rectangle.
pub fn detile_32bpp(
    tiled: &[u8],
    width: u32,
    height: u32,
    offset_x: u32,
    offset_y: u32,
) -> Option<Vec<u8>> {
    const BPP_BYTES: usize = 4;

    let tiles_per_row = offset_x.checked_add(width)?.div_ceil(32);
    let tile_rows = offset_y.checked_add(height)?.div_ceil(32);
    let surface_width = tiles_per_row.checked_mul(32)?;

    // Tile offsets are computed in u32, so the whole surface must fit in it.
    let surface_bytes = tiles_per_row.checked_mul(tile_rows)?.checked_mul(0x1000)?;
    if surface_bytes as usize > tiled.len() {
        return None;
    }

    let mut out = vec![0u8; (width as usize) * (height as usize) * BPP_BYTES];
    for y in 0..height {
        for x in 0..width {
            let src = tile_offset_32bpp_bytes(x + offset_x, y + offset_y, surface_width) as usize;
            let dst = ((y as usize) * (width as usize) + (x as usize)) * BPP_BYTES;
            out[dst..dst + BPP_BYTES].copy_from_slice(&tiled[src..src + BPP_BYTES]);
        }
    }

    Some(out)
}

/// Byte offset of pixel `(x, y)` inside a 32-bpp tiled surface `width`
/// pixels wide: the tile index times 4 KiB plus the position inside the
/// tile.
pub fn tile_offset_32bpp_bytes(x: u32, y: u32, width: u32) -> u32 {
    const LOG_BPP: u32 = 2;

    let aligned_width = (width + 31) & !31;
    let macro_offset = ((x >> 5) + (y >> 5) * (aligned_width >> 5)) << (LOG_BPP + 7);
    let micro_offset = ((x & 7) + ((y & 6) << 2)) << LOG_BPP;
    let offset = macro_offset
        + ((micro_offset & !0xF) << 1)
        + (micro_offset & 0xF)
        + ((y & 8) << (3 + LOG_BPP))
        + ((y & 1) << 4);

    ((offset & !0x1FF) << 3)
        + ((y & 16) << 7)
        + ((offset & 0x1C0) << 2)
        + ((((y & 8) >> 2) + (x >> 3)) & 3) * 64
        + (offset & 0x3F)
}

/// Parse the ASCII metadata line emitted right after `203- binary
/// response follows`.
pub fn parse_metadata_line(line: &str) -> Result<ScreenshotMetadata, ParseError> {
    // The kernel emits a stray comma after `offsety`; strip it so our
    // KV tokenizer accepts the line cleanly.
    let cleaned = line.replace(',', "");
    let kv = parse_kv_line(&cleaned);

    let pitch = value_u32(kv.require("pitch")?, "pitch")?;
    let width = value_u32(kv.require("width")?, "width")?;
    let height = value_u32(kv.require("height")?, "height")?;
    let format = value_u32(kv.require("format")?, "format")?;
    let offset_x = value_u32(kv.require("offsetx")?, "offsetx")?;
    let offset_y = value_u32(kv.require("offsety")?, "offsety")?;
    let framebuffer_size = value_u32(kv.require("framebuffersize")?, "framebuffersize")?;
    let shown_width = value_u32(kv.require("sw")?, "sw")?;
    let shown_height = value_u32(kv.require("sh")?, "sh")?;
    let colorspace = value_u32(kv.require("colorspace")?, "colorspace")?;

    Ok(ScreenshotMetadata {
        pitch,
        width,
        height,
        format: PixelFormat::from_u32(format),
        offset_x,
        offset_y,
        framebuffer_size,
        shown_width,
        shown_height,
        colorspace,
    })
}

async fn read_line_buffered<R>(
    reader: &mut R,
    leftover: &mut BytesMut,
) -> Result<String, rootcause::Report<Error>>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0u8; 512];

    loop {
        if let Some(pos) = memchr::memchr(b'\n', leftover) {
            let end = if pos > 0 && leftover[pos - 1] == b'\r' {
                pos - 1
            } else {
                pos
            };
            let line = String::from_utf8(leftover[..end].to_vec())
                .map_err(|_| rootcause::Report::new(Error::from(FramingError::NonUtf8Line)))?;
            let _ = leftover.split_to(pos + 1);

            return Ok(line);
        }

        let read_len = reader
            .read(&mut scratch)
            .await
            .map_err(Error::from)
            .into_report()
            .attach("reading screenshot metadata line")?;
        if read_len == 0 {
            return Err(rootcause::Report::new(Error::ConnectionClosed));
        }

        leftover.extend_from_slice(&scratch[..read_len]);
    }
}

async fn read_framebuffer<R>(
    reader: &mut R,
    leftover: &mut BytesMut,
    dest: &mut [u8],
) -> Result<(), rootcause::Report<Error>>
where
    R: AsyncRead + Unpin,
{
    let mut filled = core::cmp::min(leftover.len(), dest.len());
    dest[..filled].copy_from_slice(&leftover[..filled]);
    let _ = leftover.split_to(filled);

    while filled < dest.len() {
        let read_len = reader
            .read(&mut dest[filled..])
            .await
            .map_err(Error::from)
            .into_report()
            .attach("reading screenshot framebuffer")?;
        if read_len == 0 {
            return Err(rootcause::Report::new(Error::ConnectionClosed));
        }

        filled += read_len;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_metadata_line() {
        let line = "pitch=0x00000a00 width=0x00000280 height=0x000001e0 format=0x98280186 offsetx=0x00000000 offsety=0x00000000, framebuffersize=0x0012c000 sw=0x00000280 sh=0x000001e0 colorspace=0x0";
        let meta = parse_metadata_line(line).unwrap();
        assert_eq!(meta.pitch, 0xa00);
        assert_eq!(meta.width, 0x280);
        assert_eq!(meta.height, 0x1e0);
        assert_eq!(meta.format, PixelFormat::LeX8R8G8B8);
        assert_eq!(meta.framebuffer_size, 0x12c000);
        assert!(meta.format.is_linear_xrgb8888());
    }

    #[test]
    fn detile_rejects_overflowing_rectangle() {
        let body = [0u8; 0x1000];
        assert_eq!(detile_32bpp(&body, 1, 1, u32::MAX, 0), None);
        assert_eq!(detile_32bpp(&body, 1, 1, 0, u32::MAX), None);
        assert_eq!(detile_32bpp(&body, 1, 1, u32::MAX - 1, 0), None);
        assert!(detile_32bpp(&body, 1, 1, 31, 31).is_some());
    }
}
