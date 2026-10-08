//! Screenshot capture.
//!
//! Wire shape (reverse-engineered from `xbdm.xex`'s screenshot callback):
//!
//! ```text
//! 203- binary response follows\r\n
//! pitch=0x... width=0x... height=0x... format=0x... offsetx=0x... offsety=0x...,
//!   framebuffersize=0x... sw=0x... sh=0x... colorspace=0x...\r\n
//! <framebuffersize bytes of raw pixel data>
//! ```
//!
//! The pixel buffer is the current HDMI scanout. For the typical
//! `format=0x98280186` (D3DFMT_LE_X8R8G8B8 with XBDM's "ready" flag set)
//! on standard-definition output, the layout is linear `B G R X` bytes
//! per pixel at `pitch` bytes per row. When `pitch > width * 4` each row
//! has trailing padding that must be stripped.
//!
//! Format variants we explicitly recognise are documented in
//! [`ScreenshotPixelFormat`]; everything else is surfaced as
//! `PixelFormat::Unknown(u32)` so callers can still access the raw bytes
//! and decide how to interpret them.

use bytes::BytesMut;
use rootcause::prelude::*;

use crate::client::Client;
use crate::client::Connected;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::error::Error;
use crate::error::FramingError;
use crate::error::ParseError;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use futures_util::io::AsyncReadExt;

/// Metadata XBDM emits before the framebuffer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenshotMetadata {
    /// Bytes per scanline on the wire. Usually `width * 4` but may be
    /// larger if the GPU needs pitch alignment.
    pub pitch: u32,
    /// Logical framebuffer width (same as `sw` in standard cases).
    pub width: u32,
    /// Logical framebuffer height (same as `sh`).
    pub height: u32,
    /// Raw XBDM format enum. High bit `0x80000000` is an internal marker
    /// we preserve so round-trips are faithful.
    pub format: PixelFormat,
    /// Offset into the first tile along X, if the format uses tiling.
    pub offset_x: u32,
    /// Offset into the first tile along Y, if the format uses tiling.
    pub offset_y: u32,
    /// Total bytes XBDM will send as the body (== `pitch * aligned_height`).
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
    /// Raw 32-bit value the kernel reported, high bit stripped.
    pub fn raw(self) -> u32 {
        match self {
            PixelFormat::LeX8R8G8B8 => 0x1828_0186,
            PixelFormat::LeX8R8G8B8Gamma => 0x1828_01B6,
            PixelFormat::Unknown(raw) => raw,
        }
    }

    fn from_u32(raw: u32) -> Self {
        // XBDM ORs 0x80000000 with the base format as a "ready" marker.
        let base = raw & 0x7FFF_FFFF;
        match base {
            0x1828_0186 => PixelFormat::LeX8R8G8B8,
            0x1828_01B6 => PixelFormat::LeX8R8G8B8Gamma,
            _ => PixelFormat::Unknown(base),
        }
    }

    /// Whether the format is a known linear 32-bit XRGB layout we can
    /// convert to an RGB / RGBA image without further de-tiling.
    pub fn is_linear_xrgb8888(self) -> bool {
        matches!(self, PixelFormat::LeX8R8G8B8 | PixelFormat::LeX8R8G8B8Gamma)
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
    /// Decode the framebuffer into a fully linear `RGBA` byte buffer with
    /// `stride == width * 4`.
    ///
    /// Xbox 360 GPU memory for scanout is 2D-tiled: the visible 32x32
    /// tiles are laid out in a Z-ordered macro/micro pattern. We run
    /// [`detile_2d_32bpp`] to undo the swizzle first, then convert from
    /// the in-memory `B G R X` byte order to `R G B A` with fully opaque
    /// alpha. Returns `None` for formats we don't know how to decode so
    /// callers can fall back to saving the raw bytes.
    pub fn to_rgba8(&self) -> Option<Vec<u8>> {
        if !self.metadata.format.is_linear_xrgb8888() {
            return None;
        }
        let w = self.metadata.width;
        let h = self.metadata.height;
        if (w as usize) * (h as usize) * 4 > self.data.len() {
            return None;
        }
        let linear = detile_2d_32bpp(&self.data, w, h);
        let mut rgba = Vec::with_capacity(linear.len());
        for chunk in linear.as_chunks::<4>().0 {
            let (b, g, r, _x) = (chunk[0], chunk[1], chunk[2], chunk[3]);
            rgba.extend_from_slice(&[r, g, b, 0xFF]);
        }
        Some(rgba)
    }
}

/// Undo Xbox 360 2D tile swizzling for a 32 bits-per-pixel surface.
///
/// The GPU lays scanout memory out in a macro/micro Z-ordered pattern:
/// pixels are grouped into 32x32 tiles, each tile is 4 KiB, and within
/// a tile pixels follow a fixed bit-scramble. This function reverses
/// that so the result is a simple `width * height * 4` row-major buffer
/// matching what the display ultimately scans out.
pub fn detile_2d_32bpp(tiled: &[u8], width: u32, height: u32) -> Vec<u8> {
    const BPP_BYTES: usize = 4;
    let mut out = vec![0u8; (width as usize) * (height as usize) * BPP_BYTES];
    for y in 0..height {
        for x in 0..width {
            let src_byte = tile_offset_32bpp_bytes(x, y, width) as usize;
            let dst_byte = ((y * width + x) as usize) * BPP_BYTES;
            if src_byte + BPP_BYTES <= tiled.len() {
                out[dst_byte..dst_byte + BPP_BYTES]
                    .copy_from_slice(&tiled[src_byte..src_byte + BPP_BYTES]);
            }
        }
    }
    out
}

/// Byte offset of the logical pixel at `(x, y)` inside a 32-bpp Xbox 360
/// 2D-tiled surface. This is the standard `XGAddress2DTiledOffset`
/// algorithm specialised for 32 bpp (log2(bytes_per_pixel) = 2).
pub fn tile_offset_32bpp_bytes(x: u32, y: u32, width: u32) -> u32 {
    const LOG_BPP: u32 = 2;
    let aligned_width = (width + 31) & !31;
    let macro_ = ((x >> 5) + (y >> 5) * (aligned_width >> 5)) << (LOG_BPP + 7);
    let micro = ((x & 7) + ((y & 6) << 2)) << LOG_BPP;
    let offset = macro_
        + ((micro & !0xF) << 1)
        + (micro & 0xF)
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
    let offsetx = value_u32(kv.require("offsetx")?, "offsetx")?;
    let offsety = value_u32(kv.require("offsety")?, "offsety")?;
    let framebuffer_size = value_u32(kv.require("framebuffersize")?, "framebuffersize")?;
    let sw = value_u32(kv.require("sw")?, "sw")?;
    let sh = value_u32(kv.require("sh")?, "sh")?;
    let colorspace = value_u32(kv.require("colorspace")?, "colorspace")?;
    Ok(ScreenshotMetadata {
        pitch,
        width,
        height,
        format: PixelFormat::from_u32(format),
        offset_x: offsetx,
        offset_y: offsety,
        framebuffer_size,
        shown_width: sw,
        shown_height: sh,
        colorspace,
    })
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Take a screenshot of the current HDMI scanout. Returns the typed
    /// metadata plus the raw framebuffer bytes.
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
            Ok(m) => m,
            Err(e) => {
                engine.abort_stream(None);
                return Err(rootcause::Report::new(Error::from(e)));
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

async fn read_line_buffered<R>(
    reader: &mut R,
    leftover: &mut BytesMut,
) -> Result<String, rootcause::Report<Error>>
where
    R: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 512];
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
        let n = reader
            .read(&mut tmp)
            .await
            .map_err(Error::from)
            .into_report()
            .attach("reading screenshot metadata line")?;
        if n == 0 {
            return Err(rootcause::Report::new(Error::ConnectionClosed));
        }
        leftover.extend_from_slice(&tmp[..n]);
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
    let mut filled = 0usize;
    if !leftover.is_empty() {
        let take = core::cmp::min(leftover.len(), dest.len());
        dest[..take].copy_from_slice(&leftover[..take]);
        let _ = leftover.split_to(take);
        filled = take;
    }
    while filled < dest.len() {
        let n = reader
            .read(&mut dest[filled..])
            .await
            .map_err(Error::from)
            .into_report()
            .attach("reading screenshot framebuffer")?;
        if n == 0 {
            return Err(rootcause::Report::new(Error::ConnectionClosed));
        }
        filled += n;
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
}
