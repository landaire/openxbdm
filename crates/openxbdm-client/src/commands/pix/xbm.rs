//! Parser for xbmovie's on-disk `.xbm` intermediate format.
//!
//! The container is what xbdm's PIX handler dumps to
//! `\Device\Harddisk0\Partition1\DEVKIT\<name>N.xbm` while a PIX!
//! capture session is active. xbmovie's own decoder (in
//! `xbmovie.exe:sub_42d3de`) defines the layout:
//!
//! # Top-level header (first 0x800 bytes, all fields big-endian)
//!
//! ```text
//! 0x000  u32  magic            0x53A722B4 // standard
//!                               0x53A722B5 // thumbnail
//!                               0x53A722B6 // alternate pixel format
//! 0x004  u32  version          0x00010001 (matches PIX_VERSION)
//! 0x008  u32  header_size      0x800
//! 0x00C  u32  reserved         0
//! 0x010  u32  frame_width      frame-buffer width  (e.g. 960)
//! 0x014  u32  frame_height     frame-buffer height (e.g. 720)
//! 0x018  u32  source_width     source/visible width  (e.g. 640)
//! 0x01C  u32  source_height    source/visible height (e.g. 480)
//! 0x020  u32  timestamp_rate   0x02FAF080 = 50,000,000 ticks/sec
//! 0x038  u32  display_width    display width  (e.g. 640)
//! 0x03C  u32  display_height   display height (e.g. 480)
//! ```
//!
//! # Frame records
//!
//! Each frame record begins with a 16-byte big-endian header:
//!
//! ```text
//! 0x0  u32  frame_magic  per-stream constant sentinel; xbmovie
//!                         scans the file for this marker to find
//!                         the start of video data
//! 0x4  u32  flags        bit 0 -> 0x38 bytes of metadata follow
//!                         bit 1 -> 0x600 bytes of palette-ish block
//! 0x8  u32  timestamp    absolute, in `timestamp_rate` ticks
//! 0xC  u32  audio_count  PCM samples multiplier; audio byte count
//!                         = audio_count * 0x1800
//! ```
//!
//! After the header (+ optional metadata/palette blocks), the
//! payload is padded up to a 512-byte boundary relative to the
//! frame start; the YUV 4:2:0 pixel data then follows at that
//! offset. Pixel byte count = `aligned_w * aligned_h * 3 / 2` where
//! `aligned_w` / `aligned_h` are the header's `frame_width` /
//! `frame_height` rounded up to a multiple of 32 (Xbox 360 GPU tile
//! granularity). Audio PCM (`audio_count * 0x1800` bytes) completes
//! the record.
//!
//! So total record size = `512 + aligned_w*aligned_h*3/2 +
//! audio_count*0x1800` when flags=0.
//!
//! This module only implements the pieces needed for `xbm info` and
//! `xbm extract`; the encoding path is in [`super::encode`].

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use rootcause::prelude::*;

use crate::error::Error;

/// Size of the top-level file header in bytes.
pub const HEADER_SIZE: u64 = 0x800;

/// `0x53A722B4` - the main magic value identifying a standard-capture
/// xbmovie intermediate file. `B5` / `B6` are variants we recognise
/// structurally but don't currently decode.
pub const MAGIC_STANDARD: u32 = 0x53A722B4;
pub const MAGIC_THUMBNAIL: u32 = 0x53A722B5;
pub const MAGIC_ALTERNATE: u32 = 0x53A722B6;

#[derive(Debug, thiserror::Error)]
pub enum XbmError {
    #[error("not an .xbm file: expected magic 0x53A722B[4-6], got {got:#010x}")]
    BadMagic { got: u32 },
    #[error(
        "unsupported .xbm version {got:#010x}; only {expected:#010x} \
         (matching xbmovie + PIX_VERSION) is known"
    )]
    UnsupportedVersion { got: u32, expected: u32 },
    #[error("header size {got:#x} is not the expected {expected:#x}")]
    UnexpectedHeaderSize { got: u32, expected: u32 },
    #[error("frame record at {offset:#x} has implausible size {size}")]
    ImplausibleFrameSize { offset: u64, size: u32 },
}

#[derive(Debug, Clone, Copy)]
pub enum MagicVariant {
    Standard,
    Thumbnail,
    Alternate,
}

impl MagicVariant {
    pub fn from_u32(raw: u32) -> Option<Self> {
        Some(match raw {
            MAGIC_STANDARD => Self::Standard,
            MAGIC_THUMBNAIL => Self::Thumbnail,
            MAGIC_ALTERNATE => Self::Alternate,
            _ => return None,
        })
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::Standard => MAGIC_STANDARD,
            Self::Thumbnail => MAGIC_THUMBNAIL,
            Self::Alternate => MAGIC_ALTERNATE,
        }
    }
}

/// The top-level file header. Only the fields we've actually
/// identified from xbmovie.exe are exposed; the rest of the 0x800
/// bytes are preserved as `trailing_raw` for debugging + later RE.
#[derive(Debug, Clone)]
pub struct XbmHeader {
    pub variant: MagicVariant,
    pub version: u32,
    pub header_size: u32,
    /// Frame-buffer width; pixel-data calc uses this rounded up to 32.
    pub frame_width: u32,
    /// Frame-buffer height; pixel-data calc uses this rounded up to 32.
    pub frame_height: u32,
    /// Source/visible width of the captured image.
    pub source_width: u32,
    /// Source/visible height of the captured image.
    pub source_height: u32,
    pub timestamp_rate: u32,
    pub display_width: u32,
    pub display_height: u32,
    /// The remaining bytes of the 0x800 header, for inspection.
    pub raw_tail: Vec<u8>,
}

impl XbmHeader {
    /// Read and validate the 0x800-byte top-level header from a seekable reader.
    pub fn read<R: Read + Seek>(r: &mut R) -> Result<Self, rootcause::Report<Error>> {
        r.seek(SeekFrom::Start(0))
            .map_err(Error::from)
            .into_report()
            .attach("seeking xbm to offset 0")?;
        let mut buf = [0u8; HEADER_SIZE as usize];
        r.read_exact(&mut buf)
            .map_err(Error::from)
            .into_report()
            .attach("reading xbm header block")?;

        let read_u32 = |off: usize| u32::from_be_bytes(buf[off..off + 4].try_into().unwrap());

        let magic = read_u32(0x000);
        let variant = MagicVariant::from_u32(magic).ok_or_else(|| {
            rootcause::Report::new(Error::from(XbmError::BadMagic { got: magic }))
        })?;
        let version = read_u32(0x004);
        if version != crate::commands::pix::PIX_VERSION {
            return Err(rootcause::Report::new(Error::from(
                XbmError::UnsupportedVersion {
                    got: version,
                    expected: crate::commands::pix::PIX_VERSION,
                },
            )));
        }
        let header_size = read_u32(0x008);
        if header_size as u64 != HEADER_SIZE {
            return Err(rootcause::Report::new(Error::from(
                XbmError::UnexpectedHeaderSize {
                    got: header_size,
                    expected: HEADER_SIZE as u32,
                },
            )));
        }

        Ok(XbmHeader {
            variant,
            version,
            header_size,
            frame_width: read_u32(0x010),
            frame_height: read_u32(0x014),
            source_width: read_u32(0x018),
            source_height: read_u32(0x01C),
            timestamp_rate: read_u32(0x020),
            display_width: read_u32(0x038),
            display_height: read_u32(0x03C),
            raw_tail: buf[0x040..].to_vec(),
        })
    }

    /// Width rounded up to a multiple of 32 (xbox framebuffer tile size).
    pub fn aligned_frame_width(&self) -> u32 {
        (self.frame_width + 31) & !31
    }

    /// Height rounded up to a multiple of 32.
    pub fn aligned_frame_height(&self) -> u32 {
        (self.frame_height + 31) & !31
    }

    /// Raw YUV 4:2:0 byte count per frame for the `Standard` variant.
    pub fn frame_pixel_bytes(&self) -> u32 {
        let w = self.aligned_frame_width();
        let h = self.aligned_frame_height();
        // w * h * 1.5 (planar 4:2:0)
        w.wrapping_mul(h).wrapping_mul(3) / 2
    }

    /// Byte count of the plain (detiled) NV12 representation of one
    /// frame: Y plane then interleaved UV plane, both at
    /// `aligned_w` stride and `aligned_h` / `aligned_h/2` height.
    pub fn nv12_bytes(&self) -> u32 {
        self.frame_pixel_bytes()
    }
}

/// Detile a single frame from the on-device layout into plain NV12
/// (Y plane, then interleaved UV plane).
///
/// Recovered by tracing `xbmovie.exe:sub_41e476` (the decoder for
/// magic `0x53A722B4`; the thumbnail magic `0x53A722B5` goes through
/// a different function with a different layout).
///
/// The frame is tiled as 32x32 pixel super-blocks in raster order.
/// Each super-block is 1536 bytes = 32 iters * 48 bytes, and each
/// iter fills a 16x2 patch with:
/// * y offset within super-block: `2 * (i & 15)`
/// * x offset: `16 * ((i >> 4) & 1)` (iters 0..15 fill the left
///   16-wide half top-to-bottom, iters 16..31 fill the right half).
///
/// Per-iter bytes: 32 Y (one per pixel in the 16x2 patch, in the
/// permutation spelled out in [`Y_MAP`]) followed by 16 chroma
/// bytes (1 NV12 chroma row of 8 UV pairs).
///
/// Input and output buffers must both equal
/// [`XbmHeader::frame_pixel_bytes`] in size.
pub fn detile_frame(input: &[u8], output: &mut [u8], header: &XbmHeader) {
    let aligned_w = header.aligned_frame_width() as usize;
    let aligned_h = header.aligned_frame_height() as usize;
    let y_plane_len = aligned_w * aligned_h;
    let uv_plane_len = aligned_w * aligned_h / 2;
    assert_eq!(input.len(), y_plane_len + uv_plane_len);
    assert_eq!(output.len(), y_plane_len + uv_plane_len);

    // Each 4-byte group of Y bytes fills either the even-x or
    // odd-x columns of one patch row in reverse x order.
    const Y_MAP: [(usize, usize); 32] = [
        (6, 0),
        (4, 0),
        (2, 0),
        (0, 0),
        (7, 0),
        (5, 0),
        (3, 0),
        (1, 0),
        (6, 1),
        (4, 1),
        (2, 1),
        (0, 1),
        (7, 1),
        (5, 1),
        (3, 1),
        (1, 1),
        (14, 0),
        (12, 0),
        (10, 0),
        (8, 0),
        (15, 0),
        (13, 0),
        (11, 0),
        (9, 0),
        (14, 1),
        (12, 1),
        (10, 1),
        (8, 1),
        (15, 1),
        (13, 1),
        (11, 1),
        (9, 1),
    ];

    const ITER_BYTES: usize = 48;
    const MACRO: usize = 32;
    const ITERS_PER_SUPER: usize = 32;
    let supers_x = aligned_w / MACRO;
    let supers_y = aligned_h / MACRO;
    let (y_out, uv_out) = output.split_at_mut(y_plane_len);

    for sy in 0..supers_y {
        for sx in 0..supers_x {
            let sb_base_byte = (sy * supers_x + sx) * ITERS_PER_SUPER * ITER_BYTES;
            let sb_x = sx * MACRO;
            let sb_y = sy * MACRO;

            for i in 0..ITERS_PER_SUPER {
                let src = sb_base_byte + i * ITER_BYTES;
                let y_offset = 2 * (i & 15);
                let x_offset = 16 * ((i >> 4) & 1);
                let patch_x = sb_x + x_offset;
                let patch_y = sb_y + y_offset;

                for (byte_i, &(lx, ly)) in Y_MAP.iter().enumerate() {
                    y_out[(patch_y + ly) * aligned_w + patch_x + lx] = input[src + byte_i];
                }

                // Chroma: 16 bytes = 1 chroma row of 8 UV pairs.
                let cy = patch_y / 2;
                let c_dst = cy * aligned_w + patch_x;
                uv_out[c_dst..c_dst + 16].copy_from_slice(&input[src + 32..src + 48]);
            }
        }
    }
}

/// The 16-byte big-endian frame-record header.
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    /// Per-stream sentinel (constant for all frames of one capture).
    /// xbmovie scans the file for this value to locate the first
    /// valid frame; we validate it against the sentinel recovered
    /// during the initial scan.
    pub frame_magic: u32,
    /// Bit 0 set -> 0x38 bytes of metadata follow. Bit 1 set -> 0x600
    /// bytes of palette-ish block follow.
    pub flags: u32,
    /// Timestamp in the file header's `timestamp_rate` ticks (absolute).
    pub timestamp: u32,
    /// Audio sample multiplier. Byte count = `audio_count * 0x1800`.
    pub audio_count: u32,
}

impl FrameHeader {
    pub const SIZE: u64 = 16;

    pub fn parse(buf: &[u8; 16]) -> Self {
        let u = |o: usize| u32::from_be_bytes(buf[o..o + 4].try_into().unwrap());
        FrameHeader {
            frame_magic: u(0),
            flags: u(4),
            timestamp: u(8),
            audio_count: u(12),
        }
    }

    pub fn has_metadata_struct(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn has_palette_block(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Offset from the start of the frame record to the pixel data.
    pub fn pixels_offset_within_record(&self) -> u64 {
        let mut cur = 16u64;
        if self.has_metadata_struct() {
            cur += 0x38;
        }
        if self.has_palette_block() {
            cur += 0x600;
        }
        (cur + 0x1FF) & !0x1FF
    }

    /// Size in bytes of the PCM audio payload tailing the frame.
    pub fn audio_bytes(&self) -> u32 {
        self.audio_count.wrapping_mul(0x1800)
    }
}

/// Iterate frame records in a file. Each yielded `FrameRef` carries
/// the parsed `FrameHeader` plus the absolute file offset of its
/// pixel payload (512-byte aligned, past any per-frame metadata).
#[derive(Debug)]
pub struct FrameCursor<'a, R> {
    reader: &'a mut R,
    file_size: u64,
    next_offset: u64,
    /// Sentinel from the first frame; subsequent frames must match.
    expected_magic: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameRef {
    pub record_offset: u64,
    pub pixels_offset: u64,
    pub audio_offset: u64,
    pub record_size: u64,
    pub header: FrameHeader,
}

impl<'a, R: Read + Seek> FrameCursor<'a, R> {
    pub fn new(reader: &'a mut R) -> Result<Self, rootcause::Report<Error>> {
        let file_size = reader
            .seek(SeekFrom::End(0))
            .map_err(Error::from)
            .into_report()
            .attach("stat-ing xbm file size")?;
        Ok(FrameCursor {
            reader,
            file_size,
            next_offset: HEADER_SIZE,
            expected_magic: None,
        })
    }

    /// Advance to the next frame record. Returns `Ok(None)` at EOF.
    pub fn next_frame(
        &mut self,
        file_header: &XbmHeader,
    ) -> Result<Option<FrameRef>, rootcause::Report<Error>> {
        if self.next_offset + FrameHeader::SIZE > self.file_size {
            return Ok(None);
        }
        self.reader
            .seek(SeekFrom::Start(self.next_offset))
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("seek to frame at {:#x}", self.next_offset))?;
        let mut fh_buf = [0u8; 16];
        self.reader
            .read_exact(&mut fh_buf)
            .map_err(Error::from)
            .into_report()
            .attach("reading frame header")?;
        let header = FrameHeader::parse(&fh_buf);

        // First frame sets the sentinel we expect subsequent frames to
        // carry. That catches a mis-computed record_size walking us
        // off into audio data partway through the file.
        match self.expected_magic {
            None => self.expected_magic = Some(header.frame_magic),
            Some(expected) if expected == header.frame_magic => {}
            Some(_expected) => {
                return Err(
                    rootcause::Report::new(Error::from(XbmError::ImplausibleFrameSize {
                        offset: self.next_offset,
                        size: 0,
                    }))
                    .attach(format!(
                        "frame magic at {:#x} does not match the first frame's sentinel",
                        self.next_offset
                    )),
                );
            }
        }

        let pixels_relative = header.pixels_offset_within_record();
        let pixels_offset = self.next_offset + pixels_relative;
        let audio_offset = pixels_offset + file_header.frame_pixel_bytes() as u64;
        let record_size =
            pixels_relative + file_header.frame_pixel_bytes() as u64 + header.audio_bytes() as u64;

        if self.next_offset + record_size > self.file_size {
            return Err(rootcause::Report::new(Error::from(
                XbmError::ImplausibleFrameSize {
                    offset: self.next_offset,
                    size: record_size as u32,
                },
            )));
        }

        let record = FrameRef {
            record_offset: self.next_offset,
            pixels_offset,
            audio_offset,
            record_size,
            header,
        };
        self.next_offset += record_size;
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_variants_round_trip() {
        for v in [
            MagicVariant::Standard,
            MagicVariant::Thumbnail,
            MagicVariant::Alternate,
        ] {
            let round = MagicVariant::from_u32(v.as_u32()).unwrap();
            assert!(matches!(
                (v, round),
                (MagicVariant::Standard, MagicVariant::Standard)
                    | (MagicVariant::Thumbnail, MagicVariant::Thumbnail)
                    | (MagicVariant::Alternate, MagicVariant::Alternate)
            ));
        }
    }

    #[test]
    fn frame_pixel_bytes_960x720() {
        let h = XbmHeader {
            variant: MagicVariant::Standard,
            version: 0x0001_0001,
            header_size: 0x800,
            frame_width: 960,
            frame_height: 720,
            source_width: 640,
            source_height: 480,
            timestamp_rate: 50_000_000,
            display_width: 640,
            display_height: 480,
            raw_tail: Vec::new(),
        };
        // 720 rounds up to 736 (32-aligned), 960 is already 32-aligned.
        assert_eq!(h.aligned_frame_width(), 960);
        assert_eq!(h.aligned_frame_height(), 736);
        // 960 * 736 * 1.5 = 1,059,840
        assert_eq!(h.frame_pixel_bytes(), 1_059_840);
    }

    #[test]
    fn frame_header_flags() {
        let raw = [
            0x9b, 0x58, 0xe7, 0x1a, // frame_magic
            0x00, 0x00, 0x00, 0x03, // flags = 0b11 (both metadata + palette)
            0x00, 0x0F, 0x42, 0x40, // timestamp = 1_000_000
            0x00, 0x00, 0x00, 0x03, // audio_count = 3
        ];
        let fh = FrameHeader::parse(&raw);
        assert_eq!(fh.frame_magic, 0x9b58e71a);
        assert_eq!(fh.flags, 3);
        assert!(fh.has_metadata_struct());
        assert!(fh.has_palette_block());
        assert_eq!(fh.timestamp, 1_000_000);
        assert_eq!(fh.audio_count, 3);
        assert_eq!(fh.audio_bytes(), 3 * 0x1800);
        // 16 base + 0x38 metadata + 0x600 palette = 0x648, rounded up to 512 = 0x800 = 2048
        assert_eq!(fh.pixels_offset_within_record(), 2048);
    }

    #[test]
    fn pixels_offset_no_flags() {
        let raw = [0u8; 16];
        // frame_magic=0, flags=0 -> offset = round_up(16, 512) = 512
        assert_eq!(FrameHeader::parse(&raw).pixels_offset_within_record(), 512);
    }
}
