#[diplomat::bridge]
pub mod ffi {
    use openxbdm_client::commands::Screenshot;
    use openxbdm_client::commands::screenshot::detile_32bpp;

    use crate::buffers::ffi::OpenxbdmBytes;

    /// `screenshot` reply: the raw framebuffer plus its metadata.
    #[diplomat::opaque]
    pub struct OpenxbdmScreenshot {
        pitch: u32,
        width: u32,
        height: u32,
        format_raw: u32,
        is_linear_xrgb8888: bool,

        offset_x: u32,
        offset_y: u32,
        framebuffer_size: u32,
        shown_width: u32,
        shown_height: u32,
        colorspace: u32,

        data: Vec<u8>,
    }

    impl From<Screenshot> for OpenxbdmScreenshot {
        fn from(screenshot: Screenshot) -> Self {
            let metadata = screenshot.metadata;

            Self {
                pitch: metadata.pitch,
                width: metadata.width,
                height: metadata.height,
                format_raw: metadata.format.raw(),
                is_linear_xrgb8888: metadata.format.is_linear_xrgb8888(),
                offset_x: metadata.offset_x,
                offset_y: metadata.offset_y,
                framebuffer_size: metadata.framebuffer_size,
                shown_width: metadata.shown_width,
                shown_height: metadata.shown_height,
                colorspace: metadata.colorspace,
                data: screenshot.data,
            }
        }
    }

    impl OpenxbdmScreenshot {
        pub fn pitch(&self) -> u32 {
            self.pitch
        }

        pub fn width(&self) -> u32 {
            self.width
        }

        pub fn height(&self) -> u32 {
            self.height
        }

        /// Raw XBDM pixel-format value with the `0x80000000` ready-marker
        /// stripped.
        pub fn format_raw(&self) -> u32 {
            self.format_raw
        }

        /// True when the format is a known linear 32-bit XRGB layout that
        /// the built-in RGBA8 decoder understands.
        pub fn is_linear_xrgb8888(&self) -> bool {
            self.is_linear_xrgb8888
        }

        pub fn offset_x(&self) -> u32 {
            self.offset_x
        }

        pub fn offset_y(&self) -> u32 {
            self.offset_y
        }

        pub fn framebuffer_size(&self) -> u32 {
            self.framebuffer_size
        }

        pub fn shown_width(&self) -> u32 {
            self.shown_width
        }

        pub fn shown_height(&self) -> u32 {
            self.shown_height
        }

        pub fn colorspace(&self) -> u32 {
            self.colorspace
        }

        pub fn data_len(&self) -> usize {
            self.data.len()
        }

        pub fn copy_data(&self, dst: &mut [u8]) -> usize {
            let len = self.data.len().min(dst.len());
            dst[..len].copy_from_slice(&self.data[..len]);

            len
        }

        /// Decode the raw framebuffer into a `width * height * 4` RGBA
        /// byte buffer. Returns a zero-length handle when the pixel
        /// format isn't a known linear XRGB layout or the body is short.
        pub fn to_rgba8(&self) -> Box<OpenxbdmBytes> {
            if !self.is_linear_xrgb8888 {
                return Box::new(OpenxbdmBytes(Vec::new()));
            }

            let Some(linear) = detile_32bpp(
                &self.data,
                self.width,
                self.height,
                self.offset_x,
                self.offset_y,
            ) else {
                return Box::new(OpenxbdmBytes(Vec::new()));
            };

            let mut rgba = Vec::with_capacity(linear.len());
            for &[blue, green, red, _] in linear.as_chunks::<4>().0 {
                rgba.extend_from_slice(&[red, green, blue, 0xFF]);
            }

            Box::new(OpenxbdmBytes(rgba))
        }
    }
}
