//! `screenshot`: save the console framebuffer.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use image::ImageFormat;
use image::RgbaImage;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::ui::ok_tag;

pub async fn screenshot<T>(
    client: &mut Client<T, Connected>,
    output: &str,
    raw: bool,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let shot = client.screenshot().await?;
    let meta = shot.metadata;
    eprintln!(
        "{} {}x{} pitch={} bytes={} format={:?}",
        ok_tag("captured"),
        meta.width,
        meta.height,
        meta.pitch,
        meta.framebuffer_size,
        meta.format
    );

    if raw {
        std::fs::write(output, &shot.data)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("writing raw framebuffer to {output}"))?;

        let sidecar = format!("{output}.meta");
        let meta_text = format!(
            "pitch={}\nwidth={}\nheight={}\nformat={:?}\noffset_x={}\noffset_y={}\nframebuffer_size={}\nshown_width={}\nshown_height={}\npitch_hex={:#010x}\nformat_raw={:#010x}\n",
            meta.pitch,
            meta.width,
            meta.height,
            meta.format,
            meta.offset_x,
            meta.offset_y,
            meta.framebuffer_size,
            meta.shown_width,
            meta.shown_height,
            meta.pitch,
            meta.format.raw()
        );
        std::fs::write(&sidecar, meta_text)
            .map_err(Error::from)
            .into_report()
            .attach("writing metadata sidecar")?;
        eprintln!(
            "{} raw framebuffer + metadata to {output} (+ {sidecar})",
            ok_tag("wrote"),
        );

        return Ok(());
    }

    let rgba = shot
        .to_rgba8()
        .map_err(Error::from)
        .into_report()
        .attach("decoding screenshot; re-run with --raw to keep the tiled body")?;
    let Some(buffer) = RgbaImage::from_raw(meta.width, meta.height, rgba) else {
        return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
            .attach("RgbaImage::from_raw rejected the buffer dimensions"));
    };

    let png_message = format!("encoding PNG to {output}");
    buffer
        .save_with_format(output, ImageFormat::Png)
        .map_err(|e| {
            Report::new(Error::from(std::io::Error::other(e.to_string()))).attach(png_message)
        })?;
    eprintln!("{} PNG to {output}", ok_tag("wrote"));

    Ok(())
}
