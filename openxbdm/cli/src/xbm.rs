//! `xbm`: inspect, extract, and encode local `.xbm` capture files.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use openxbdm_client::commands::pix::FrameCursor;
use openxbdm_client::commands::pix::FrameRef;
use openxbdm_client::commands::pix::XbmHeader;
use openxbdm_client::commands::pix::detile_frame;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::args::XbmCommand;
use crate::ui::humanize_bytes;
use crate::ui::ok_tag;

pub fn run(command: &XbmCommand) -> Result<(), Report<Error>> {
    match command {
        XbmCommand::Info { file } => info(file),
        XbmCommand::Extract {
            file,
            output_dir,
            concat,
            raw,
        } => extract(file, output_dir, *concat, *raw),
        XbmCommand::Encode {
            file,
            output,
            crop,
            fps,
            crf,
            ffmpeg_args,
        } => {
            // An fps of 0 asks for the rate derived from the timestamps.
            let fps_override = (*fps > 0.0).then_some(*fps);

            // Probe ffmpeg first so a missing binary fails before any work.
            require_ffmpeg()?;
            encode_to_mp4(file, output, crop, fps_override, *crf, ffmpeg_args)
        }
    }
}

/// Encode `file` to `output` by streaming detiled NV12 frames to ffmpeg.
/// Callers check for ffmpeg with [`require_ffmpeg`] first.
pub fn encode_to_mp4(
    file: &str,
    output: &str,
    crop_mode: &str,
    fps_override: Option<f64>,
    crf: u32,
    extra_args: &[String],
) -> Result<(), Report<Error>> {
    const DEFAULT_FPS: f64 = 30.0;

    let mut reader = open_xbm(file)?;
    let header = XbmHeader::read(&mut reader)?;
    let aligned_width = header.aligned_frame_width();
    let aligned_height = header.aligned_frame_height();

    let (crop_width, crop_height) = match crop_mode {
        "frame" => (header.frame_width, header.frame_height),
        "source" => (header.source_width, header.source_height),
        "none" => (aligned_width, aligned_height),
        other => {
            return Err(
                Report::new(Error::from(ArgumentError::EmptyFilename)).attach(format!(
                    "--crop must be one of `frame`, `source`, `none`; got {other:?}"
                )),
            );
        }
    };

    let frames = read_frames(&mut reader, &header)?;
    if frames.is_empty() {
        return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
            .attach("xbm contains no frame records"));
    }
    let fps = fps_override
        .or_else(|| frame_rate(&frames, &header))
        .unwrap_or(DEFAULT_FPS);

    let size = format!("{aligned_width}x{aligned_height}");
    let framerate = format!("{fps:.3}");
    let crop_filter = format!("crop={crop_width}:{crop_height}:0:0");
    let crf = crf.to_string();
    let mut command = Command::new("ffmpeg");
    command
        .arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-stats")
        .arg("-f")
        .arg("rawvideo")
        .arg("-pix_fmt")
        .arg("nv12")
        .arg("-s")
        .arg(&size)
        .arg("-framerate")
        .arg(&framerate)
        .arg("-i")
        .arg("-")
        .arg("-vf")
        .arg(&crop_filter)
        .arg("-c:v")
        .arg("libx264")
        .arg("-crf")
        .arg(&crf)
        .arg("-pix_fmt")
        .arg("yuv420p");
    for extra in extra_args {
        command.arg(extra);
    }
    command.arg("-y").arg(output).stdin(Stdio::piped());

    eprintln!(
        "{} encoding {} frames at {aligned_width}x{aligned_height} -> {crop_width}x{crop_height} @ {fps:.2} fps -> {output}",
        ok_tag("encoding"),
        frames.len()
    );
    let mut child = command
        .spawn()
        .map_err(Error::from)
        .into_report()
        .attach("spawning ffmpeg")?;
    let mut stdin = child.stdin.take().expect("stdin configured as piped");

    let pixel_bytes = header.frame_pixel_bytes() as usize;
    let mut tiled = vec![0u8; pixel_bytes];
    let mut nv12 = vec![0u8; pixel_bytes];
    for frame in &frames {
        reader
            .seek(SeekFrom::Start(frame.pixels_offset))
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("seek to pixels at {:#x}", frame.pixels_offset))?;
        reader
            .read_exact(&mut tiled)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("reading pixels at {:#x}", frame.pixels_offset))?;
        detile_frame(&tiled, &mut nv12, &header);

        // ffmpeg exited; its status below explains why.
        if stdin.write_all(&nv12).is_err() {
            break;
        }
    }

    // Closing stdin ends ffmpeg's input.
    drop(stdin);
    let status = child
        .wait()
        .map_err(Error::from)
        .into_report()
        .attach("waiting on ffmpeg")?;
    if !status.success() {
        return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
            .attach(format!("ffmpeg exited with {status}")));
    }
    eprintln!("{} wrote {output}", ok_tag("done"));

    Ok(())
}

/// Fail when `ffmpeg` is not on `$PATH`.
pub fn require_ffmpeg() -> Result<(), Report<Error>> {
    let found = Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if found {
        return Ok(());
    }

    Err(
        Report::new(Error::from(ArgumentError::EmptyFilename)).attach(
            "ffmpeg not found on $PATH. Install it (`nix-shell -p ffmpeg`, \
         `brew install ffmpeg`, etc.) and retry. The `xbm encode` \
         subcommand streams decoded NV12 frames to ffmpeg's stdin.",
        ),
    )
}

fn info(file: &str) -> Result<(), Report<Error>> {
    let mut reader = open_xbm(file)?;
    let header = XbmHeader::read(&mut reader)?;
    println!(
        "magic        {:?} ({:#010x})  version {:#010x}  header_size {:#x}",
        header.variant,
        header.variant.as_u32(),
        header.version,
        header.header_size
    );
    println!(
        "frame        {}x{}  aligned {}x{}  (this drives pixel stride)",
        header.frame_width,
        header.frame_height,
        header.aligned_frame_width(),
        header.aligned_frame_height(),
    );
    println!(
        "source       {}x{}  display {}x{}",
        header.source_width, header.source_height, header.display_width, header.display_height,
    );
    println!(
        "tick rate    {} ticks/s  yuv bytes/frame {}",
        header.timestamp_rate,
        header.frame_pixel_bytes(),
    );

    let mut cursor = FrameCursor::new(&mut reader)?;
    let mut frame_count = 0u64;
    let mut audio_bytes = 0u64;
    let mut first_timestamp: Option<u32> = None;
    let mut last_timestamp: Option<u32> = None;
    let mut first_record_size: Option<u64> = None;
    let mut frame_magic: Option<u32> = None;
    while let Some(frame) = cursor.next_frame(&header)? {
        frame_count += 1;
        audio_bytes += frame.header.audio_bytes() as u64;
        first_timestamp.get_or_insert(frame.header.timestamp);
        last_timestamp = Some(frame.header.timestamp);
        first_record_size.get_or_insert(frame.record_size);
        frame_magic.get_or_insert(frame.header.frame_magic);
    }

    println!("frames       {frame_count}");
    if let Some(magic) = frame_magic {
        println!("frame magic  {magic:#010x}");
    }
    if let (Some(first), Some(last)) = (first_timestamp, last_timestamp) {
        let span = last.wrapping_sub(first);
        let seconds = span as f64 / header.timestamp_rate as f64;
        let fps = if seconds > 0.0 {
            frame_count.saturating_sub(1) as f64 / seconds
        } else {
            0.0
        };
        println!("timestamps   {first} -> {last} (span {span}, {seconds:.3}s, {fps:.2} fps)");
    }
    println!("audio bytes  {audio_bytes}");
    if let Some(size) = first_record_size {
        println!("first record {size} bytes");
    }

    Ok(())
}

fn extract(file: &str, output_dir: &str, concat: bool, raw: bool) -> Result<(), Report<Error>> {
    std::fs::create_dir_all(output_dir)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating {output_dir}"))?;
    let mut reader = open_xbm(file)?;
    let header = XbmHeader::read(&mut reader)?;
    let pixel_bytes = header.frame_pixel_bytes() as usize;

    let extension = if raw { "tiled" } else { "nv12" };
    let mut concat_output = if concat {
        let path = format!("{output_dir}/frames.{extension}");
        let concat_file = File::create(&path)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("creating {path}"))?;
        Some((concat_file, path))
    } else {
        None
    };

    let frames = read_frames(&mut reader, &header)?;

    let mut tiled = vec![0u8; pixel_bytes];
    let mut nv12 = vec![0u8; pixel_bytes];
    for (index, frame) in frames.iter().enumerate() {
        reader
            .seek(SeekFrom::Start(frame.pixels_offset))
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("seek to pixels at {:#x}", frame.pixels_offset))?;
        reader
            .read_exact(&mut tiled)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("reading pixel bytes at {:#x}", frame.pixels_offset))?;

        let payload: &[u8] = if raw {
            &tiled
        } else {
            detile_frame(&tiled, &mut nv12, &header);
            &nv12
        };

        let out_path = format!("{output_dir}/frame-{index:05}.{extension}");
        std::fs::write(&out_path, payload)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("writing {out_path}"))?;
        if let Some((concat_file, _)) = concat_output.as_mut() {
            concat_file
                .write_all(payload)
                .map_err(Error::from)
                .into_report()
                .attach("appending to concat")?;
        }
    }

    // The metadata file records an unknown rate as 0.
    let fps = frame_rate(&frames, &header).unwrap_or(0.0);
    let layout = if raw {
        "tiled Xbox 360 16-wide-column NV12 (raw on-device layout)"
    } else {
        "nv12 (Y plane, then interleaved UV plane; detiled from on-device layout)"
    };
    let ffmpeg_pixel_format = if raw {
        "nv12  # WILL NOT RENDER -- re-run without --raw"
    } else {
        "nv12"
    };
    let meta = format!(
        "# xbmovie .xbm frame dump\n\
         source: {file}\n\
         magic: {:?}\n\
         frame_width: {}\n\
         frame_height: {}\n\
         aligned_width: {}\n\
         aligned_height: {}\n\
         visible_crop: {}x{}\n\
         pixel_format: {layout}\n\
         frame_count: {}\n\
         approx_fps: {fps:.3}\n\
         \n\
         # Reconstruct (crops off the 32-alignment padding):\n\
         # ffmpeg -f rawvideo -pix_fmt {ffmpeg_pixel_format} -s {}x{} -r {} \\\n\
         #   -i frames.{extension} -vf crop={}:{}:0:0 \\\n\
         #   -c:v libx264 -pix_fmt yuv420p out.mp4\n",
        header.variant,
        header.frame_width,
        header.frame_height,
        header.aligned_frame_width(),
        header.aligned_frame_height(),
        header.source_width,
        header.source_height,
        frames.len(),
        header.aligned_frame_width(),
        header.aligned_frame_height(),
        fps.round() as u32,
        header.frame_width,
        header.frame_height,
    );
    let meta_path = format!("{output_dir}/metadata.txt");
    std::fs::write(&meta_path, meta)
        .map_err(Error::from)
        .into_report()
        .attach("writing metadata")?;

    let frame_count = frames.len();
    eprintln!(
        "{} extracted {frame_count} frame{s} ({} pixel bytes each) -> {output_dir}",
        ok_tag("done"),
        humanize_bytes(pixel_bytes as u64),
        s = if frame_count == 1 { "" } else { "s" },
    );
    if let Some((_, path)) = concat_output {
        eprintln!("{} concatenated stream -> {path}", ok_tag("done"));
    }
    eprintln!("{} metadata -> {meta_path}", ok_tag("done"));

    Ok(())
}

fn open_xbm(file: &str) -> Result<File, Report<Error>> {
    File::open(file)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("opening xbm file {file}"))
}

/// Index every frame record in the file.
fn read_frames(reader: &mut File, header: &XbmHeader) -> Result<Vec<FrameRef>, Report<Error>> {
    let mut cursor = FrameCursor::new(reader)?;

    let mut frames = Vec::new();
    while let Some(frame) = cursor.next_frame(header)? {
        frames.push(frame);
    }

    Ok(frames)
}

/// Frames per second over the timestamp span of `frames`. `None` when the
/// span is empty or the rate is not positive.
fn frame_rate(frames: &[FrameRef], header: &XbmHeader) -> Option<f64> {
    let [first, .., last] = frames else {
        return None;
    };

    let span = last.header.timestamp.wrapping_sub(first.header.timestamp);
    if span == 0 {
        return None;
    }

    let fps = (frames.len() - 1) as f64 * header.timestamp_rate as f64 / span as f64;
    (fps > 0.0).then_some(fps)
}
