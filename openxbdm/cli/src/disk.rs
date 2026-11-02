//! Read-only block device subcommands over `gethddblk`.

mod inspect;

use std::io;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use clap::Subcommand;
use fatxtool::FatxCommand;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::DeviceName;
use openxbdm_client::commands::SectorCount;
use openxbdm_client::commands::SectorIndex;
use openxbdm_client::disk::DeviceSize;
use openxbdm_client::disk::DiskError;
use openxbdm_client::disk::JournalError;
use openxbdm_client::disk::KNOWN_DEVICES;
use openxbdm_client::disk::MAX_LINE_LEN;
use openxbdm_client::disk::Pull;
use openxbdm_client::disk::PullHeader;
use openxbdm_client::disk::PullStep;
use openxbdm_client::disk::RemoteDisk;
use openxbdm_client::disk::Signature;
use openxbdm_client::disk::known_device;
use openxbdm_client::error::Error;
use rootcause::Report;
use same_file::Handle;
use tabled::Tabled;
use tokio::fs::File;
use tokio::fs::OpenOptions;
use tokio::io::AsyncBufRead;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;

use self::inspect::Inspection;
use self::inspect::LayoutArguments;
use self::inspect::VolumeArguments;
use crate::args::parse_u64;
use crate::memory::print_hex_dump;
use crate::ui::UiOptions;
use crate::ui::ok_tag;
use crate::ui::print_table;

/// Every subcommand only reads the console's storage.
#[derive(Subcommand, Debug)]
pub enum DiskCommand {
    /// List the known block devices and probe their size and first bytes.
    ///
    /// Without arguments, probe each storage device on the allow list
    /// (hard disk partitions and memory unit and USB storage); with
    /// arguments, probe only the named devices. Devices that are not disks
    /// are never probed unless named: `gethddblk` on `\Device\Flash`
    /// stopped kernel 16547.
    Devices {
        /// NT device names to probe, e.g. '\Device\BuiltInMuSfc'.
        devices: Vec<String>,
    },

    /// Read bytes of a device. Prints a hex dump unless `-o` is given.
    Read {
        /// NT device name, e.g. '\Device\BuiltInMuSfc'.
        device: String,
        /// Byte offset, decimal or `0x` hex.
        offset: String,
        /// Byte count, decimal or `0x` hex.
        length: String,
        /// Write the bytes to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Copy a whole device to an image file.
    ///
    /// `<output>.progress` records each completed 4 MiB segment and its
    /// SHA-256, so an interrupted pull continues with `--resume`.
    Pull {
        /// NT device name, e.g. '\Device\Harddisk0\Partition1'.
        device: String,
        /// Image file to write.
        output: PathBuf,
        /// Continue the pull that `<output>.progress` records.
        #[arg(long)]
        resume: bool,
    },

    /// Identify the device and print its partition layout, as
    /// `fatxtool partitions` does.
    Partitions {
        /// NT device name, e.g. '\Device\Harddisk0\Partition0'.
        device: String,
        #[command(flatten)]
        layout: LayoutArguments,
    },

    /// Run a read-only `fatxtool` command on a FATX volume of a device.
    ///
    /// The volume is the whole device unless `--offset` and `--length` or
    /// `--partition` select one. Extracted and recovered files are written
    /// on this computer.
    Fatx {
        /// NT device name, e.g. '\Device\BuiltInMuSfc'.
        device: String,
        #[command(flatten)]
        volume: VolumeArguments,
        #[command(subcommand)]
        command: FatxCommand,
    },
}

pub async fn run<T>(
    mut client: Client<T, Connected>,
    command: DiskCommand,
    ui: UiOptions,
) -> Result<Client<T, Connected>, Report>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        DiskCommand::Devices { devices } => {
            Box::pin(list_devices(&mut client, &devices, ui)).await?;

            Ok(client)
        }
        DiskCommand::Read {
            device,
            offset,
            length,
            output,
        } => {
            let disk = RemoteDisk::open(client, device_name(&device)?).await?;
            Box::pin(read(&disk, &offset, &length, output.as_deref())).await?;

            Ok(disk.into_client())
        }
        DiskCommand::Pull {
            device,
            output,
            resume,
        } => {
            let disk = RemoteDisk::open(client, device_name(&device)?).await?;
            Box::pin(pull(&disk, &output, resume, ui)).await?;

            Ok(disk.into_client())
        }
        DiskCommand::Partitions { device, layout } => {
            let disk = RemoteDisk::open(client, device_name(&device)?).await?;
            Box::pin(inspect::run(&disk, Inspection::Partitions(layout))).await?;

            Ok(disk.into_client())
        }
        DiskCommand::Fatx {
            device,
            volume,
            command,
        } => {
            let disk = RemoteDisk::open(client, device_name(&device)?).await?;
            Box::pin(inspect::run(&disk, Inspection::Volume { volume, command })).await?;

            Ok(disk.into_client())
        }
    }
}

fn device_name(name: &str) -> Result<DeviceName, Report<Error>> {
    DeviceName::new(name)
        .map_err(|error| Report::new(Error::from(error)).attach(format!("device {name:?}")))
}

enum Probe {
    NotProbed,
    Unreadable,
    Readable {
        size: DeviceSize,
        signature: Signature,
    },
}

async fn list_devices<T>(
    client: &mut Client<T, Connected>,
    named: &[String],
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[derive(Tabled)]
    struct Row {
        device: String,
        drives: String,
        readable: &'static str,
        size: String,
        signature: String,
        contents: &'static str,
    }

    let targets: Vec<(String, bool)> = if named.is_empty() {
        KNOWN_DEVICES
            .iter()
            .map(|device| (device.name.to_owned(), device.is_probe_safe()))
            .collect()
    } else {
        named.iter().map(|name| (name.clone(), true)).collect()
    };

    let mut rows = Vec::with_capacity(targets.len());
    for (name, probe) in targets {
        let probe = if probe {
            probe_device(client, &device_name(&name)?).await?
        } else {
            Probe::NotProbed
        };
        let known = known_device(&name);

        let (readable, size, signature) = match probe {
            Probe::NotProbed => ("not probed", String::new(), String::new()),
            Probe::Unreadable => ("no", String::new(), String::new()),
            Probe::Readable { size, signature } => (
                "yes",
                format!("{:#x} ({})", size.bytes(), ui.format_bytes(size.bytes())),
                signature.to_string(),
            ),
        };
        rows.push(Row {
            device: name,
            drives: known
                .map(|device| device.drives.join(","))
                .unwrap_or_default(),
            readable,
            size,
            signature,
            contents: known.map(|device| device.contents).unwrap_or_default(),
        });
    }

    if !ui.is_pretty() {
        for row in rows {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                row.device, row.drives, row.readable, row.size, row.signature, row.contents
            );
        }
        return Ok(());
    }

    print_table(&ui.heading("devices"), rows);

    Ok(())
}

async fn probe_device<T>(
    client: &mut Client<T, Connected>,
    device: &DeviceName,
) -> Result<Probe, Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let Some(size) = client.discover_device_size(device).await? else {
        return Ok(Probe::Unreadable);
    };

    let sector = client
        .read_sectors(device, SectorIndex(0), SectorCount::ONE)
        .await?;
    let signature = Signature::from_sector(&sector).expect("a sector is 512 bytes");

    Ok(Probe::Readable { size, signature })
}

async fn read<T>(
    disk: &RemoteDisk<T>,
    offset: &str,
    length: &str,
    output: Option<&Path>,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const CHUNK_LEN: u64 = SectorCount::MAX.byte_len() as u64;

    let offset = parse_u64(offset).map_err(|error| Report::new(error).attach("offset"))?;
    let length = parse_u64(length).map_err(|error| Report::new(error).attach("length"))?;
    let size = disk.size().bytes();
    let out_of_bounds = |end: u64| {
        Report::new(Error::from(DiskError::RangeOutOfBounds {
            start: offset,
            end,
            size,
        }))
    };
    let end = offset
        .checked_add(length)
        .ok_or_else(|| out_of_bounds(u64::MAX))?;
    if end > size {
        return Err(out_of_bounds(end));
    }

    let mut file = match output {
        Some(path) => {
            let file = File::create(path)
                .await
                .map_err(file_error("creating", path))?;
            Some((file, path))
        }
        None => None,
    };

    let mut next = offset;
    while next < end {
        let chunk_end = next
            .checked_add(CHUNK_LEN)
            .map_or(end, |limit| limit.min(end));
        let bytes = disk.read(next..chunk_end).await?;
        match &mut file {
            Some((file, path)) => {
                file.write_all(&bytes)
                    .await
                    .map_err(file_error("writing", path))?;
            }
            None => print_hex_dump(next, &bytes, &[]),
        }
        next = chunk_end;
    }

    if let Some((mut file, path)) = file {
        file.flush().await.map_err(file_error("flushing", path))?;
        eprintln!(
            "{} {length:#x} bytes at {offset:#x} of {} to {}",
            ok_tag("read"),
            disk.device(),
            path.display()
        );
    }

    Ok(())
}

async fn pull<T>(
    disk: &RemoteDisk<T>,
    output: &Path,
    resume: bool,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const STATUS_INTERVAL: u64 = 0x400_0000;

    let journal_path = {
        let mut path = output.as_os_str().to_owned();
        path.push(".progress");
        PathBuf::from(path)
    };
    let header = PullHeader::new(disk.device().clone(), disk.size());
    let size = disk.size().bytes();

    let resuming = resume
        && tokio::fs::try_exists(&journal_path)
            .await
            .map_err(file_error("checking", &journal_path))?;
    let (mut pull, mut image, mut journal) = if resuming {
        open_resumed(header, output, &journal_path).await?
    } else {
        create_fresh(header, output, &journal_path).await?
    };

    let resumed_bytes = pull.completed_bytes();
    let bar = ui.progress(size, "pull");
    bar.set_position(resumed_bytes);
    if resumed_bytes > 0 {
        eprintln!(
            "resuming {}: {resumed_bytes:#x} of {size:#x} bytes already in {}",
            disk.device(),
            output.display()
        );
    }

    let started = Instant::now();
    let mut position = None;
    let mut next_status = resumed_bytes + STATUS_INTERVAL;
    while let PullStep::Read(range) = pull.step() {
        let bytes = disk.read(range.clone()).await?;

        if position != Some(range.start) {
            image
                .seek(SeekFrom::Start(range.start))
                .await
                .map_err(file_error("seeking", output))?;
        }
        image
            .write_all(&bytes)
            .await
            .map_err(file_error("writing", output))?;
        position = Some(range.end);
        bar.inc(bytes.len() as u64);

        let Some(record) = pull.feed(&bytes).map_err(Error::from)? else {
            continue;
        };

        // The record must not reach the progress file before its bytes are
        // durable in the image.
        image
            .flush()
            .await
            .map_err(file_error("flushing", output))?;
        image
            .sync_data()
            .await
            .map_err(file_error("syncing", output))?;
        journal
            .write_all(record.line().as_bytes())
            .await
            .map_err(file_error("writing", &journal_path))?;
        journal
            .sync_data()
            .await
            .map_err(file_error("syncing", &journal_path))?;

        if bar.is_hidden() && pull.completed_bytes() >= next_status {
            next_status = pull.completed_bytes() + STATUS_INTERVAL;
            tracing::info!(
                "{:#x} of {size:#x} bytes, {}/s",
                pull.completed_bytes(),
                ui.format_bytes(rate(pull.completed_bytes() - resumed_bytes, started))
            );
        }
    }

    bar.finish_and_clear();
    let transferred = pull.completed_bytes() - resumed_bytes;
    eprintln!(
        "{} {} ({size:#x} bytes) to {}; {} this run in {:.1} s, {}/s",
        ok_tag("pulled"),
        disk.device(),
        output.display(),
        ui.format_bytes(transferred),
        started.elapsed().as_secs_f64(),
        ui.format_bytes(rate(transferred, started))
    );

    Ok(())
}

async fn create_fresh(
    header: PullHeader,
    output: &Path,
    journal_path: &Path,
) -> Result<(Pull, File, File), Report<Error>> {
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(journal_path)
        .await
        .map_err(file_error("creating", journal_path))
        .map_err(|report| report.attach("pass --resume to continue the pull it records"))?;

    let image = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .await
    {
        Ok(image) => image,
        Err(error) => {
            // The progress file is ours and records nothing yet.
            let _ = tokio::fs::remove_file(journal_path).await;
            return Err(file_error("creating", output)(error));
        }
    };

    let initialized = async {
        ensure_distinct(&journal, journal_path, &image, output).await?;
        image
            .set_len(header.size().bytes())
            .await
            .map_err(file_error("sizing", output))?;
        // The image length must be durable before the header that relies
        // on it.
        image
            .sync_all()
            .await
            .map_err(file_error("syncing", output))?;
        journal
            .write_all(header.line().as_bytes())
            .await
            .map_err(file_error("writing", journal_path))?;
        journal
            .sync_data()
            .await
            .map_err(file_error("syncing", journal_path))?;
        sync_directory(output).await
    }
    .await;

    if let Err(report) = initialized {
        // Both files are ours and record nothing that a resume could use.
        drop((image, journal));
        let _ = tokio::fs::remove_file(journal_path).await;
        let _ = tokio::fs::remove_file(output).await;
        return Err(report);
    }

    Ok((Pull::new(header), image, journal))
}

async fn open_resumed(
    header: PullHeader,
    output: &Path,
    journal_path: &Path,
) -> Result<(Pull, File, File), Report<Error>> {
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .open(journal_path)
        .await
        .map_err(file_error("opening", journal_path))?;
    let mut image = OpenOptions::new()
        .read(true)
        .write(true)
        .open(output)
        .await
        .map_err(file_error("opening", output))?;
    ensure_distinct(&journal, journal_path, &image, output).await?;

    let image_len = image
        .metadata()
        .await
        .map_err(file_error("reading metadata of", output))?
        .len();
    if image_len != header.size().bytes() {
        return Err(Report::new(Error::from(DiskError::ImageLengthMismatch {
            expected: header.size().bytes(),
            actual: image_len,
        })));
    }

    let journal_error = |error: JournalError| {
        Report::new(Error::from(DiskError::from(error))).attach(journal_path.display().to_string())
    };
    let mut reader = BufReader::new(&mut journal);
    let mut line = Vec::new();
    let mut segment = Vec::new();
    let mut complete_len = 0u64;
    let mut pull = None;
    let mut line_number = 0usize;
    loop {
        let kind = read_journal_line(&mut reader, &mut line)
            .await
            .map_err(file_error("reading", journal_path))?;
        match kind {
            JournalLine::Complete => {}
            // A final line without its line feed was cut short by an
            // interruption; its segment is read again.
            JournalLine::Torn | JournalLine::End => break,
            JournalLine::TooLong if line_number == 0 => {
                return Err(journal_error(JournalError::Header { line: 1 }));
            }
            JournalLine::TooLong => {
                return Err(journal_error(JournalError::Record {
                    line: line_number + 1,
                }));
            }
        }

        line_number += 1;
        complete_len += line.len() as u64;
        let text = core::str::from_utf8(&line[..line.len() - 1])
            .map_err(|_| journal_error(JournalError::Record { line: line_number }))?;
        let Some(pull) = &mut pull else {
            pull = Some(Pull::resume(header.clone(), text).map_err(journal_error)?);
            continue;
        };

        let record = pull.record(line_number, text).map_err(journal_error)?;
        let range = record.range();
        segment.resize((range.end - range.start) as usize, 0);
        image
            .seek(SeekFrom::Start(range.start))
            .await
            .map_err(file_error("seeking", output))?;
        image
            .read_exact(&mut segment)
            .await
            .map_err(file_error("reading", output))?;
        record.verify(&segment).map_err(|error| {
            Report::new(Error::from(error)).attach(output.display().to_string())
        })?;
        pull.restore(&record);
    }

    let Some(pull) = pull else {
        return Err(journal_error(JournalError::Empty));
    };

    journal
        .set_len(complete_len)
        .await
        .map_err(file_error("truncating", journal_path))?;
    journal
        .seek(SeekFrom::Start(complete_len))
        .await
        .map_err(file_error("seeking", journal_path))?;

    Ok((pull, image, journal))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalLine {
    /// A line with its line feed.
    Complete,
    /// Bytes without a line feed before the end of the file.
    Torn,
    End,
    /// [`MAX_LINE_LEN`] bytes without a line feed.
    TooLong,
}

/// Read one progress file line into `line`, holding at most
/// [`MAX_LINE_LEN`] bytes.
async fn read_journal_line<R>(reader: &mut R, line: &mut Vec<u8>) -> io::Result<JournalLine>
where
    R: AsyncBufRead + Unpin,
{
    line.clear();
    (&mut *reader)
        .take(MAX_LINE_LEN as u64)
        .read_until(b'\n', line)
        .await?;

    if line.last() == Some(&b'\n') {
        return Ok(JournalLine::Complete);
    }

    if line.len() == MAX_LINE_LEN {
        return Ok(JournalLine::TooLong);
    }

    if line.is_empty() {
        return Ok(JournalLine::End);
    }

    Ok(JournalLine::Torn)
}

/// Fail when the progress file and the image are one file, through a link
/// or another name, before either is changed.
async fn ensure_distinct(
    journal: &File,
    journal_path: &Path,
    image: &File,
    output: &Path,
) -> Result<(), Report<Error>> {
    let journal_handle = file_handle(journal, journal_path).await?;
    let image_handle = file_handle(image, output).await?;
    if journal_handle == image_handle {
        return Err(Report::new(Error::from(DiskError::JournalAliasesImage {
            journal: journal_path.to_owned(),
            image: output.to_owned(),
        })));
    }

    Ok(())
}

async fn file_handle(file: &File, path: &Path) -> Result<Handle, Report<Error>> {
    let file = file
        .try_clone()
        .await
        .map_err(file_error("duplicating the handle of", path))?
        .into_std()
        .await;

    Handle::from_file(file).map_err(file_error("identifying", path))
}

/// Make the new entries of the directory that holds `output` durable.
#[cfg(unix)]
async fn sync_directory(output: &Path) -> Result<(), Report<Error>> {
    // A bare file name is in the current directory.
    let directory = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    File::open(directory)
        .await
        .map_err(file_error("opening", directory))?
        .sync_all()
        .await
        .map_err(file_error("syncing", directory))
}

/// Directory entries cannot be synchronized through a file handle on this
/// platform.
#[cfg(not(unix))]
async fn sync_directory(_output: &Path) -> Result<(), Report<Error>> {
    Ok(())
}

fn file_error(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> Report<Error> {
    let context = format!("{action} {}", path.display());

    move |error| Report::new(Error::from(error)).attach(context)
}

/// Bytes per second.
fn rate(bytes: u64, started: Instant) -> u64 {
    let seconds = started.elapsed().as_secs_f64();
    if seconds == 0.0 {
        return 0;
    }

    (bytes as f64 / seconds) as u64
}

#[cfg(test)]
mod tests {
    use openxbdm_client::transport::MockTransport;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn scratch_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xeedee-disk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();

        directory
    }

    fn header(sectors: u64) -> PullHeader {
        PullHeader::new(
            DeviceName::new(r"\Device\BuiltInMuSfcSystem").unwrap(),
            DeviceSize::from_sectors(sectors).unwrap(),
        )
    }

    fn disk_error(report: &Report<Error>) -> &DiskError {
        let Error::Disk(error) = report.current_context() else {
            panic!("not a disk error: {report:?}");
        };

        error
    }

    #[test]
    fn journal_lines_are_bounded() {
        let mut input = b"complete\ntorn".to_vec();
        let mut long = vec![b'0'; 0x10_0000];
        long.push(b'\n');
        let runtime = runtime();

        let mut kinds = Vec::new();
        let mut line = Vec::new();
        let mut reader = input.as_slice();
        for _ in 0..3 {
            kinds.push(
                runtime
                    .block_on(read_journal_line(&mut reader, &mut line))
                    .unwrap(),
            );
        }
        input = long;
        let mut reader = input.as_slice();
        let too_long = runtime
            .block_on(read_journal_line(&mut reader, &mut line))
            .unwrap();

        assert_eq!(
            kinds,
            [JournalLine::Complete, JournalLine::Torn, JournalLine::End]
        );
        assert_eq!(too_long, JournalLine::TooLong);
        assert_eq!(line.len(), MAX_LINE_LEN);
    }

    #[test]
    fn resume_rejects_an_oversized_record_line() {
        let directory = scratch_directory("oversized");
        let output = directory.join("image.bin");
        let journal_path = directory.join("image.bin.progress");
        std::fs::File::create(&output)
            .unwrap()
            .set_len(header(8).size().bytes())
            .unwrap();
        let mut journal = header(8).line().into_bytes();
        journal.extend(std::iter::repeat_n(b'0', 0x10_0000));
        std::fs::write(&journal_path, &journal).unwrap();

        let report = runtime()
            .block_on(open_resumed(header(8), &output, &journal_path))
            .unwrap_err();

        assert!(
            matches!(
                disk_error(&report),
                DiskError::Journal(JournalError::Record { line: 2 })
            ),
            "{report:?}"
        );
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn resume_rejects_a_progress_file_that_is_the_image() {
        let directory = scratch_directory("alias");
        let output = directory.join("image.bin");
        let journal_path = directory.join("image.bin.progress");
        let contents = header(8).line().into_bytes();
        std::fs::write(&output, &contents).unwrap();
        std::fs::hard_link(&output, &journal_path).unwrap();

        let report = runtime()
            .block_on(open_resumed(header(8), &output, &journal_path))
            .unwrap_err();

        assert!(
            matches!(
                disk_error(&report),
                DiskError::JournalAliasesImage { journal, image }
                    if *journal == journal_path && *image == output
            ),
            "{report:?}"
        );
        assert_eq!(std::fs::read(&output).unwrap(), contents);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn out_of_range_read_creates_no_file() {
        let directory = scratch_directory("read");
        let output = directory.join("bytes.bin");
        let runtime = runtime();
        let client = runtime
            .block_on(
                Client::new(MockTransport::from_server_script(["201- connected\r\n"]))
                    .read_banner(),
            )
            .unwrap();
        let disk = RemoteDisk::new(
            client,
            DeviceName::new(r"\Device\BuiltInMuSfcSystem").unwrap(),
            DeviceSize::from_sectors(0x3ff8).unwrap(),
        );

        for (offset, length) in [("0x7ff000", "1"), ("0xffffffffffffffff", "2")] {
            let report = runtime
                .block_on(read(&disk, offset, length, Some(&output)))
                .unwrap_err();

            assert!(
                matches!(disk_error(&report), DiskError::RangeOutOfBounds { .. }),
                "{offset} {length}: {report:?}"
            );
            assert!(!output.exists(), "{offset} {length}");
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
