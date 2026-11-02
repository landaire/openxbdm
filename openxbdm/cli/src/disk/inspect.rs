//! `fatxtool` partition layouts and read-only FATX volume commands on a
//! console device.
//!
//! The `fatxtool` commands read through the synchronous [`ReadAt`], so they
//! run on a blocking thread. Each of their reads is sent to the task that
//! owns the connection, which reads it from the [`RemoteDisk`] and sends the
//! bytes back; one read is outstanding at a time.

use std::convert::Infallible;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::ops::Range;
use std::path::Path;

use clap::Args;
use fatx::IntegrityPolicy;
use fatx::MAXIMUM_READ_SIZE;
use fatx::PartitionKind;
use fatx::ReadAt;
use fatx::VolumeOptions;
use fatxtool::DiskToolError;
use fatxtool::FatxCommand;
use fatxtool::FatxToolError;
use fatxtool::InputFile;
use fatxtool::OutputError;
use fatxtool::Session;
use fatxtool::VolumeLocation;
use fatxtool::VolumeSource;
use fatxtool::parse_number;
use fatxtool::partitions;
use fatxtool::select_partition;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::commands::DeviceName;
use openxbdm_client::disk::RemoteDisk;
use rootcause::Report;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinError;
use xenon_disk::DetectOptions;
use xenon_disk::MemoryDumpSize;

/// Prefix of the notes and warnings that `fatxtool` prints.
const PROGRAM: &str = "xeedee";

/// How to identify the layout of a device and treat failed integrity
/// checks.
#[derive(Args, Debug, Clone, Copy)]
pub struct LayoutArguments {
    /// The devkit has the large memory, which makes its MemDump partition
    /// 0x40e30000 bytes.
    #[arg(long)]
    large_memory: bool,

    /// Treat failed integrity checks, such as unreadable directories, as
    /// errors instead of warnings.
    #[arg(long)]
    strict: bool,
}

impl LayoutArguments {
    fn detect_options(self) -> DetectOptions {
        let memory_dump = if self.large_memory {
            MemoryDumpSize::Large
        } else {
            MemoryDumpSize::Standard
        };

        DetectOptions { memory_dump }
    }

    fn policy(self) -> IntegrityPolicy {
        if self.strict {
            IntegrityPolicy::Deny
        } else {
            IntegrityPolicy::Ignore
        }
    }
}

/// The volume of a device to run a FATX command on.
#[derive(Args, Debug, Clone)]
pub struct VolumeArguments {
    /// Offset of the volume in the device, decimal or `0x` hex.
    #[arg(long, value_parser = parse_number, default_value = "0")]
    offset: u64,

    /// Length of the volume; the rest of the device by default.
    #[arg(long, value_parser = parse_number)]
    length: Option<u64>,

    /// The volume of the named partition of the device, such as
    /// Partition1; `disk partitions` lists the names.
    #[arg(long, value_name = "NAME", conflicts_with_all = ["offset", "length"])]
    partition: Option<String>,

    /// Mount the volume as a partition in a growable file, which always has
    /// a 32-bit FAT and 16 KiB clusters. A partition selected by name gets
    /// this from its layout.
    #[arg(long)]
    alternate_partition: bool,

    #[command(flatten)]
    layout: LayoutArguments,
}

/// A `fatxtool` command on a device.
#[derive(Debug)]
pub enum Inspection {
    Partitions(LayoutArguments),
    Volume {
        volume: VolumeArguments,
        command: FatxCommand,
    },
}

/// A failed `disk partitions` or `disk fatx` command.
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error(transparent)]
    Volume(#[from] FatxToolError),

    #[error(transparent)]
    Layout(#[from] DiskToolError),

    #[error(transparent)]
    Output(#[from] OutputError),

    #[error(
        "the volume at offset {offset:#x} with length {length:#x?} is not inside the {device_length:#x}-byte device"
    )]
    RangeOutsideDevice {
        offset: u64,
        length: Option<u64>,
        device_length: u64,
    },

    /// The client's report of the failed read is the child of this one.
    #[error("reading bytes {range:#x?} of {device} failed")]
    RemoteRead {
        device: DeviceName,
        range: Range<u64>,
    },

    /// fatx asks for at most [`MAXIMUM_READ_SIZE`] bytes at once, so a
    /// larger read is a defect. It is rejected before a buffer for it is
    /// allocated.
    #[error("a read of bytes {range:#x?} exceeds the {maximum:#x}-byte limit of one FATX read")]
    ReadTooLarge { range: Range<u64>, maximum: u64 },

    #[error("the command thread did not finish")]
    Thread(#[from] JoinError),
}

/// Why the command thread got no bytes for a read. If the command fails,
/// the report of the read is the child of its report.
#[derive(Debug, thiserror::Error)]
enum ReadFailure {
    #[error("the console read failed")]
    Remote,
    #[error("the read exceeds the limit of one FATX read")]
    TooLarge,
    #[error("the connection task stopped answering device reads")]
    Stopped,
}

struct ReadRequest {
    range: Range<u64>,
    reply: oneshot::Sender<io::Result<Vec<u8>>>,
}

/// The device as a synchronous source, for the command thread.
struct BlockingDisk {
    requests: mpsc::Sender<ReadRequest>,
}

impl ReadAt for BlockingDisk {
    fn read_at(&self, _context: &(), range: Range<u64>) -> io::Result<impl AsRef<[u8]>> {
        let (reply, response) = oneshot::channel();
        self.requests
            .blocking_send(ReadRequest { range, reply })
            .map_err(|_| io::Error::other(ReadFailure::Stopped))?;

        response
            .blocking_recv()
            .map_err(|_| io::Error::other(ReadFailure::Stopped))?
    }
}

impl VolumeSource for BlockingDisk {
    type Warning = Infallible;

    fn take_warnings(&self) -> Vec<Infallible> {
        // `gethddblk` returns the sectors without integrity checks of its own.
        Vec::new()
    }
}

/// Run `inspection` on `disk`, printing its output to standard output.
pub async fn run<T>(
    disk: &RemoteDisk<T>,
    inspection: Inspection,
) -> Result<(), Report<InspectError>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (requests, mut pending) = mpsc::channel(1);
    let source = BlockingDisk { requests };
    let device = disk.device().as_str().to_owned();
    let device_length = disk.size().bytes();
    // `source` is dropped when the command returns, which ends the loop
    // below.
    let command =
        tokio::task::spawn_blocking(move || inspection.run(&source, &device, device_length));

    let mut failed_read = None;
    while let Some(request) = pending.recv().await {
        let reply = match read(disk, request.range).await {
            Ok(bytes) => Ok(bytes),
            Err(FailedRead { failure, report }) => {
                failed_read.get_or_insert(report);
                Err(io::Error::other(failure))
            }
        };
        // The command thread drops the receiver only when it panics, which
        // `command` returns.
        let _ = request.reply.send(reply);
    }

    let result = command
        .await
        .map_err(InspectError::from)
        .and_then(|result| result);
    let mut report = match result {
        Ok(()) => return Ok(()),
        Err(error) => Report::new(error),
    };
    // A command that succeeds without the bytes of a failed read did not
    // need them, such as a listing that skips an unreadable directory.
    if let Some(cause) = failed_read {
        report
            .children_mut()
            .push(cause.into_dynamic().into_cloneable());
    }

    Err(report)
}

struct FailedRead {
    /// What the command thread is told.
    failure: ReadFailure,
    report: Report<InspectError>,
}

/// Read `range` for the command thread.
async fn read<T>(disk: &RemoteDisk<T>, range: Range<u64>) -> Result<Vec<u8>, FailedRead>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if range.end.saturating_sub(range.start) > MAXIMUM_READ_SIZE {
        return Err(FailedRead {
            failure: ReadFailure::TooLarge,
            report: Report::new(InspectError::ReadTooLarge {
                range,
                maximum: MAXIMUM_READ_SIZE,
            }),
        });
    }

    disk.read(range.clone()).await.map_err(|report| FailedRead {
        failure: ReadFailure::Remote,
        report: report.context(InspectError::RemoteRead {
            device: disk.device().clone(),
            range,
        }),
    })
}

impl Inspection {
    fn layout(&self) -> LayoutArguments {
        match self {
            Self::Partitions(layout) => *layout,
            Self::Volume { volume, .. } => volume.layout,
        }
    }

    fn run(
        self,
        source: &BlockingDisk,
        device: &str,
        device_length: u64,
    ) -> Result<(), InspectError> {
        let layout = self.layout();
        // The device is on the console, so no local file can be an alias of
        // it.
        let input = InputFile::with_files(Path::new(device), std::iter::empty::<(&File, &Path)>())?;
        let session = Session::new(PROGRAM, layout.policy(), &input);
        let mut out = BufWriter::new(io::stdout().lock());

        match self {
            Self::Partitions(layout) => {
                partitions::run(
                    source,
                    device_length,
                    layout.detect_options(),
                    &session,
                    &mut out,
                )?;
            }
            Self::Volume { volume, command } => {
                let location = locate(&volume, source, device_length, &session)?;
                fatxtool::run(&command, source, &location, &session, &mut out)?;
            }
        }

        out.flush().map_err(FatxToolError::WriteListing)?;

        Ok(())
    }
}

/// The volume that `--partition`, or `--offset` and `--length`, select.
fn locate(
    volume: &VolumeArguments,
    source: &BlockingDisk,
    device_length: u64,
    session: &Session<'_>,
) -> Result<VolumeLocation, InspectError> {
    let requested_kind = volume
        .alternate_partition
        .then_some(PartitionKind::Alternate);

    if let Some(name) = &volume.partition {
        let selected = select_partition(
            source,
            device_length,
            name,
            volume.layout.detect_options(),
            session,
        )?;
        let mut options = VolumeOptions::new().with_kind(requested_kind.unwrap_or(selected.kind));
        if let Some(partition_length) = selected.truncated_length {
            options = options.with_partition_length(partition_length);
            session.note(format_args!(
                "the device ends {:#x} bytes into the {partition_length:#x}-byte {} partition",
                selected.range.end - selected.range.start,
                selected.name
            ));
        }

        return Ok(VolumeLocation::new(selected.range, options));
    }

    let end = match volume.length {
        Some(length) => volume.offset.checked_add(length),
        None => Some(device_length),
    };
    let range = match end {
        Some(end) if volume.offset <= end && end <= device_length => volume.offset..end,
        _ => {
            return Err(InspectError::RangeOutsideDevice {
                offset: volume.offset,
                length: volume.length,
                device_length,
            });
        }
    };
    let kind = requested_kind.unwrap_or(PartitionKind::Standard);

    Ok(VolumeLocation::new(
        range,
        VolumeOptions::new().with_kind(kind),
    ))
}

#[cfg(test)]
mod tests {
    use openxbdm_client::Client;
    use openxbdm_client::commands::DeviceName;
    use openxbdm_client::disk::DeviceSize;
    use openxbdm_client::error::Error;
    use openxbdm_client::transport::MockTransport;

    use super::*;

    const SECTORS: u64 = 0x3ff8;

    /// A disk whose connection ends after the banner, so every block read
    /// sent to it fails.
    fn disk(runtime: &tokio::runtime::Runtime) -> RemoteDisk<MockTransport> {
        let client = runtime
            .block_on(
                Client::new(MockTransport::from_server_script(["201- connected\r\n"]))
                    .read_banner(),
            )
            .unwrap();

        RemoteDisk::new(
            client,
            DeviceName::new(r"\Device\BuiltInMuSfcSystem").unwrap(),
            DeviceSize::from_sectors(SECTORS).unwrap(),
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn inspect(volume: VolumeArguments) -> Report<InspectError> {
        let runtime = runtime();
        let disk = disk(&runtime);
        let inspection = Inspection::Volume {
            volume,
            command: FatxCommand::Info,
        };

        runtime.block_on(run(&disk, inspection)).unwrap_err()
    }

    fn volume(offset: u64, length: Option<u64>) -> VolumeArguments {
        VolumeArguments {
            offset,
            length,
            partition: None,
            alternate_partition: false,
            layout: LayoutArguments {
                large_memory: false,
                strict: false,
            },
        }
    }

    #[test]
    fn a_range_outside_the_device_fails_before_any_read() {
        let size = SECTORS * 0x200;

        let report = inspect(volume(size, Some(1)));

        assert!(
            matches!(
                report.current_context(),
                InspectError::RangeOutsideDevice { offset, length: Some(1), device_length }
                    if *offset == size && *device_length == size
            ),
            "{report:?}"
        );
    }

    #[test]
    fn a_failed_device_read_is_reported_with_its_range() {
        // The first read, of the volume header, fails.
        let report = inspect(volume(0, None));

        assert!(
            matches!(report.current_context(), InspectError::Volume(_)),
            "{report:?}"
        );
        let cause = report.children().get(0).expect("the read failure");
        assert!(
            matches!(
                cause.downcast_current_context::<InspectError>(),
                Some(InspectError::RemoteRead { device, range })
                    if device.as_str() == r"\Device\BuiltInMuSfcSystem" && range.start == 0
            ),
            "{report:?}"
        );
        assert!(
            cause
                .children()
                .get(0)
                .and_then(|client| client.downcast_current_context::<Error>())
                .is_some(),
            "{report:?}"
        );
    }

    #[test]
    fn a_read_over_the_fatx_limit_is_rejected_without_a_request() {
        let runtime = runtime();
        let disk = disk(&runtime);
        let range = 0..MAXIMUM_READ_SIZE + 1;

        let Err(failed) = runtime.block_on(read(&disk, range.clone())) else {
            panic!("the read succeeded");
        };

        // A request would have failed as a remote read on the closed
        // connection.
        assert!(matches!(failed.failure, ReadFailure::TooLarge));
        assert!(
            matches!(
                failed.report.current_context(),
                InspectError::ReadTooLarge { range: rejected, maximum }
                    if *rejected == range && *maximum == MAXIMUM_READ_SIZE
            ),
            "{:?}",
            failed.report
        );
    }
}
