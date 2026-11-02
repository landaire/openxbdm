//! A console block device read over `gethddblk`.

use core::fmt;
use core::ops::Range;
use std::io;

use fskit::AsyncReadAt;
use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;
use futures_util::lock::Mutex;
use rootcause::Report;
use rootcause::compat::ReportAsError;

use crate::client::Client;
use crate::client::Connected;
use crate::commands::DeviceName;
use crate::commands::GetHddBlock;
use crate::commands::SECTOR_SIZE;
use crate::commands::SectorCount;
use crate::commands::SectorIndex;
use crate::disk::DiskError;
use crate::error::Error;

/// Number of readable sectors of a device, 1 through 2^32 (the sector
/// field of `gethddblk` is 32 bits wide).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceSize {
    sectors: u64,
}

impl DeviceSize {
    pub const MAX_SECTORS: u64 = 1 << 32;

    pub const fn from_sectors(sectors: u64) -> Option<Self> {
        if sectors == 0 || sectors > Self::MAX_SECTORS {
            return None;
        }

        Some(Self { sectors })
    }

    pub const fn sectors(self) -> u64 {
        self.sectors
    }

    pub const fn bytes(self) -> u64 {
        self.sectors * SECTOR_SIZE
    }
}

impl fmt::Display for DeviceSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x} bytes", self.bytes())
    }
}

/// Sectors read by one `gethddblk` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRun {
    pub first: SectorIndex,
    pub count: SectorCount,
}

impl SectorRun {
    pub const fn byte_range(self) -> Range<u64> {
        let start = self.first.byte_offset();

        start..start + self.count.byte_len() as u64
    }
}

/// The runs that cover `range`, split at every multiple of
/// [`SectorCount::MAX`] sectors so that each run is one request and reads
/// of nearby ranges repeat the same runs. `range` must lie within the
/// first 2^32 sectors.
pub fn sector_runs(range: Range<u64>) -> impl Iterator<Item = SectorRun> {
    let run_sectors = u64::from(SectorCount::MAX.get());
    let end = range.end.div_ceil(SECTOR_SIZE);
    let mut next = range.start / SECTOR_SIZE;
    if range.start >= range.end {
        next = end;
    }

    core::iter::from_fn(move || {
        if next >= end {
            return None;
        }

        let boundary = (next / run_sectors + 1) * run_sectors;
        let run_end = boundary.min(end);
        let first = u32::try_from(next).expect("range lies within the first 2^32 sectors");
        let count = SectorCount::new((run_end - next) as u32).expect("run is 1..=0x100 sectors");
        next = run_end;

        Some(SectorRun {
            first: SectorIndex(first),
            count,
        })
    })
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn read_sectors(
        &mut self,
        device: &DeviceName,
        first: SectorIndex,
        count: SectorCount,
    ) -> Result<Vec<u8>, Report<Error>> {
        self.run(GetHddBlock {
            device,
            first,
            count,
        })
        .await
    }

    /// Size of `device`, or `None` when its first sector cannot be read.
    ///
    /// The monitor reports no device size, so this bisects for the last
    /// sector that reads without a `400` reply: 33 one-sector reads. A
    /// device larger than 2^32 sectors reports 2^32. A sector that fails
    /// to read for another reason, such as a media error, also answers
    /// `400` and ends the readable range early.
    pub async fn discover_device_size(
        &mut self,
        device: &DeviceName,
    ) -> Result<Option<DeviceSize>, Report<Error>> {
        if !self.sector_readable(device, 0).await? {
            return Ok(None);
        }

        let mut readable = 0u64;
        let mut rejected = DeviceSize::MAX_SECTORS;
        while rejected - readable > 1 {
            let middle = readable + (rejected - readable) / 2;
            if self.sector_readable(device, middle).await? {
                readable = middle;
            } else {
                rejected = middle;
            }
        }

        Ok(DeviceSize::from_sectors(readable + 1))
    }

    async fn sector_readable(
        &mut self,
        device: &DeviceName,
        sector: u64,
    ) -> Result<bool, Report<Error>> {
        let first = SectorIndex(u32::try_from(sector).expect("probe below 2^32"));
        match self.read_sectors(device, first, SectorCount::ONE).await {
            Ok(_) => Ok(true),
            Err(report) if matches!(report.current_context(), Error::BlockReadRejected { .. }) => {
                Ok(false)
            }
            Err(report) => Err(report),
        }
    }
}

/// A device on the console read as a byte-addressed source. Reads take
/// the connection for their duration, so concurrent reads run one after
/// another.
#[derive(Debug)]
pub struct RemoteDisk<T> {
    client: Mutex<Client<T, Connected>>,
    device: DeviceName,
    size: DeviceSize,
}

impl<T> RemoteDisk<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Longest range [`RemoteDisk::read`] accepts, since the reply is held
    /// in memory. Copy larger ranges in pieces.
    pub const MAX_READ_LEN: u64 = 0x400_0000;

    pub fn new(client: Client<T, Connected>, device: DeviceName, size: DeviceSize) -> Self {
        Self {
            client: Mutex::new(client),
            device,
            size,
        }
    }

    /// Open `device` with the size [`Client::discover_device_size`] finds.
    pub async fn open(
        mut client: Client<T, Connected>,
        device: DeviceName,
    ) -> Result<Self, Report<Error>> {
        let Some(size) = client.discover_device_size(&device).await? else {
            return Err(Report::new(Error::from(DiskError::Unreadable { device })));
        };

        Ok(Self::new(client, device, size))
    }

    pub fn device(&self) -> &DeviceName {
        &self.device
    }

    pub fn size(&self) -> DeviceSize {
        self.size
    }

    pub fn into_client(self) -> Client<T, Connected> {
        self.client.into_inner()
    }

    /// Read the bytes of `range`, which must lie within the device and be
    /// at most [`RemoteDisk::MAX_READ_LEN`] bytes long.
    pub async fn read(&self, range: Range<u64>) -> Result<Vec<u8>, Report<Error>> {
        let size = self.size.bytes();
        if range.start > range.end || range.end > size {
            return Err(Report::new(Error::from(DiskError::RangeOutOfBounds {
                start: range.start,
                end: range.end,
                size,
            })));
        }

        let length = range.end - range.start;
        if length > Self::MAX_READ_LEN {
            return Err(Report::new(Error::from(DiskError::ReadTooLong {
                length,
                maximum: Self::MAX_READ_LEN,
            })));
        }

        let mut client = self.client.lock().await;
        let mut runs = sector_runs(range.clone());
        let Some(first_run) = runs.next() else {
            return Ok(Vec::new());
        };

        let mut data = client
            .read_sectors(&self.device, first_run.first, first_run.count)
            .await?;
        let run = first_run.byte_range();
        let skip = (range.start - run.start) as usize;

        // A range within one run is the reply itself, trimmed in place.
        if range.end <= run.end {
            data.truncate((range.end - run.start) as usize);
            data.drain(..skip);
            return Ok(data);
        }

        let mut bytes = Vec::with_capacity((range.end - range.start) as usize);
        bytes.extend_from_slice(&data[skip..]);
        for run in runs {
            let data = client
                .read_sectors(&self.device, run.first, run.count)
                .await?;
            let take = (range.end.min(run.byte_range().end) - run.byte_range().start) as usize;
            bytes.extend_from_slice(&data[..take]);
        }

        Ok(bytes)
    }
}

impl<T> AsyncReadAt for RemoteDisk<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn read_at(&self, _context: &(), range: Range<u64>) -> io::Result<impl AsRef<[u8]>> {
        self.read(range)
            .await
            .map_err(|report| io::Error::other(ReportAsError::from(report)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::task::Context;
    use std::task::Poll;

    use futures::executor::block_on;

    use super::*;

    /// Answers `gethddblk` for one device of `sectors` sectors whose byte at
    /// offset `o` is [`pattern`]`(o)`, and records each request.
    struct SimulatedDevice {
        name: &'static str,
        sectors: u64,
        requests: Arc<StdMutex<Vec<SectorRun>>>,
        pending: Vec<u8>,
        reply: VecDeque<u8>,
    }

    impl SimulatedDevice {
        fn new(name: &'static str, sectors: u64) -> Self {
            Self {
                name,
                sectors,
                requests: Arc::default(),
                pending: Vec::new(),
                reply: b"201- connected\r\n".iter().copied().collect(),
            }
        }

        fn answer(&mut self, line: &str) {
            let mut fields = line.split(' ');
            assert_eq!(fields.next(), Some("gethddblk"));
            let name = fields.next().unwrap();
            let block = hex_field(fields.next().unwrap(), "block=");
            let count = hex_field(fields.next().unwrap(), "count=");
            assert_eq!(fields.next(), None);

            let run = SectorRun {
                first: SectorIndex(block as u32),
                count: SectorCount::new(count as u32).expect("client sends a valid count"),
            };
            self.requests.lock().unwrap().push(run);

            if name != format!("name=\"{}\"", self.name) || block + count > self.sectors {
                self.reply.extend(b"400- \r\n");
                return;
            }

            self.reply.extend(b"203- binary response follows\r\n");
            self.reply.extend(run.byte_range().map(pattern));
        }
    }

    impl futures_io::AsyncRead for SimulatedDevice {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let count = buf.len().min(self.reply.len());
            for (slot, byte) in buf.iter_mut().zip(self.reply.drain(..count)) {
                *slot = byte;
            }

            Poll::Ready(Ok(count))
        }
    }

    impl futures_io::AsyncWrite for SimulatedDevice {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.pending.extend_from_slice(buf);
            while let Some(end) = self.pending.windows(2).position(|pair| pair == b"\r\n") {
                let line: Vec<u8> = self.pending.drain(..end + 2).collect();
                self.answer(core::str::from_utf8(&line[..end]).unwrap());
            }

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn hex_field(field: &str, key: &str) -> u64 {
        let digits = field.strip_prefix(key).unwrap().strip_prefix("0x").unwrap();

        u64::from_str_radix(digits, 16).unwrap()
    }

    fn pattern(offset: u64) -> u8 {
        (offset.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
    }

    const DEVICE: &str = r"\Device\BuiltInMuSfc";

    fn connect(
        device: SimulatedDevice,
    ) -> (
        Client<SimulatedDevice, Connected>,
        Arc<StdMutex<Vec<SectorRun>>>,
    ) {
        let requests = Arc::clone(&device.requests);
        let client = block_on(Client::new(device).read_banner()).unwrap();

        (client, requests)
    }

    fn device_name() -> DeviceName {
        DeviceName::new(DEVICE).unwrap()
    }

    #[test]
    fn discovers_size_by_bisection() {
        for sectors in [
            1,
            2,
            0x100,
            0x101,
            0xd2508,
            0x1b31_e3f0,
            (1 << 32) - 1,
            1 << 32,
            1 << 33,
        ] {
            let (mut client, requests) = connect(SimulatedDevice::new(DEVICE, sectors));

            let size = block_on(client.discover_device_size(&device_name())).unwrap();

            let expected = sectors.min(DeviceSize::MAX_SECTORS);
            assert_eq!(
                size.map(DeviceSize::sectors),
                Some(expected),
                "{sectors:#x} sectors"
            );
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 33, "{sectors:#x} sectors");
            assert!(requests.iter().all(|run| run.count == SectorCount::ONE));
        }
    }

    #[test]
    fn unreadable_device_has_no_size_after_one_probe() {
        let (mut client, requests) = connect(SimulatedDevice::new(r"\Device\Mu0", 0x1000));

        let size = block_on(client.discover_device_size(&device_name())).unwrap();

        assert_eq!(size, None);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn reads_return_requested_bytes_from_aligned_runs() {
        const SECTORS: u64 = 0x0345;
        let run_bytes = SectorCount::MAX.byte_len() as u64;
        let size = SECTORS * SECTOR_SIZE;
        let ranges = [
            0..0,
            0..1,
            5..6,
            511..513,
            0..run_bytes,
            1..run_bytes + 1,
            run_bytes - 1..run_bytes + 1,
            3..3 * run_bytes + 7,
            0..size,
            size - 1..size,
            size..size,
        ];

        for range in ranges {
            let (client, requests) = connect(SimulatedDevice::new(DEVICE, SECTORS));
            let disk = RemoteDisk::new(
                client,
                device_name(),
                DeviceSize::from_sectors(SECTORS).unwrap(),
            );

            let bytes = block_on(disk.read(range.clone())).unwrap();

            let expected: Vec<u8> = range.clone().map(pattern).collect();
            assert!(bytes == expected, "bytes of {range:?}");

            let requests = requests.lock().unwrap();
            let first_sector = range.start / SECTOR_SIZE;
            let end_sector = range.end.div_ceil(SECTOR_SIZE).max(first_sector);
            let mut next = first_sector;
            for run in requests.iter() {
                let start = u64::from(run.first.0);
                let end = start + u64::from(run.count.get());
                assert_eq!(start, next, "runs of {range:?} are contiguous");
                assert_eq!(
                    start / 0x100,
                    (end - 1) / 0x100,
                    "run of {range:?} stays in one 128 KiB block"
                );
                next = end;
            }
            assert_eq!(next, end_sector, "runs of {range:?} cover it exactly");
        }
    }

    #[test]
    fn rejects_ranges_beyond_the_device_without_a_request() {
        let (client, requests) = connect(SimulatedDevice::new(DEVICE, 4));
        let disk = RemoteDisk::new(client, device_name(), DeviceSize::from_sectors(4).unwrap());

        for range in [0..2049, 2048..2049, 10..5] {
            let report = block_on(disk.read(range.clone())).unwrap_err();
            assert!(
                matches!(
                    report.current_context(),
                    Error::Disk(DiskError::RangeOutOfBounds { .. })
                ),
                "{range:?}: {report:?}"
            );
        }
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn rejects_reads_longer_than_the_limit_without_a_request() {
        const SECTORS: u64 = 0x4_0001;
        let (client, requests) = connect(SimulatedDevice::new(DEVICE, SECTORS));
        let disk = RemoteDisk::new(
            client,
            device_name(),
            DeviceSize::from_sectors(SECTORS).unwrap(),
        );
        let limit = RemoteDisk::<SimulatedDevice>::MAX_READ_LEN;

        let report = block_on(disk.read(0..limit + 1)).unwrap_err();

        assert!(
            matches!(
                report.current_context(),
                Error::Disk(DiskError::ReadTooLong { length, .. }) if *length == limit + 1
            ),
            "{report:?}"
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn async_read_at_serves_parsers() {
        let (client, _requests) = connect(SimulatedDevice::new(DEVICE, 0x400));
        let disk = RemoteDisk::new(
            client,
            device_name(),
            DeviceSize::from_sectors(0x400).unwrap(),
        );

        let bytes = block_on(AsyncReadAt::read_at(&disk, &(), 0x1fff0..0x20010)).unwrap();

        let expected: Vec<u8> = (0x1fff0..0x20010).map(pattern).collect();
        assert!(bytes.as_ref() == expected.as_slice());
    }
}
