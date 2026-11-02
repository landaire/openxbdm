//! Resumable copy of a whole device to an image file.
//!
//! [`Pull`] names each byte range to read and hashes the bytes fed back.
//! The image is split into segments of [`SEGMENT_LEN`] bytes; when the
//! last byte of a segment arrives, [`Pull::feed`] returns a
//! [`SegmentRecord`]. The caller appends the record to a progress file
//! once the segment's bytes are durable in the image, and
//! [`Pull::resume`] with [`Pull::restore`] skips the recorded segments.
//!
//! Progress file lines:
//!
//! ```text
//! xeedee-disk-pull 1 size=0x<bytes> segment=0x<bytes> device=<name>
//! 0x<start> 0x<end> <sha256 of the segment>
//! ```

use core::fmt::Write as _;
use core::ops::Range;

use sha2::Digest;
use sha2::Sha256;

use crate::commands::DeviceName;
use crate::commands::SectorCount;
use crate::disk::DeviceSize;
use crate::disk::DiskError;
use crate::disk::JournalError;

/// Bytes covered by one progress record.
pub const SEGMENT_LEN: u64 = 0x40_0000;

const MAGIC: &str = "xeedee-disk-pull 1";

/// Longest progress file line, line feed included: a header with 64-bit
/// size and segment fields and the longest device name. Record lines are
/// shorter.
pub const MAX_LINE_LEN: usize = MAGIC.len()
    + " size=0x".len()
    + 16
    + " segment=0x".len()
    + 16
    + " device=".len()
    + DeviceName::MAX_LENGTH
    + 1;

/// The device and geometry a pull copies, written as the first line of
/// the progress file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullHeader {
    device: DeviceName,
    size: DeviceSize,
}

impl PullHeader {
    pub fn new(device: DeviceName, size: DeviceSize) -> Self {
        Self { device, size }
    }

    pub fn device(&self) -> &DeviceName {
        &self.device
    }

    pub fn size(&self) -> DeviceSize {
        self.size
    }

    /// The header line, with its line feed.
    pub fn line(&self) -> String {
        format!(
            "{MAGIC} size={:#x} segment={SEGMENT_LEN:#x} device={}\n",
            self.size.bytes(),
            self.device
        )
    }

    /// Check that `line` (without its line feed) is the header of a pull of
    /// this device and geometry.
    fn check(&self, line: &str) -> Result<(), JournalError> {
        let malformed = || JournalError::Header { line: 1 };

        let rest = line.strip_prefix(MAGIC).ok_or_else(malformed)?;
        let rest = rest.strip_prefix(" size=").ok_or_else(malformed)?;
        let (size, rest) = rest.split_once(" segment=").ok_or_else(malformed)?;
        let (segment, device) = rest.split_once(" device=").ok_or_else(malformed)?;
        let size = parse_hex(size).ok_or_else(malformed)?;
        let segment = parse_hex(segment).ok_or_else(malformed)?;
        let device = DeviceName::new(device).map_err(|_| malformed())?;

        // NT object names compare without regard to case.
        if !device.as_str().eq_ignore_ascii_case(self.device.as_str()) {
            return Err(JournalError::DeviceMismatch {
                journal: device,
                requested: self.device.clone(),
            });
        }

        if size != self.size.bytes() {
            return Err(JournalError::SizeMismatch {
                journal: size,
                device: self.size.bytes(),
            });
        }

        if segment != SEGMENT_LEN {
            return Err(JournalError::SegmentMismatch {
                journal: segment,
                expected: SEGMENT_LEN,
            });
        }

        Ok(())
    }
}

/// A segment whose bytes are in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    range: Range<u64>,
    sha256: [u8; 32],
}

impl SegmentRecord {
    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Check that `bytes`, read from the image at [`SegmentRecord::range`],
    /// are the bytes this record was written for.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), DiskError> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != self.sha256 {
            return Err(DiskError::DigestMismatch {
                start: self.range.start,
                end: self.range.end,
            });
        }

        Ok(())
    }

    /// The record line, with its line feed.
    pub fn line(&self) -> String {
        let mut line = format!("{:#x} {:#x} ", self.range.start, self.range.end);
        for byte in self.sha256 {
            let _ = write!(line, "{byte:02x}");
        }
        line.push('\n');

        line
    }

    fn parse(line_number: usize, line: &str) -> Result<Self, JournalError> {
        let malformed = || JournalError::Record { line: line_number };

        let mut fields = line.split(' ');
        let start = fields.next().and_then(parse_hex).ok_or_else(malformed)?;
        let end = fields.next().and_then(parse_hex).ok_or_else(malformed)?;
        let digest = fields.next().ok_or_else(malformed)?;
        if fields.next().is_some() || digest.len() != 64 {
            return Err(malformed());
        }

        let mut sha256 = [0u8; 32];
        for (byte, pair) in sha256.iter_mut().zip(digest.as_bytes().chunks(2)) {
            let pair = core::str::from_utf8(pair).map_err(|_| malformed())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
        }

        Ok(Self {
            range: start..end,
            sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullStep {
    /// Read these bytes of the device and pass them to [`Pull::feed`].
    Read(Range<u64>),
    /// Every segment is in the image.
    Done,
}

#[derive(Debug)]
pub struct Pull {
    header: PullHeader,
    /// One bit per segment, set once the segment is recorded.
    completed: Vec<u64>,
    completed_bytes: u64,
    /// No segment below this index is still to be read.
    next_segment: u64,
    current: Option<Segment>,
}

#[derive(Debug)]
struct Segment {
    range: Range<u64>,
    /// Start of the next read.
    next: u64,
    outstanding: Option<Range<u64>>,
    hasher: Sha256,
}

impl Pull {
    pub fn new(header: PullHeader) -> Self {
        let words = segment_count(header.size).div_ceil(64);

        Self {
            header,
            completed: vec![0; words as usize],
            completed_bytes: 0,
            next_segment: 0,
            current: None,
        }
    }

    /// Resume from a progress file whose first line, without its line
    /// feed, is `first_line`. Pass each remaining line to
    /// [`Pull::record`], check the image against it with
    /// [`SegmentRecord::verify`], and then [`Pull::restore`] it.
    pub fn resume(header: PullHeader, first_line: &str) -> Result<Self, JournalError> {
        header.check(first_line)?;

        Ok(Self::new(header))
    }

    /// Parse one record line (one-based `line_number`, without its line
    /// feed) and check that it names a segment of this image.
    pub fn record(&self, line_number: usize, line: &str) -> Result<SegmentRecord, JournalError> {
        let record = SegmentRecord::parse(line_number, line)?;
        let index = record.range.start / SEGMENT_LEN;
        if index >= segment_count(self.header.size) || record.range != self.segment_range(index) {
            return Err(JournalError::NotASegment {
                line: line_number,
                start: record.range.start,
                end: record.range.end,
            });
        }

        Ok(record)
    }

    /// Mark the segment of `record`, from [`Pull::record`], as complete.
    pub fn restore(&mut self, record: &SegmentRecord) {
        self.mark(record.range.start / SEGMENT_LEN);
    }

    pub fn header(&self) -> &PullHeader {
        &self.header
    }

    /// Bytes of the recorded segments.
    pub fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    pub fn step(&mut self) -> PullStep {
        const READ_LEN: u64 = SectorCount::MAX.byte_len() as u64;

        if self.current.is_none() {
            let count = segment_count(self.header.size);
            while self.next_segment < count && self.is_complete(self.next_segment) {
                self.next_segment += 1;
            }

            if self.next_segment == count {
                return PullStep::Done;
            }

            let range = self.segment_range(self.next_segment);
            self.current = Some(Segment {
                next: range.start,
                range,
                outstanding: None,
                hasher: Sha256::new(),
            });
        }

        let segment = self.current.as_mut().expect("a segment is open");
        let read = segment
            .outstanding
            .get_or_insert_with(|| segment.next..segment.range.end.min(segment.next + READ_LEN));

        PullStep::Read(read.clone())
    }

    /// Accept the bytes of the read [`Pull::step`] named. Returns the
    /// record of the segment those bytes complete.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<SegmentRecord>, DiskError> {
        let Some(segment) = self.current.as_mut() else {
            return Err(DiskError::NoReadOutstanding);
        };

        let Some(read) = segment.outstanding.clone() else {
            return Err(DiskError::NoReadOutstanding);
        };

        if data.len() as u64 != read.end - read.start {
            return Err(DiskError::FeedLengthMismatch {
                expected: read.end - read.start,
                actual: data.len() as u64,
            });
        }

        segment.hasher.update(data);
        segment.next = read.end;
        segment.outstanding = None;
        if segment.next < segment.range.end {
            return Ok(None);
        }

        let segment = self.current.take().expect("a segment is open");
        let record = SegmentRecord {
            range: segment.range,
            sha256: segment.hasher.finalize().into(),
        };
        self.mark(record.range.start / SEGMENT_LEN);

        Ok(Some(record))
    }

    fn segment_range(&self, index: u64) -> Range<u64> {
        let start = index * SEGMENT_LEN;

        start..self.header.size.bytes().min(start + SEGMENT_LEN)
    }

    fn is_complete(&self, index: u64) -> bool {
        self.completed[(index / 64) as usize] & (1 << (index % 64)) != 0
    }

    fn mark(&mut self, index: u64) {
        if self.is_complete(index) {
            return;
        }

        self.completed[(index / 64) as usize] |= 1 << (index % 64);
        let range = self.segment_range(index);
        self.completed_bytes += range.end - range.start;
    }
}

fn segment_count(size: DeviceSize) -> u64 {
    size.bytes().div_ceil(SEGMENT_LEN)
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(sectors: u64) -> PullHeader {
        PullHeader::new(
            DeviceName::new(r"\Device\BuiltInMuSfc").unwrap(),
            DeviceSize::from_sectors(sectors).unwrap(),
        )
    }

    fn pattern(offset: u64) -> u8 {
        (offset.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
    }

    /// Run `pull` to completion, returning the progress lines it produced
    /// and the ranges it read.
    fn drive(pull: &mut Pull, stop_after_records: Option<usize>) -> (Vec<String>, Vec<Range<u64>>) {
        let mut lines = Vec::new();
        let mut reads = Vec::new();
        while let PullStep::Read(range) = pull.step() {
            let data: Vec<u8> = range.clone().map(pattern).collect();
            reads.push(range);
            if let Some(record) = pull.feed(&data).unwrap() {
                lines.push(record.line());
                if Some(lines.len()) == stop_after_records {
                    break;
                }
            }
        }

        (lines, reads)
    }

    #[test]
    fn reads_every_byte_once_in_aligned_requests() {
        // The last segment and the last read are partial.
        let size = header(0x2508).size().bytes();
        let mut pull = Pull::new(header(0x2508));

        let (lines, reads) = drive(&mut pull, None);

        let mut next = 0;
        for read in &reads {
            assert_eq!(read.start, next);
            assert_eq!(read.start % 0x20000, 0);
            assert!(read.end - read.start <= 0x20000);
            next = read.end;
        }
        assert_eq!(next, size);
        assert_eq!(lines.len() as u64, size.div_ceil(SEGMENT_LEN));
        assert_eq!(pull.completed_bytes(), size);
        assert_eq!(pull.step(), PullStep::Done);
    }

    #[test]
    fn records_hash_their_segment() {
        let mut pull = Pull::new(header(0x2100));

        let (lines, _) = drive(&mut pull, None);

        let segment: Vec<u8> = (SEGMENT_LEN..0x2100 * 0x200).map(pattern).collect();
        let digest: [u8; 32] = Sha256::digest(&segment).into();
        let expected = SegmentRecord {
            range: SEGMENT_LEN..0x2100 * 0x200,
            sha256: digest,
        };
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], expected.line());
        assert_eq!(
            SegmentRecord::parse(2, lines[1].trim_end()).unwrap(),
            expected
        );
    }

    #[test]
    fn resume_skips_recorded_segments() {
        let mut first = Pull::new(header(0x5000));
        let header_line = first.header().line();
        let (recorded, _) = drive(&mut first, Some(2));
        // An interrupted segment's partial reads are not recorded.
        first.step();

        let mut resumed = Pull::resume(header(0x5000), header_line.trim_end()).unwrap();
        for (index, line) in recorded.iter().enumerate() {
            let record = resumed.record(index + 2, line.trim_end()).unwrap();
            let image: Vec<u8> = record.range().map(pattern).collect();
            record.verify(&image).unwrap();
            resumed.restore(&record);
        }
        let (rest, reads) = drive(&mut resumed, None);

        assert_eq!(reads.first().map(|read| read.start), Some(2 * SEGMENT_LEN));
        assert_eq!(recorded.len() + rest.len(), 3);
        assert_eq!(resumed.completed_bytes(), 0x5000 * 0x200);
    }

    #[test]
    fn resume_rejects_another_pull() {
        let other_device = PullHeader::new(
            DeviceName::new(r"\Device\BuiltInMuSfcSystem").unwrap(),
            DeviceSize::from_sectors(0x5000).unwrap(),
        );
        let other_size = header(0x4000);

        let device = Pull::resume(header(0x5000), other_device.line().trim_end());
        let size = Pull::resume(header(0x5000), other_size.line().trim_end());
        let garbage = Pull::resume(header(0x5000), "xeedee-disk-pull 1 size=0x200");
        let same_device = Pull::resume(
            header(0x5000),
            &header(0x5000).line().trim_end().to_ascii_lowercase(),
        );

        assert!(matches!(device, Err(JournalError::DeviceMismatch { .. })));
        assert!(matches!(size, Err(JournalError::SizeMismatch { .. })));
        assert!(matches!(garbage, Err(JournalError::Header { line: 1 })));
        assert!(same_device.is_ok(), "device names compare without case");
    }

    #[test]
    fn record_rejects_ranges_that_are_not_segments() {
        let pull = Pull::new(header(0x5000));
        let zeros = "0".repeat(64);

        let misaligned = pull.record(2, &format!("0x200 0x400200 {zeros}"));
        let short = pull.record(3, &format!("0x0 0x200 {zeros}"));
        let beyond = pull.record(4, &format!("0xc00000 0x1000000 {zeros}"));
        let malformed = pull.record(5, "0x0 0x400000");

        assert!(matches!(
            misaligned,
            Err(JournalError::NotASegment { line: 2, .. })
        ));
        assert!(matches!(
            short,
            Err(JournalError::NotASegment { line: 3, .. })
        ));
        assert!(matches!(
            beyond,
            Err(JournalError::NotASegment { line: 4, .. })
        ));
        assert!(matches!(malformed, Err(JournalError::Record { line: 5 })));
    }

    #[test]
    fn verify_rejects_changed_image_bytes() {
        let mut pull = Pull::new(header(0x2000));
        let (lines, _) = drive(&mut pull, Some(1));
        let record = pull.record(2, lines[0].trim_end()).unwrap();
        let mut image: Vec<u8> = record.range().map(pattern).collect();
        image[0x1234] ^= 1;

        let changed = record.verify(&image);

        assert!(matches!(
            changed,
            Err(DiskError::DigestMismatch {
                start: 0,
                end: SEGMENT_LEN
            })
        ));
    }

    #[test]
    fn feed_checks_the_outstanding_read() {
        let mut pull = Pull::new(header(0x5000));

        let unprompted = pull.feed(&[0; 16]);
        let PullStep::Read(range) = pull.step() else {
            panic!("a fresh pull reads");
        };
        let short = pull.feed(&vec![0; (range.end - range.start - 1) as usize]);

        assert!(matches!(unprompted, Err(DiskError::NoReadOutstanding)));
        assert!(matches!(short, Err(DiskError::FeedLengthMismatch { .. })));
    }

    #[test]
    fn longest_lines_fit_the_line_limit() {
        let longest = PullHeader::new(
            DeviceName::new("x".repeat(DeviceName::MAX_LENGTH)).unwrap(),
            DeviceSize::from_sectors(DeviceSize::MAX_SECTORS).unwrap(),
        );
        let record = SegmentRecord {
            range: u64::MAX - 1..u64::MAX,
            sha256: [0xff; 32],
        };

        assert!(longest.line().len() <= MAX_LINE_LEN);
        assert!(record.line().len() <= MAX_LINE_LEN);
    }
}
