//! Capture file format and frame accounting of the frame-log library
//! (0x91f67f78..0x91f6b4e8) as `netcap` uses it. Multi-byte fields are
//! little-endian.
//!
//! Layout: a 0xf4-byte header, then one record per frame (16-byte record
//! header, frame bytes, 2-byte frame type), then a frame table of record
//! offsets whose location the header holds at 0x18.

use core::num::NonZeroU32;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;

/// Bytes before the first record: the 0x80-byte file header and the
/// 0x74-byte media block.
pub const HEADER_SIZE: usize = 0xf4;
const MEDIA_BLOCK_OFFSET: usize = 0x80;
const MEDIA_BLOCK_SIZE: u32 = 0x74;
/// Header offset of the frame table location: table offset, table bytes.
pub const TABLE_LOCATION_OFFSET: u64 = 0x18;
pub const RECORD_HEADER_SIZE: usize = 0x10;
/// Frame type that ends every record (Ethernet).
pub const RECORD_TRAILER: [u8; 2] = 1u16.to_le_bytes();
/// Bytes a record adds to its frame, counted against the data limit.
const RECORD_OVERHEAD: u32 = 0x12;
/// Longest frame the context accepts: `netcap` creates it with frame length
/// 0, which selects this default.
pub const MAX_FRAME_LENGTH: u32 = 0x5ea;
/// Largest single file write of the buffered writer.
pub const WRITE_LIMIT: u32 = 0x1_0000;

/// Why a capture file operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFileError {
    /// A frame is longer than [`MAX_FRAME_LENGTH`], or a file transfer was
    /// short.
    BadLength,
    /// The data limit is used up.
    DataLimitReached,
    /// The write buffer was full where the caller could not wait for it.
    WriteFault,
    /// A record header in the file is inconsistent.
    InvalidData,
    /// No memory for the context or the write buffer.
    OutOfMemory,
    /// A file operation failed.
    Kernel(KernelError),
}

impl From<CaptureFileError> for Hresult {
    fn from(error: CaptureFileError) -> Self {
        match error {
            CaptureFileError::BadLength => Win32Error::BAD_LENGTH.into(),
            CaptureFileError::DataLimitReached => Win32Error::BUFFER_OVERFLOW.into(),
            CaptureFileError::WriteFault => Win32Error::WRITE_FAULT.into(),
            CaptureFileError::InvalidData => Win32Error::INVALID_DATA.into(),
            CaptureFileError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            CaptureFileError::Kernel(error) => error.into(),
        }
    }
}

impl From<KernelError> for CaptureFileError {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}

/// Local time of context creation, in `GetLocalTime` field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub millisecond: u16,
}

impl LocalTime {
    const fn fields(&self) -> [u16; 8] {
        [
            self.year,
            self.month,
            self.day_of_week,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.millisecond,
        ]
    }
}

/// Frame bytes the capture accepts (`maxframedata`); `None` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataLimit(pub Option<NonZeroU32>);

/// Record time: microseconds since the context was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Microseconds(pub u64);

/// Time base reading of the context creation and the tick rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    origin: u64,
    ticks_per_millisecond: NonZeroU32,
}

impl Clock {
    /// Stock stores `frequency * 0.001` truncated to 32 bits (0x91f698f0).
    pub fn new(origin: u64, frequency: u64) -> Self {
        let ticks = (frequency as f64 * 0.001) as i64 as u32;
        // Stock traps on a zero divisor; time base rates are in the MHz
        // range, so the minimum is never selected on hardware.
        Self {
            origin,
            ticks_per_millisecond: NonZeroU32::new(ticks).unwrap_or(NonZeroU32::MIN),
        }
    }

    /// Record time of the time base reading `now`, with the stock 64-bit
    /// wrapping arithmetic.
    pub fn timestamp(&self, now: u64) -> Microseconds {
        Microseconds(
            now.wrapping_sub(self.origin).wrapping_mul(1000)
                / u64::from(self.ticks_per_millisecond.get()),
        )
    }
}

/// The header and media block (0x91f6b4e8). The frame table location at
/// [`TABLE_LOCATION_OFFSET`] stays zero until the capture is finished.
pub fn file_header(start: &LocalTime) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[..4].copy_from_slice(b"GMBU");
    // Records carry the frame type trailer.
    header[4] = 1;
    header[5] = 2;
    header[6..8].copy_from_slice(&1u16.to_le_bytes());
    for (index, field) in start.fields().into_iter().enumerate() {
        header[8 + index * 2..10 + index * 2].copy_from_slice(&field.to_le_bytes());
    }
    put(&mut header, 0x38, MEDIA_BLOCK_OFFSET as u32);
    put(&mut header, 0x3c, MEDIA_BLOCK_SIZE);
    let media = MEDIA_BLOCK_OFFSET;
    put(&mut header, media + 0x1c, 100);
    // Media type of the file object (+0x60), set when the file opens.
    put(&mut header, media + 0x20, 1);
    put(&mut header, media + 0x24, MAX_FRAME_LENGTH);
    // File object +0x28, initialized to 1000.
    put(&mut header, media + 0x2c, 1000);
    put(&mut header, media + 0x50, 1);
    header
}

fn put(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Header of a record (0x91f6a730): time, then the frame length twice.
pub fn record_header(time: Microseconds, length: u32) -> [u8; RECORD_HEADER_SIZE] {
    let mut header = [0u8; RECORD_HEADER_SIZE];
    header[..8].copy_from_slice(&time.0.to_le_bytes());
    put(&mut header, 8, length);
    put(&mut header, 12, length);
    header
}

/// What to do with a frame that passed [`Recorder::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Write a record and report it with [`Recorder::recorded`].
    Record,
    /// The file is closing; the frame is dropped and counts as appended.
    Discard,
}

/// Frame accounting of a capture context (0x91f699f8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorder {
    limit: DataLimit,
    /// Frame bytes plus record overhead appended (+0x50).
    used: u32,
    /// Records appended (+0x48); replaced by the records found when the
    /// file is finished.
    frames: u32,
    /// The data limit was hit (flag 0x01000000).
    exhausted: bool,
    /// A record failed with [`CaptureFileError::WriteFault`] (flag
    /// 0x00800000).
    write_fault: bool,
    closing: bool,
}

impl Recorder {
    pub const fn new(limit: DataLimit) -> Self {
        Self {
            limit,
            used: 0,
            frames: 0,
            exhausted: false,
            write_fault: false,
            closing: false,
        }
    }

    pub const fn frames(&self) -> u32 {
        self.frames
    }

    /// Check a frame of `length` bytes before it is written.
    pub fn admit(&mut self, length: u32) -> Result<Admission, CaptureFileError> {
        if length > MAX_FRAME_LENGTH {
            return Err(CaptureFileError::BadLength);
        }
        if self.exhausted {
            return Err(CaptureFileError::DataLimitReached);
        }
        if self.closing {
            return Ok(Admission::Discard);
        }
        // Unsigned like stock: the overhead of the last record can push
        // `used` past the limit, after which the remainder wraps and any
        // frame fits.
        let remaining = self
            .limit
            .0
            .map_or(u32::MAX, NonZeroU32::get)
            .wrapping_sub(self.used);
        if length > remaining {
            self.exhausted = true;
            return Err(CaptureFileError::DataLimitReached);
        }
        Ok(Admission::Record)
    }

    /// A record of `length` frame bytes was written.
    pub fn recorded(&mut self, length: u32) {
        self.used = self.used.wrapping_add(length).wrapping_add(RECORD_OVERHEAD);
        self.frames = self.frames.wrapping_add(1);
    }

    /// Writing a record failed with `error`.
    pub fn failed(&mut self, error: CaptureFileError) {
        if error == CaptureFileError::WriteFault {
            self.write_fault = true;
        }
    }

    /// Stop accepting records; later frames are discarded.
    pub fn begin_close(&mut self) {
        self.closing = true;
    }

    /// Finish the file (0x91f69d18 after the data is written): with records,
    /// rebuild the frame table from the records between the header and
    /// `end`; then cut the file after the table and store the table
    /// location. A record lost to [`CaptureFileError::WriteFault`] makes a
    /// successful finish report that error.
    pub fn finish(&mut self, file: &mut impl CaptureIo, end: u64) -> Result<(), CaptureFileError> {
        let mut table = Table {
            offset: 0,
            bytes: 0,
        };
        if self.frames > 0 {
            self.frames = write_frame_table(file, end, &mut table)?;
        }
        file.truncate(end + u64::from(table.bytes))?;
        let mut location = [0u8; 8];
        put(&mut location, 0, table.offset);
        put(&mut location, 4, table.bytes);
        file.write_at(TABLE_LOCATION_OFFSET, &location)?;
        if self.write_fault {
            Err(CaptureFileError::WriteFault)
        } else {
            Ok(())
        }
    }
}

/// Positional access to an open capture file.
pub trait CaptureIo {
    /// Read exactly `buffer.len()` bytes; a short read is
    /// [`CaptureFileError::BadLength`].
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), CaptureFileError>;
    /// Write all of `data`; a short write is [`CaptureFileError::BadLength`].
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), CaptureFileError>;
    /// Set the end of file and the allocation size to `length`
    /// (0x91f6a310).
    fn truncate(&mut self, length: u64) -> Result<(), CaptureFileError>;
}

struct Table {
    offset: u32,
    bytes: u32,
}

/// Walk the records from the header to `end`, appending each record offset
/// to the table at `end` (0x91f6b080). Returns the record count.
fn write_frame_table(
    file: &mut impl CaptureIo,
    end: u64,
    table: &mut Table,
) -> Result<u32, CaptureFileError> {
    let mut position = HEADER_SIZE as u64;
    let mut count = 0u32;
    while position < end {
        let mut header = [0u8; RECORD_HEADER_SIZE];
        file.read_at(position, &mut header)?;
        let original = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let captured = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let available = end as i64 - (position + RECORD_HEADER_SIZE as u64) as i64;
        if i64::from(captured) > available || captured != original {
            return Err(CaptureFileError::InvalidData);
        }
        let entry_offset = end + u64::from(count) * 4;
        file.write_at(entry_offset, &(position as u32).to_le_bytes())?;
        if count == 0 {
            table.offset = end as u32;
        }
        table.bytes = table.bytes.wrapping_add(4);
        position += u64::from(captured.wrapping_add(RECORD_HEADER_SIZE as u32))
            + RECORD_TRAILER.len() as u64;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    struct MemoryFile(Vec<u8>);

    impl CaptureIo for MemoryFile {
        fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), CaptureFileError> {
            let start = offset as usize;
            let bytes = self
                .0
                .get(start..start + buffer.len())
                .ok_or(CaptureFileError::BadLength)?;
            buffer.copy_from_slice(bytes);
            Ok(())
        }

        fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), CaptureFileError> {
            let end = offset as usize + data.len();
            if self.0.len() < end {
                self.0.resize(end, 0);
            }
            self.0[offset as usize..end].copy_from_slice(data);
            Ok(())
        }

        fn truncate(&mut self, length: u64) -> Result<(), CaptureFileError> {
            self.0.resize(length as usize, 0);
            Ok(())
        }
    }

    const START: LocalTime = LocalTime {
        year: 2026,
        month: 10,
        day_of_week: 3,
        day: 14,
        hour: 9,
        minute: 30,
        second: 5,
        millisecond: 250,
    };

    fn hex(bytes: &[u8]) -> std::string::String {
        bytes
            .chunks(16)
            .map(|row| {
                row.iter()
                    .map(|byte| std::format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn header_layout() {
        let header = file_header(&START);
        let expected = "\
47 4d 42 55 01 02 01 00 ea 07 0a 00 03 00 0e 00
09 00 1e 00 05 00 fa 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 80 00 00 00 74 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00
01 00 00 00 ea 05 00 00 00 00 00 00 e8 03 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00";
        assert_eq!(hex(&header), expected);
    }

    #[test]
    fn record_header_layout() {
        assert_eq!(
            hex(&record_header(Microseconds(0x0000_0001_0203_0405), 0x3c)),
            "05 04 03 02 01 00 00 00 3c 00 00 00 3c 00 00 00"
        );
    }

    #[test]
    fn clock_counts_microseconds() {
        let clock = Clock::new(1_000, 50_000_000);
        assert_eq!(clock.timestamp(1_000), Microseconds(0));
        assert_eq!(clock.timestamp(1_000 + 50_000_000), Microseconds(1_000_000));
        assert_eq!(clock.timestamp(1_000 + 49), Microseconds(0));
        assert_eq!(clock.timestamp(1_000 + 50), Microseconds(1));
    }

    #[test]
    fn admission_limits() {
        let mut recorder = Recorder::new(DataLimit(None));
        assert_eq!(recorder.admit(MAX_FRAME_LENGTH), Ok(Admission::Record));
        assert_eq!(
            recorder.admit(MAX_FRAME_LENGTH + 1),
            Err(CaptureFileError::BadLength)
        );

        let mut recorder = Recorder::new(DataLimit(NonZeroU32::new(100)));
        assert_eq!(recorder.admit(101), Err(CaptureFileError::DataLimitReached));
        // Once exhausted, even small frames fail.
        assert_eq!(recorder.admit(1), Err(CaptureFileError::DataLimitReached));

        let mut recorder = Recorder::new(DataLimit(NonZeroU32::new(100)));
        assert_eq!(recorder.admit(90), Ok(Admission::Record));
        recorder.recorded(90);
        // 100 - 108 wraps: the limit no longer applies.
        assert_eq!(recorder.admit(MAX_FRAME_LENGTH), Ok(Admission::Record));

        let mut recorder = Recorder::new(DataLimit(NonZeroU32::new(100)));
        assert_eq!(recorder.admit(60), Ok(Admission::Record));
        recorder.recorded(60);
        assert_eq!(recorder.admit(23), Err(CaptureFileError::DataLimitReached));

        let mut recorder = Recorder::new(DataLimit(None));
        recorder.begin_close();
        assert_eq!(recorder.admit(10), Ok(Admission::Discard));
    }

    fn capture(frames: &[&[u8]]) -> (MemoryFile, Recorder) {
        let mut file = MemoryFile(file_header(&START).to_vec());
        let mut recorder = Recorder::new(DataLimit(None));
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(recorder.admit(frame.len() as u32), Ok(Admission::Record));
            file.0.extend_from_slice(&record_header(
                Microseconds(index as u64 * 10),
                frame.len() as u32,
            ));
            file.0.extend_from_slice(frame);
            file.0.extend_from_slice(&RECORD_TRAILER);
            recorder.recorded(frame.len() as u32);
        }
        (file, recorder)
    }

    #[test]
    fn finish_appends_the_frame_table() {
        let (mut file, mut recorder) = capture(&[&[0xaa; 3], &[0xbb; 2]]);
        let end = file.0.len() as u64;
        assert_eq!(recorder.finish(&mut file, end), Ok(()));
        assert_eq!(recorder.frames(), 2);
        assert_eq!(&file.0[0x18..0x20], &[0x1d, 0x01, 0, 0, 8, 0, 0, 0]);
        assert_eq!(
            hex(&file.0[HEADER_SIZE..]),
            "\
00 00 00 00 00 00 00 00 03 00 00 00 03 00 00 00
aa aa aa 01 00 0a 00 00 00 00 00 00 00 02 00 00
00 02 00 00 00 bb bb 01 00 f4 00 00 00 09 01 00
00"
        );
    }

    #[test]
    fn finish_without_frames_keeps_the_table_empty() {
        let (mut file, mut recorder) = capture(&[]);
        file.0.extend_from_slice(&[0xcc; 7]);
        assert_eq!(recorder.finish(&mut file, HEADER_SIZE as u64), Ok(()));
        assert_eq!(file.0.len(), HEADER_SIZE);
        assert_eq!(&file.0[0x18..0x20], &[0; 8]);
    }

    #[test]
    fn finish_rejects_inconsistent_records() {
        let (mut file, mut recorder) = capture(&[&[1, 2, 3]]);
        file.0[HEADER_SIZE + 8] = 4;
        let end = file.0.len() as u64;
        assert_eq!(
            recorder.finish(&mut file, end),
            Err(CaptureFileError::InvalidData)
        );
        assert_eq!(recorder.frames(), 1);

        let (mut file, mut recorder) = capture(&[&[1, 2, 3]]);
        let end = file.0.len() as u64 - 4;
        assert_eq!(
            recorder.finish(&mut file, end),
            Err(CaptureFileError::InvalidData)
        );
    }

    #[test]
    fn finish_reports_a_write_fault() {
        let (mut file, mut recorder) = capture(&[&[1]]);
        recorder.failed(CaptureFileError::WriteFault);
        let end = file.0.len() as u64;
        assert_eq!(
            recorder.finish(&mut file, end),
            Err(CaptureFileError::WriteFault)
        );
        assert_eq!(recorder.frames(), 1);
    }
}
