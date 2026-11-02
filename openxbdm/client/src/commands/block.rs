//! Raw sector reads of named block devices.

use core::fmt;

use crate::commands::error::report_argument;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ErrorCode;
use crate::protocol::ExpectedBody;
use crate::protocol::RemoteStatus;
use crate::protocol::Response;

/// Bytes per sector of `gethddblk`.
pub const SECTOR_SIZE: u64 = 0x200;

/// NT object name of a block device, such as `\Device\BuiltInMuSfc`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceName(String);

impl DeviceName {
    /// The monitor copies the name into a 0x100-byte buffer with its
    /// terminator.
    pub const MAX_LENGTH: usize = 0xff;

    pub fn new(name: impl Into<String>) -> Result<Self, ArgumentError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ArgumentError::EmptyDeviceName);
        }

        if name.len() > Self::MAX_LENGTH {
            return Err(ArgumentError::DeviceNameTooLong {
                length: name.len(),
                maximum: Self::MAX_LENGTH,
            });
        }

        if name.contains(['\r', '\n', '"']) {
            return Err(ArgumentError::DeviceNameInvalidCharacter);
        }

        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Index of a 512-byte sector within a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectorIndex(pub u32);

impl SectorIndex {
    pub const fn byte_offset(self) -> u64 {
        self.0 as u64 * SECTOR_SIZE
    }
}

impl fmt::Display for SectorIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Number of sectors in one `gethddblk` request, 1 through
/// [`SectorCount::MAX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectorCount(u32);

impl SectorCount {
    /// Largest count the monitor accepts (128 KiB).
    pub const MAX: Self = Self(0x100);
    pub const ONE: Self = Self(1);

    pub const fn new(count: u32) -> Result<Self, ArgumentError> {
        if count == 0 || count > Self::MAX.0 {
            return Err(ArgumentError::SectorCountOutOfRange {
                count,
                maximum: Self::MAX.0,
            });
        }

        Ok(Self(count))
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub const fn byte_len(self) -> usize {
        self.0 as usize * SECTOR_SIZE as usize
    }
}

impl fmt::Display for SectorCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// `gethddblk name=<device> block=<sector> count=<n>`: read `n` sectors.
///
/// The monitor reads the whole run before it replies, then sends `203`
/// and exactly `n * 512` bytes. A failed open or read, including a run
/// that extends past the end of the device, is a `400` with no text and
/// becomes [`Error::BlockReadRejected`].
#[derive(Debug, Clone, Copy)]
pub struct GetHddBlock<'a> {
    pub device: &'a DeviceName,
    pub first: SectorIndex,
    pub count: SectorCount,
}

impl Command for GetHddBlock<'_> {
    type Output = Vec<u8>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("gethddblk")
            .quoted("name", self.device.as_str())
            .map_err(report_argument)?
            .hex32("block", self.first.0)
            .hex32("count", self.count.get())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Binary
    }

    fn binary_len(&self) -> Option<usize> {
        Some(self.count.byte_len())
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_binary().map_err(rootcause::Report::new)
    }

    fn handle_remote(
        &self,
        code: RemoteStatus,
        _message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        (code == ErrorCode::Undefined).then(|| {
            Err(rootcause::Report::new(Error::BlockReadRejected {
                device: self.device.clone(),
                first: self.first,
                count: self.count,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;
    use crate::Client;
    use crate::transport::CaptureLog;
    use crate::transport::Direction;
    use crate::transport::MockTransport;

    fn device() -> DeviceName {
        DeviceName::new(r"\Device\BuiltInMuSfc").unwrap()
    }

    fn run(log: CaptureLog, first: u32, count: u32) -> Result<Vec<u8>, rootcause::Report<Error>> {
        let device = device();
        block_on(async {
            let mut client = Client::new(MockTransport::from_log(log))
                .read_banner()
                .await
                .unwrap();
            client
                .run(GetHddBlock {
                    device: &device,
                    first: SectorIndex(first),
                    count: SectorCount::new(count).unwrap(),
                })
                .await
        })
    }

    #[test]
    fn reads_exactly_count_sectors() {
        let payload: Vec<u8> = (0..0x400u32).map(|offset| (offset * 7) as u8).collect();
        let mut log = CaptureLog::new();
        log.push(Direction::ServerToClient, b"201- connected\r\n");
        log.push(
            Direction::ClientToServer,
            b"gethddblk name=\"\\Device\\BuiltInMuSfc\" block=0x000d2506 count=0x00000002\r\n",
        );
        log.push(
            Direction::ServerToClient,
            b"203- binary response follows\r\n",
        );
        log.push(Direction::ServerToClient, &payload);

        let data = run(log, 0xd2506, 2).unwrap();

        assert_eq!(data, payload);
    }

    #[test]
    fn empty_400_is_a_rejected_read() {
        let mut log = CaptureLog::new();
        log.push(Direction::ServerToClient, b"201- connected\r\n");
        log.push(
            Direction::ClientToServer,
            b"gethddblk name=\"\\Device\\BuiltInMuSfc\" block=0x000d2508 count=0x00000001\r\n",
        );
        log.push(Direction::ServerToClient, b"400- \r\n");

        let report = run(log, 0xd2508, 1).unwrap_err();

        let Error::BlockReadRejected {
            device: rejected,
            first,
            count,
        } = report.current_context()
        else {
            panic!("unexpected error {report:?}");
        };
        assert_eq!(*rejected, device());
        assert_eq!(*first, SectorIndex(0xd2508));
        assert_eq!(*count, SectorCount::ONE);
    }

    #[test]
    fn count_bounds() {
        assert!(SectorCount::new(0).is_err());
        assert_eq!(SectorCount::new(0x100).unwrap().byte_len(), 0x20000);
        assert!(SectorCount::new(0x101).is_err());
    }

    #[test]
    fn device_name_bounds() {
        assert!(DeviceName::new("").is_err());
        assert!(DeviceName::new("\\Device\\A\"").is_err());
        assert!(DeviceName::new("x".repeat(DeviceName::MAX_LENGTH)).is_ok());
        assert!(DeviceName::new("x".repeat(DeviceName::MAX_LENGTH + 1)).is_err());
    }
}
