//! Virtual controller commands exposed by `autoinput`.

use core::ops::BitOr;
use core::ops::BitOrAssign;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use futures_util::io::AsyncWriteExt as _;
use rootcause::prelude::ResultExt as _;

use crate::Client;
use crate::Connected;
use crate::commands::KvLine;
use crate::commands::error::report_parse;
use crate::commands::parse_kv_line;
use crate::commands::value_u32;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::error::ExpectedShape;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

/// Xbox controller user slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserSlot(u8);

impl UserSlot {
    pub const COUNT: u8 = 4;

    pub const fn new(slot: u8) -> Option<Self> {
        if slot < Self::COUNT {
            Some(Self(slot))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Capacity of the timed packet queue allocated for a virtual controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerQueueLength(u32);

impl ControllerQueueLength {
    pub const FIXED_STATE: Self = Self(0);
    /// Largest length whose stock XBDM pool allocation fits in 32 bits.
    pub const MAX: u32 = 214_748_362;

    pub const fn new(length: u32) -> Result<Self, ArgumentError> {
        if length <= Self::MAX {
            Ok(Self(length))
        } else {
            Err(ArgumentError::ControllerQueueLengthOutOfRange {
                length,
                maximum: Self::MAX,
            })
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Button mask in the XInput gamepad packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GamepadButtons(u16);

impl GamepadButtons {
    pub const DPAD_UP: Self = Self(0x0001);
    pub const DPAD_DOWN: Self = Self(0x0002);
    pub const DPAD_LEFT: Self = Self(0x0004);
    pub const DPAD_RIGHT: Self = Self(0x0008);
    pub const START: Self = Self(0x0010);
    pub const BACK: Self = Self(0x0020);
    pub const LEFT_THUMB: Self = Self(0x0040);
    pub const RIGHT_THUMB: Self = Self(0x0080);
    pub const LEFT_SHOULDER: Self = Self(0x0100);
    pub const RIGHT_SHOULDER: Self = Self(0x0200);
    pub const GUIDE: Self = Self(0x0400);
    pub const A: Self = Self(0x1000);
    pub const B: Self = Self(0x2000);
    pub const X: Self = Self(0x4000);
    pub const Y: Self = Self(0x8000);

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for GamepadButtons {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for GamepadButtons {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// One XInput-compatible virtual gamepad state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gamepad {
    pub buttons: GamepadButtons,
    pub left_trigger: u8,
    pub right_trigger: u8,
    pub left_thumb_x: i16,
    pub left_thumb_y: i16,
    pub right_thumb_x: i16,
    pub right_thumb_y: i16,
}

impl Gamepad {
    pub const WIRE_SIZE: usize = 12;

    pub const fn to_wire(self) -> [u8; Self::WIRE_SIZE] {
        let buttons = self.buttons.bits().to_le_bytes();
        let left_thumb_x = self.left_thumb_x.to_le_bytes();
        let left_thumb_y = self.left_thumb_y.to_le_bytes();
        let right_thumb_x = self.right_thumb_x.to_le_bytes();
        let right_thumb_y = self.right_thumb_y.to_le_bytes();

        [
            buttons[0],
            buttons[1],
            self.left_trigger,
            self.right_trigger,
            left_thumb_x[0],
            left_thumb_x[1],
            left_thumb_y[0],
            left_thumb_y[1],
            right_thumb_x[0],
            right_thumb_x[1],
            right_thumb_y[0],
            right_thumb_y[1],
        ]
    }
}

/// Millisecond duration accepted by the stock XBDM playback timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GamepadDurationMillis(u32);

impl GamepadDurationMillis {
    pub const MAX: u32 = 2_147_483_647;

    pub const fn new(duration_ms: u32) -> Result<Self, ArgumentError> {
        if duration_ms > 0 && duration_ms <= Self::MAX {
            Ok(Self(duration_ms))
        } else {
            Err(ArgumentError::ControllerFrameDurationOutOfRange {
                duration_ms,
                maximum_ms: Self::MAX,
            })
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A gamepad packet and the minimum time for which the console presents it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedGamepad {
    pub packet: Gamepad,
    pub duration: GamepadDurationMillis,
}

/// Result from uploading timed packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedPackets(pub u32);

/// Current state of a virtual controller packet queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControllerQueueStatus {
    pub capacity: u32,
    pub queued: u32,
    pub remaining_ms: u32,
    pub remaining_polls: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct BindController {
    pub user: UserSlot,
    pub queue_length: ControllerQueueLength,
}

impl Command for BindController {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("autoinput")
            .dec("user", u64::from(self.user.get()))
            .flag("bind")
            .dec("queuelen", u64::from(self.queue_length.get()))
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnbindController {
    pub user: UserSlot,
}

impl Command for UnbindController {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(simple_command(self.user, "unbind"))
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QueryControllerQueue {
    pub user: UserSlot,
}

impl Command for QueryControllerQueue {
    type Output = ControllerQueueStatus;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(simple_command(self.user, "queryqueue"))
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let values = parse_kv_line(&head);

        Ok(ControllerQueueStatus {
            capacity: required_u32(&values, "nQueue")?,
            queued: required_u32(&values, "nPacket")?,
            remaining_ms: required_u32(&values, "t_remain_ms")?,
            remaining_polls: required_u32(&values, "t_remain_count")?,
        })
    }
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Replace the fixed state of a bound virtual controller.
    pub async fn set_gamepad(
        &mut self,
        user: UserSlot,
        packet: Gamepad,
    ) -> Result<(), rootcause::Report<Error>> {
        let line = simple_command(user, "setpacket");
        self.begin_upload(&line).await?;
        self.transport_mut()
            .write_all(&packet.to_wire())
            .await
            .map_err(Error::from)
            .into_report()
            .attach("sending autoinput gamepad packet")?;
        self.transport_mut()
            .flush()
            .await
            .map_err(Error::from)
            .into_report()
            .attach("flushing autoinput gamepad packet")?;
        self.read_post_upload_response()
            .await?
            .expect_ok()
            .map_err(rootcause::Report::new)?;

        Ok(())
    }

    /// Upload and begin playing timed gamepad packets on the console.
    pub async fn queue_gamepads(
        &mut self,
        user: UserSlot,
        packets: &[TimedGamepad],
    ) -> Result<QueuedPackets, rootcause::Report<Error>> {
        let count = packet_count(packets.len())
            .map_err(Error::from)
            .map_err(rootcause::Report::new)?;
        let line = ArgBuilder::new("autoinput")
            .dec("user", u64::from(user.get()))
            .flag("queuepackets")
            .dec("count", u64::from(count))
            .flag("timearray")
            .finish();
        self.begin_upload(&line).await?;

        for timed in packets {
            self.transport_mut()
                .write_all(&timed.packet.to_wire())
                .await
                .map_err(Error::from)
                .into_report()
                .attach("sending queued autoinput gamepad packet")?;
        }
        for timed in packets {
            self.transport_mut()
                .write_all(&timed.duration.get().to_le_bytes())
                .await
                .map_err(Error::from)
                .into_report()
                .attach("sending queued autoinput duration")?;
        }
        self.transport_mut()
            .flush()
            .await
            .map_err(Error::from)
            .into_report()
            .attach("flushing queued autoinput packets")?;

        let head = self
            .read_post_upload_response()
            .await?
            .expect_ok()
            .map_err(rootcause::Report::new)?;
        let values = parse_kv_line(&head);
        let queued = required_u32(&values, "queued")?;

        Ok(QueuedPackets(queued))
    }

    async fn begin_upload(&mut self, line: &str) -> Result<(), rootcause::Report<Error>> {
        let response = self.send_raw(line).await?;
        if matches!(response, Response::SendBinary { .. }) {
            return Ok(());
        }

        Err(rootcause::Report::new(Error::UnexpectedStatus {
            expected: ExpectedShape::SendBinary204,
            got: response.status(),
        }))
    }
}
fn required_u32(values: &KvLine<'_>, key: &'static str) -> Result<u32, rootcause::Report<Error>> {
    let value = values.require(key).map_err(report_parse)?;

    value_u32(value, key).map_err(report_parse)
}

fn packet_count(count: usize) -> Result<u32, ArgumentError> {
    if count == 0 {
        return Err(ArgumentError::EmptyControllerPacketQueue);
    }

    u32::try_from(count).map_err(|_| ArgumentError::ControllerPacketCountOverflow)
}

fn simple_command(user: UserSlot, action: &'static str) -> String {
    ArgBuilder::new("autoinput")
        .dec("user", u64::from(user.get()))
        .flag(action)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gamepad_wire_layout_is_little_endian() {
        let packet = Gamepad {
            buttons: GamepadButtons::GUIDE | GamepadButtons::A,
            left_trigger: 0x40,
            right_trigger: 0x80,
            left_thumb_x: -2,
            left_thumb_y: 0x1234,
            right_thumb_x: -0x1234,
            right_thumb_y: i16::MIN,
        };

        assert_eq!(
            packet.to_wire(),
            [
                0x00, 0x14, 0x40, 0x80, 0xfe, 0xff, 0x34, 0x12, 0xcc, 0xed, 0x00, 0x80,
            ]
        );
    }

    #[test]
    fn controller_commands_encode_user_slot() {
        let user = UserSlot::new(2).unwrap();
        let bind = BindController {
            user,
            queue_length: ControllerQueueLength::new(16).unwrap(),
        };

        assert_eq!(
            bind.wire_line().unwrap(),
            "autoinput user=2 bind queuelen=16"
        );
        assert_eq!(
            QueryControllerQueue { user }.wire_line().unwrap(),
            "autoinput user=2 queryqueue"
        );
    }

    #[test]
    fn queue_limits_reject_dangerous_sizes() {
        assert_eq!(
            ControllerQueueLength::new(ControllerQueueLength::MAX)
                .expect("maximum queue length is safe")
                .get(),
            ControllerQueueLength::MAX
        );
        assert!(ControllerQueueLength::new(ControllerQueueLength::MAX + 1).is_err());
        assert!(matches!(
            packet_count(0),
            Err(ArgumentError::EmptyControllerPacketQueue)
        ));
    }
    #[test]
    fn duration_rejects_timer_wraparound() {
        assert!(GamepadDurationMillis::new(0).is_err());
        assert_eq!(
            GamepadDurationMillis::new(GamepadDurationMillis::MAX)
                .expect("maximum duration is safe")
                .get(),
            GamepadDurationMillis::MAX
        );
        assert!(GamepadDurationMillis::new(GamepadDurationMillis::MAX + 1).is_err());
    }
}
