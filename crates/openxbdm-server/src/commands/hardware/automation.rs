//! Virtual controllers driven by `autoinput`.
//!
//! The monitor keeps one controller per user slot. A controller presents
//! either a fixed gamepad state or plays back a queue of timed states. The
//! input system polls the controller; each entry stays current until its
//! deadline has passed and it has been presented `count` times. When an
//! entry starts without a poll count, the monitor arms a 10 us timer that
//! advances it once its deadline has passed; the timer runs after the
//! operation that started the entry releases the controller lock.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::reply::CommandError;

use super::HardwareError;

/// Number of user slots.
pub const USERS: u32 = 4;

/// Gamepad state of a virtual controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gamepad {
    pub buttons: u16,
    pub left_trigger: u8,
    pub right_trigger: u8,
    pub thumb_lx: i16,
    pub thumb_ly: i16,
    pub thumb_rx: i16,
    pub thumb_ry: i16,
}

/// Guide button; pressing it is reported to the input system separately.
pub const BUTTON_GUIDE: u16 = 0x400;

impl Gamepad {
    /// Bytes of one gamepad state on the wire and in console memory.
    pub const WIRE_SIZE: usize = 12;

    /// Decode the little-endian wire layout.
    pub fn from_wire(bytes: &[u8; Self::WIRE_SIZE]) -> Self {
        let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        Self {
            buttons: word(0),
            left_trigger: bytes[2],
            right_trigger: bytes[3],
            thumb_lx: word(4) as i16,
            thumb_ly: word(6) as i16,
            thumb_rx: word(8) as i16,
            thumb_ry: word(10) as i16,
        }
    }

    /// Decode the big-endian console layout.
    pub fn from_console(bytes: &[u8; Self::WIRE_SIZE]) -> Self {
        let word = |offset: usize| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        Self {
            buttons: word(0),
            left_trigger: bytes[2],
            right_trigger: bytes[3],
            thumb_lx: word(4) as i16,
            thumb_ly: word(6) as i16,
            thumb_rx: word(8) as i16,
            thumb_ry: word(10) as i16,
        }
    }

    /// Encode the big-endian console layout.
    pub fn to_console(self) -> [u8; Self::WIRE_SIZE] {
        let mut bytes = [0u8; Self::WIRE_SIZE];
        bytes[0..2].copy_from_slice(&self.buttons.to_be_bytes());
        bytes[2] = self.left_trigger;
        bytes[3] = self.right_trigger;
        bytes[4..6].copy_from_slice(&self.thumb_lx.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.thumb_ly.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.thumb_rx.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.thumb_ry.to_be_bytes());
        bytes
    }
}

/// One queued gamepad state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueEntry {
    pub packet: Gamepad,
    /// Minimum milliseconds the entry stays current.
    pub time: u32,
    /// Minimum number of polls that present the entry.
    pub count: u32,
}

/// Bytes the monitor allocates for a controller with `queue_length`
/// entries: the controller header holds the first entry.
pub const fn allocation_size(queue_length: u32) -> u64 {
    if queue_length == 0 {
        0x48
    } else {
        0x48 + (queue_length as u64 - 1) * 0x14
    }
}

/// Entries of storage a controller with `queue_length` entries needs.
pub const fn storage_entries(queue_length: u32) -> usize {
    if queue_length == 0 {
        1
    } else {
        queue_length as usize
    }
}

/// Content of a `queuepackets` upload: `count` packets, then `count` time
/// dwords if `times`, then `count` poll-count dwords if `counts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLayout {
    pub count: u32,
    pub times: bool,
    pub counts: bool,
}

impl UploadLayout {
    /// Upload size; `None` when it does not fit in 32 bits.
    pub fn size(self) -> Option<u32> {
        let count = u64::from(self.count);
        let size = count * 12
            + if self.times { count * 4 } else { 0 }
            + if self.counts { count * 4 } else { 0 };
        u32::try_from(size).ok()
    }
}

/// Why a controller operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomationError {
    /// User slot out of range, or a malformed queue request.
    BadParameter,
    /// No controller in the slot, or it is not connected.
    NotConnected,
    OutOfMemory,
    /// The input system refused to bind or unbind the controller.
    Refused,
}

impl From<AutomationError> for CommandError {
    fn from(error: AutomationError) -> Self {
        match error {
            AutomationError::BadParameter => Self::Status(ErrorCode::BadParameter),
            AutomationError::NotConnected => HardwareError::NotConnected.into(),
            AutomationError::OutOfMemory => Self::Status(ErrorCode::OutOfMemory),
            AutomationError::Refused => Self::Status(ErrorCode::UnknownCommand),
        }
    }
}

/// Result of the automation exports 167 to 174.
impl From<AutomationError> for Hresult {
    fn from(error: AutomationError) -> Self {
        CommandError::from(error).into()
    }
}

/// Queue state reported by `queryqueue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueStatus {
    pub queue_length: u32,
    pub queued: u32,
    pub remaining_ms: u32,
    pub remaining_count: u32,
}

/// Message the monitor passes to its debugger extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerMessage {
    /// Code 0x78: `setpacket` set a gamepad state.
    Packet { user: u8, packet: Gamepad },
    /// Code 0x7d: a controller was bound or unbound.
    Binding { user: u32, bound: bool },
}

impl DebuggerMessage {
    pub const fn code(self) -> u32 {
        match self {
            Self::Packet { .. } => 0x78,
            Self::Binding { .. } => 0x7d,
        }
    }

    /// Payload in console layout: `{u8 user, u8 pad, gamepad}` or
    /// `{u32 user, u32 bound}`. Returns the buffer and its used length.
    pub fn payload(self) -> ([u8; 14], usize) {
        let mut bytes = [0u8; 14];
        match self {
            Self::Packet { user, packet } => {
                bytes[0] = user;
                bytes[2..14].copy_from_slice(&packet.to_console());
                (bytes, 14)
            }
            Self::Binding { user, bound } => {
                bytes[0..4].copy_from_slice(&user.to_be_bytes());
                bytes[4..8].copy_from_slice(&u32::from(bound).to_be_bytes());
                (bytes, 8)
            }
        }
    }
}

/// Services a controller operation uses while it holds the controller
/// lock.
pub trait InputPlatform {
    /// Millisecond tick count.
    fn tick(&mut self) -> u32;
    /// Report a guide button press.
    fn press_guide(&mut self, user: u32);
}

/// Controllers of all user slots with the services that run outside the
/// controller lock: allocation, binding, and debugger extension messages.
pub trait Controllers {
    type Storage: AsRef<[QueueEntry]> + AsMut<[QueueEntry]>;
    /// Run `operation` with the controller lock held.
    fn locked<R>(
        &mut self,
        operation: impl FnOnce(&mut Automation<Self::Storage>, &mut dyn InputPlatform) -> R,
    ) -> R;
    /// Zeroed storage of [`storage_entries`]`(queue_length)` entries, or
    /// `None` when the [`allocation_size`] allocation fails.
    fn allocate(&mut self, queue_length: u32) -> Option<Self::Storage>;
    fn bind_controller(&mut self, user: u32) -> bool;
    fn unbind_controller(&mut self, user: u32) -> bool;
    fn tell_debugger(&mut self, message: DebuggerMessage);
}

fn check_user(user: u32) -> Result<(), AutomationError> {
    if user < USERS {
        Ok(())
    } else {
        Err(AutomationError::BadParameter)
    }
}

/// Install a connected controller with a queue of `queue_length` entries,
/// replacing the slot's controller, then bind it to the input system.
pub fn bind<C: Controllers>(
    controllers: &mut C,
    user: u32,
    queue_length: u32,
) -> Result<(), AutomationError> {
    check_user(user)?;
    let entries = controllers
        .allocate(queue_length)
        .ok_or(AutomationError::OutOfMemory)?;
    let controller = Controller::new(queue_length, entries);
    drop(controllers.locked(|automation, _| automation.users[user as usize].replace(controller)));
    if !controllers.bind_controller(user) {
        drop(controllers.locked(|automation, _| automation.users[user as usize].take()));
        return Err(AutomationError::Refused);
    }
    controllers.tell_debugger(DebuggerMessage::Binding { user, bound: true });
    Ok(())
}

/// Unbind the slot from the input system and remove its controller.
pub fn unbind<C: Controllers>(controllers: &mut C, user: u32) -> Result<(), AutomationError> {
    check_user(user)?;
    if !controllers.unbind_controller(user) {
        return Err(AutomationError::Refused);
    }
    drop(controllers.locked(|automation, _| automation.users[user as usize].take()));
    controllers.tell_debugger(DebuggerMessage::Binding { user, bound: false });
    Ok(())
}

/// Present a fixed state and stop playback. The debugger extension is
/// told about the state whenever the slot is in range.
pub fn set_packet<C: Controllers>(
    controllers: &mut C,
    user: u32,
    packet: Gamepad,
) -> Result<(), AutomationError> {
    check_user(user)?;
    let result =
        controllers.locked(|automation, platform| automation.set_packet(user, packet, platform));
    controllers.tell_debugger(DebuggerMessage::Packet {
        user: user as u8,
        packet,
    });
    result
}

/// Bind every installed controller again, as the monitor does when the
/// input system restarts.
pub fn rebind_all<C: Controllers>(controllers: &mut C) {
    let installed: [bool; USERS as usize] = controllers
        .locked(|automation, _| core::array::from_fn(|user| automation.users[user].is_some()));
    for (user, installed) in installed.into_iter().enumerate() {
        if installed {
            controllers.bind_controller(user as u32);
        }
    }
}

/// Result of a poll by the input system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// The slot has a controller that is not connected.
    NotConnected,
    /// Current state: a number that changes with each new state, and the
    /// gamepad.
    State { packet_number: u32, packet: Gamepad },
}

/// One virtual controller. `S` holds the queue entries; the first entry
/// is the fixed state outside playback.
#[derive(Debug)]
pub struct Controller<S> {
    connected: bool,
    playing: bool,
    guide_latched: bool,
    queue_length: u32,
    queued: u32,
    head: u32,
    packet_number: u32,
    remaining_count: u32,
    deadline: u32,
    time_sum: u64,
    count_sum: u64,
    entries: S,
}

impl<S: AsRef<[QueueEntry]> + AsMut<[QueueEntry]>> Controller<S> {
    /// A connected controller over zeroed storage of
    /// [`storage_entries`]`(queue_length)` entries.
    pub fn new(queue_length: u32, entries: S) -> Self {
        Self {
            connected: true,
            playing: false,
            guide_latched: false,
            queue_length,
            queued: 0,
            head: 0,
            packet_number: 0,
            remaining_count: 0,
            deadline: 0,
            time_sum: 0,
            count_sum: 0,
            entries,
        }
    }

    fn entry(&self, index: u32) -> QueueEntry {
        self.entries.as_ref()[index as usize]
    }

    fn entry_mut(&mut self, index: u32) -> &mut QueueEntry {
        &mut self.entries.as_mut()[index as usize]
    }

    fn reset(&mut self) {
        self.queued = 0;
        self.head = 0;
        self.packet_number = self.packet_number.wrapping_add(1);
    }

    fn update_guide(&mut self, user: u32, packet: Gamepad, platform: &mut dyn InputPlatform) {
        if packet.buttons & BUTTON_GUIDE == 0 {
            self.guide_latched = false;
        } else if !self.guide_latched {
            self.guide_latched = true;
            platform.press_guide(user);
        }
    }

    /// Make the head entry current. Returns whether the monitor arms its
    /// advance timer.
    fn start_entry(&mut self, user: u32, now: u32, platform: &mut dyn InputPlatform) -> bool {
        self.packet_number = self.packet_number.wrapping_add(1);
        if self.queued == 0 {
            self.guide_latched = false;
            self.remaining_count = 0;
            self.deadline = 0;
            return false;
        }
        let entry = self.entry(self.head);
        self.time_sum = self.time_sum.wrapping_sub(u64::from(entry.time));
        self.count_sum = self.count_sum.wrapping_sub(u64::from(entry.count));
        self.remaining_count = entry.count;
        self.deadline = now.wrapping_add(entry.time);
        self.update_guide(user, entry.packet, platform);
        self.remaining_count == 0
    }

    /// Advance past every entry whose deadline has passed and whose polls
    /// are used up. Returns whether the advance timer was armed.
    fn advance(&mut self, user: u32, now: u32, platform: &mut dyn InputPlatform) -> bool {
        let mut armed = false;
        while self.queued != 0
            && now.wrapping_sub(self.deadline) as i32 >= 0
            && self.remaining_count == 0
        {
            self.head = (self.head + 1) % self.queue_length;
            self.queued -= 1;
            armed |= self.start_entry(user, now, platform);
        }
        armed
    }
}

/// The controllers of all user slots.
#[derive(Debug)]
pub struct Automation<S> {
    users: [Option<Controller<S>>; USERS as usize],
    /// The advance timer is armed; it fires after the current operation.
    timer_armed: bool,
}

impl<S> Automation<S> {
    pub const fn new() -> Self {
        Self {
            users: [None, None, None, None],
            timer_armed: false,
        }
    }
}

impl<S> Default for Automation<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: AsRef<[QueueEntry]> + AsMut<[QueueEntry]>> Automation<S> {
    fn slot(&mut self, user: u32) -> Result<&mut Option<Controller<S>>, AutomationError> {
        self.users
            .get_mut(user as usize)
            .ok_or(AutomationError::BadParameter)
    }

    fn controller(&mut self, user: u32) -> Result<&mut Controller<S>, AutomationError> {
        self.slot(user)?
            .as_mut()
            .ok_or(AutomationError::NotConnected)
    }

    /// Run the advance timer the way its deferred procedure does once the
    /// operation that armed it has released the lock.
    fn run_timer(&mut self, platform: &mut dyn InputPlatform) {
        while self.timer_armed {
            self.timer_armed = false;
            let now = platform.tick();
            for (user, slot) in self.users.iter_mut().enumerate() {
                if let Some(controller) = slot.as_mut().filter(|controller| controller.playing) {
                    self.timer_armed |= controller.advance(user as u32, now, platform);
                }
            }
        }
    }

    pub fn connect(&mut self, user: u32) -> Result<(), AutomationError> {
        let controller = self.controller(user)?;
        if !controller.connected {
            controller.connected = true;
            controller.playing = false;
            controller.reset();
            controller.entry_mut(0).packet = Gamepad::default();
        }
        Ok(())
    }

    pub fn disconnect(&mut self, user: u32) -> Result<(), AutomationError> {
        let controller = self.controller(user)?;
        controller.connected = false;
        controller.playing = false;
        controller.reset();
        controller.entry_mut(0).packet = Gamepad::default();
        Ok(())
    }

    pub fn clear_queue(&mut self, user: u32) -> Result<(), AutomationError> {
        let controller = self.controller(user)?;
        if !controller.connected {
            return Err(AutomationError::NotConnected);
        }
        controller.reset();
        Ok(())
    }

    pub fn query(
        &mut self,
        user: u32,
        platform: &mut dyn InputPlatform,
    ) -> Result<QueueStatus, AutomationError> {
        let controller = self.controller(user)?;
        let mut status = QueueStatus {
            queue_length: controller.queue_length,
            ..QueueStatus::default()
        };
        if controller.connected && controller.playing {
            status.queued = controller.queued;
            let left = controller.deadline.wrapping_sub(platform.tick()) as i32;
            let remaining_ms = if left > 0 {
                controller.time_sum.wrapping_add(left as u64)
            } else {
                controller.time_sum
            };
            status.remaining_ms = u32::try_from(remaining_ms).unwrap_or(u32::MAX);
            let remaining_count =
                u64::from(controller.remaining_count).wrapping_add(controller.count_sum);
            status.remaining_count = u32::try_from(remaining_count).unwrap_or(u32::MAX);
        }
        Ok(status)
    }

    fn set_packet(
        &mut self,
        user: u32,
        packet: Gamepad,
        platform: &mut dyn InputPlatform,
    ) -> Result<(), AutomationError> {
        match self
            .slot(user)?
            .as_mut()
            .filter(|controller| controller.connected)
        {
            Some(controller) => {
                controller.playing = false;
                controller.reset();
                *controller.entry_mut(0) = QueueEntry {
                    packet,
                    time: 0,
                    count: 0,
                };
                controller.update_guide(user, packet, platform);
                Ok(())
            }
            None => Err(AutomationError::NotConnected),
        }
    }

    /// Queue the entries of an upload in wire layout. Returns the number
    /// accepted.
    pub fn queue(
        &mut self,
        user: u32,
        layout: UploadLayout,
        upload: &[u8],
        platform: &mut dyn InputPlatform,
    ) -> Result<u32, AutomationError> {
        let count = layout.count as usize;
        let times_offset = count * 12;
        let counts_offset = times_offset + if layout.times { count * 4 } else { 0 };
        let dword = |offset: usize| {
            u32::from_le_bytes([
                upload[offset],
                upload[offset + 1],
                upload[offset + 2],
                upload[offset + 3],
            ])
        };
        self.queue_entries(
            user,
            layout,
            |item| {
                let mut packet = [0u8; Gamepad::WIRE_SIZE];
                packet.copy_from_slice(&upload[item * 12..item * 12 + 12]);
                QueueEntry {
                    packet: Gamepad::from_wire(&packet),
                    time: if layout.times {
                        dword(times_offset + item * 4)
                    } else {
                        0
                    },
                    count: if layout.counts {
                        dword(counts_offset + item * 4)
                    } else {
                        0
                    },
                }
            },
            platform,
        )
    }

    /// Queue up to `layout.count` entries produced by `entry`; entries
    /// without times or counts must report 0 for them. Returns the number
    /// accepted.
    pub fn queue_entries(
        &mut self,
        user: u32,
        layout: UploadLayout,
        mut entry: impl FnMut(usize) -> QueueEntry,
        platform: &mut dyn InputPlatform,
    ) -> Result<u32, AutomationError> {
        if !(layout.times || layout.counts) {
            return Err(AutomationError::BadParameter);
        }
        let controller = self.controller(user)?;
        if !controller.connected || controller.queue_length == 0 {
            return Err(AutomationError::NotConnected);
        }
        let accepted = layout
            .count
            .min(controller.queue_length - controller.queued);
        controller.playing = true;
        let now = platform.tick();
        let mut index = (controller.head + controller.queued) % controller.queue_length;
        let mut armed = false;
        for item in 0..accepted as usize {
            let queued = entry(item);
            controller.time_sum = controller.time_sum.wrapping_add(u64::from(queued.time));
            controller.count_sum = controller.count_sum.wrapping_add(u64::from(queued.count));
            *controller.entry_mut(index) = queued;
            controller.queued += 1;
            if controller.queued == 1 {
                armed |= controller.start_entry(user, now, platform);
            }
            index = (index + 1) % controller.queue_length;
        }
        self.timer_armed |= armed;
        self.run_timer(platform);
        Ok(accepted)
    }

    /// Input system poll of a slot; `None` when the slot has no controller
    /// or is out of range.
    pub fn poll(&mut self, user: u32, platform: &mut dyn InputPlatform) -> Option<Poll> {
        let controller = self.users.get_mut(user as usize)?.as_mut()?;
        if !controller.connected {
            return Some(Poll::NotConnected);
        }
        if !controller.playing {
            return Some(Poll::State {
                packet_number: controller.packet_number,
                packet: controller.entry(0).packet,
            });
        }
        let now = platform.tick();
        let mut armed = controller.advance(user, now, platform);
        let packet_number = controller.packet_number;
        let packet = if controller.queued == 0 {
            Gamepad::default()
        } else {
            let packet = controller.entry(controller.head).packet;
            let remaining = controller.remaining_count;
            controller.remaining_count = remaining.saturating_sub(1);
            if remaining <= 1 {
                armed |= controller.advance(user, now, platform);
            }
            packet
        };
        self.timer_armed |= armed;
        self.run_timer(platform);
        Some(Poll::State {
            packet_number,
            packet,
        })
    }

    /// Connection query of a slot; `None` when the slot has no controller
    /// or is out of range.
    pub fn is_connected(&self, user: u32) -> Option<bool> {
        Some(self.users.get(user as usize)?.as_ref()?.connected)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    #[derive(Default)]
    struct Platform {
        now: u32,
        guide_presses: u32,
        automation: Automation<Vec<QueueEntry>>,
    }

    impl InputPlatform for Platform {
        fn tick(&mut self) -> u32 {
            self.now
        }
        fn press_guide(&mut self, _user: u32) {
            self.guide_presses += 1;
        }
    }

    impl Controllers for Platform {
        type Storage = Vec<QueueEntry>;
        fn locked<R>(
            &mut self,
            operation: impl FnOnce(&mut Automation<Vec<QueueEntry>>, &mut dyn InputPlatform) -> R,
        ) -> R {
            let mut automation = core::mem::take(&mut self.automation);
            let result = operation(&mut automation, self);
            self.automation = automation;
            result
        }
        fn allocate(&mut self, queue_length: u32) -> Option<Vec<QueueEntry>> {
            Some(vec![QueueEntry::default(); storage_entries(queue_length)])
        }
        fn bind_controller(&mut self, _user: u32) -> bool {
            true
        }
        fn unbind_controller(&mut self, _user: u32) -> bool {
            true
        }
        fn tell_debugger(&mut self, _message: DebuggerMessage) {}
    }

    fn upload(entries: &[(u16, u32, u32)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &(buttons, _, _) in entries {
            bytes.extend_from_slice(&buttons.to_le_bytes());
            bytes.extend_from_slice(&[0; 10]);
        }
        for &(_, time, _) in entries {
            bytes.extend_from_slice(&time.to_le_bytes());
        }
        for &(_, _, count) in entries {
            bytes.extend_from_slice(&count.to_le_bytes());
        }
        bytes
    }

    fn bound(queue_length: u32, platform: &mut Platform) -> Automation<Vec<QueueEntry>> {
        bind(platform, 0, queue_length).unwrap();
        core::mem::take(&mut platform.automation)
    }

    fn polled_buttons(
        automation: &mut Automation<Vec<QueueEntry>>,
        platform: &mut Platform,
    ) -> u16 {
        match automation.poll(0, platform) {
            Some(Poll::State { packet, .. }) => packet.buttons,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn entries_without_time_or_polls_drain_through_the_timer() {
        let mut platform = Platform::default();
        let mut automation = bound(4, &mut platform);
        let layout = UploadLayout {
            count: 3,
            times: true,
            counts: false,
        };
        let accepted = automation.queue(
            0,
            layout,
            &upload(&[(1, 0, 0), (2, 0, 0), (3, 0, 0)]),
            &mut platform,
        );
        assert_eq!(accepted, Ok(3));
        let status = automation.query(0, &mut platform).unwrap();
        assert_eq!(status.queued, 0);
    }

    #[test]
    fn entry_stays_until_deadline_and_poll_count_are_met() {
        let mut platform = Platform::default();
        let mut automation = bound(4, &mut platform);
        let layout = UploadLayout {
            count: 2,
            times: true,
            counts: true,
        };
        automation
            .queue(0, layout, &upload(&[(1, 10, 2), (2, 0, 1)]), &mut platform)
            .unwrap();
        assert_eq!(polled_buttons(&mut automation, &mut platform), 1);
        assert_eq!(polled_buttons(&mut automation, &mut platform), 1);
        assert_eq!(polled_buttons(&mut automation, &mut platform), 1);
        platform.now = 10;
        assert_eq!(polled_buttons(&mut automation, &mut platform), 2);
        assert_eq!(polled_buttons(&mut automation, &mut platform), 0);
    }

    #[test]
    fn query_reports_remaining_time_and_polls() {
        let mut platform = Platform::default();
        let mut automation = bound(8, &mut platform);
        let layout = UploadLayout {
            count: 3,
            times: true,
            counts: true,
        };
        automation
            .queue(
                0,
                layout,
                &upload(&[(1, 100, 1), (2, 50, 2), (3, 25, 3)]),
                &mut platform,
            )
            .unwrap();
        platform.now = 40;
        let status = automation.query(0, &mut platform).unwrap();
        assert_eq!(
            status,
            QueueStatus {
                queue_length: 8,
                queued: 3,
                remaining_ms: 75 + 60,
                remaining_count: 1 + 5
            }
        );
    }

    #[test]
    fn queue_accepts_only_free_entries() {
        let mut platform = Platform::default();
        let mut automation = bound(2, &mut platform);
        let layout = UploadLayout {
            count: 3,
            times: false,
            counts: true,
        };
        let accepted = automation.queue(
            0,
            layout,
            &upload(&[(1, 0, 5), (2, 0, 5), (3, 0, 5)]),
            &mut platform,
        );
        assert_eq!(accepted, Ok(2));
    }

    #[test]
    fn guide_press_is_reported_once_while_held() {
        let mut platform = Platform::default();
        let mut automation = bound(1, &mut platform);
        let guide = Gamepad {
            buttons: BUTTON_GUIDE,
            ..Gamepad::default()
        };
        automation.set_packet(0, guide, &mut platform).unwrap();
        automation.set_packet(0, guide, &mut platform).unwrap();
        automation
            .set_packet(0, Gamepad::default(), &mut platform)
            .unwrap();
        automation.set_packet(0, guide, &mut platform).unwrap();
        assert_eq!(platform.guide_presses, 2);
    }

    #[test]
    fn console_layout_is_big_endian_with_byte_triggers() {
        let bytes = [
            0x04, 0x01, 0x10, 0x20, 0xff, 0xfe, 0x00, 0x02, 0x80, 0x00, 0x7f, 0xff,
        ];
        let expected = Gamepad {
            buttons: 0x0401,
            left_trigger: 0x10,
            right_trigger: 0x20,
            thumb_lx: -2,
            thumb_ly: 2,
            thumb_rx: i16::MIN,
            thumb_ry: i16::MAX,
        };
        assert_eq!(Gamepad::from_console(&bytes), expected);
    }
}
