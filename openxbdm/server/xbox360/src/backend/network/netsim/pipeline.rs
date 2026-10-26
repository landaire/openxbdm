//! Queue stages and their composition (stock classes 0x91f92fd0..0x91f94700).
//! Times are time base ticks; a stage keeps its frames ordered by release
//! time, and dropped frames move to the front so they leave first. A
//! release time is `Option<ReleaseTime>`, where `None` is never and orders
//! after every time; stock stores u64::MAX for it and orders by that value
//! (instance +0x48 holds it while nothing is due).

use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::ptr::null_mut;

use openxbdm_server::commands::network::netsim::ConfigMask;
use openxbdm_server::commands::network::netsim::LOSS_SCALE;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueKind;

use super::memory;

/// Time base rate the library assumes (0x2f90838).
const TIMEBASE_FREQUENCY: u64 = 49_875_000;
/// Time base ticks per millisecond, for latencies.
const TICKS_PER_MILLISECOND: u64 = TIMEBASE_FREQUENCY / 1000;

/// Random-number source of the stages (instance method 0,
/// `XeCryptRandom`).
pub(super) trait Random {
    fn fill(&mut self, buffer: &mut [u8]);

    /// Uniform in `low..=high` (0x91f94140).
    fn range64(&mut self, low: u64, high: u64) -> u64 {
        let span = high.wrapping_sub(low);
        if span == 0 {
            return low;
        }

        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);

        let value = u64::from_be_bytes(bytes);
        let value = if span == u64::MAX {
            value
        } else {
            value % (span + 1)
        };

        value.wrapping_add(low)
    }

    /// Uniform in `low..=high` (0x91f940b8).
    fn range32(&mut self, low: u32, high: u32) -> u32 {
        let span = high.wrapping_sub(low);
        if span == 0 {
            return low;
        }

        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);

        let value = u32::from_be_bytes(bytes);
        let value = if span == u32::MAX {
            value
        } else {
            value % (span + 1)
        };

        value.wrapping_add(low)
    }
}

/// A release time other than never: time base ticks below u64::MAX. It
/// holds the complement of the ticks, so `Option<ReleaseTime>` is one u64
/// whose `None` is the complement of stock's u64::MAX.
#[derive(Clone, Copy)]
pub(super) struct ReleaseTime(NonZeroU64);

impl ReleaseTime {
    /// `ticks` as a release time; u64::MAX is never, as in stock.
    #[inline]
    pub(super) const fn at(ticks: u64) -> Option<Self> {
        match NonZeroU64::new(!ticks) {
            Some(complement) => Some(Self(complement)),
            None => None,
        }
    }

    #[inline]
    pub(super) const fn ticks(self) -> u64 {
        !self.0.get()
    }
}

/// A copied frame (stock 0x1c-byte header before the frame).
#[repr(C)]
struct Packet {
    next: *mut Packet,
    prev: *mut Packet,
    /// Release time in stored form ([`to_stored`]); list order and due
    /// checks compare it as stock does.
    time: u64,
    /// Bytes the current stage accounts for.
    size: u32,
    dropped: bool,
    /// The frame was rewritten by a redirect and leaves through the
    /// unmodified transmit path.
    redirected: bool,
    length: u16,
}

impl Packet {
    #[inline]
    fn release_time(&self) -> Option<ReleaseTime> {
        from_stored(self.time)
    }

    #[inline]
    fn set_release_time(&mut self, time: Option<ReleaseTime>) {
        self.time = to_stored(time);
    }
}

/// A packet in no stage list, owned by the holder until it is linked into
/// a list, a [`Batch`], or freed.
pub(super) struct OwnedPacket(NonNull<Packet>);

impl OwnedPacket {
    /// Copy `frame` into a new packet (0x91f8cb70).
    pub(super) fn allocate(frame: &[u8]) -> Option<Self> {
        let header = core::mem::size_of::<Packet>();
        let block = memory::allocate(header + frame.len())?;
        let packet = block.cast::<Packet>();

        // SAFETY: the block holds the header and the frame bytes, and pool
        // blocks are 8-aligned.
        unsafe {
            packet.write(Packet {
                next: null_mut(),
                prev: null_mut(),
                time: 0,
                size: 0,
                dropped: false,
                redirected: false,
                length: frame.len() as u16,
            });
            core::ptr::copy_nonoverlapping(frame.as_ptr(), block.as_ptr().add(header), frame.len());
        }

        Some(Self(packet))
    }

    pub(super) fn frame(&mut self) -> &mut [u8] {
        // SAFETY: an owned packet is live, and its frame bytes follow the
        // header.
        unsafe {
            let length = usize::from(self.0.as_ref().length);
            core::slice::from_raw_parts_mut(
                self.0
                    .as_ptr()
                    .cast::<u8>()
                    .add(core::mem::size_of::<Packet>()),
                length,
            )
        }
    }

    fn header(&self) -> &Packet {
        // SAFETY: an owned packet is live.
        unsafe { self.0.as_ref() }
    }

    pub(super) fn length(&self) -> u16 {
        self.header().length
    }

    pub(super) fn redirected(&self) -> bool {
        self.header().redirected
    }

    pub(super) fn set_redirected(&mut self) {
        // SAFETY: an owned packet is live and reached only through `self`.
        unsafe { self.0.as_mut() }.redirected = true;
    }

    fn size(&self) -> u32 {
        self.header().size
    }

    pub(super) fn free(self) {
        // SAFETY: the block came from `memory::allocate` and `self` is its
        // only owner.
        unsafe { memory::free(self.0.as_ptr().cast()) };
    }
}

/// A packet leaving a stage.
pub(super) struct Released {
    pub(super) packet: OwnedPacket,
    pub(super) dropped: bool,
}

/// Released packets waiting to leave once the lock is dropped, linked
/// through their `next` field. Members are live packets the batch owns.
pub(super) struct Batch {
    packets: *mut Packet,
}

impl Batch {
    pub(super) const fn new() -> Self {
        Self {
            packets: null_mut(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.packets.is_null()
    }

    pub(super) fn push(&mut self, packet: OwnedPacket) {
        let packet = packet.0.as_ptr();

        // SAFETY: an owned packet is live and in no list.
        unsafe { (*packet).next = self.packets };
        self.packets = packet;
    }

    pub(super) fn pop(&mut self) -> Option<OwnedPacket> {
        let packet = NonNull::new(self.packets)?;

        // SAFETY: members are live; the popped packet leaves the batch.
        self.packets = unsafe { packet.as_ref().next };

        Some(OwnedPacket(packet))
    }

    /// Frames leave in release order.
    pub(super) fn reverse(&mut self) {
        let mut reversed = Batch::new();

        while let Some(packet) = self.pop() {
            reversed.push(packet);
        }

        *self = reversed;
    }
}

/// Time-ordered frames of a stage with byte and frame counts of the
/// frames not dropped. Members are live packets the list owns.
pub(super) struct PacketList {
    head: *mut Packet,
    tail: *mut Packet,

    bytes: u64,
    count: u32,
}

// The list is only reached through the instance, under its spin lock.
impl PacketList {
    const fn new() -> Self {
        Self {
            head: null_mut(),
            tail: null_mut(),
            bytes: 0,
            count: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Insert after the last frame released no later than `time`
    /// (0x91f93bd0).
    fn insert(&mut self, packet: OwnedPacket, time: Option<ReleaseTime>, size: u32) {
        let packet = packet.0.as_ptr();
        let stored = to_stored(time);

        // SAFETY: list members and the owned `packet` are live packets.
        unsafe {
            (*packet).time = stored;
            (*packet).size = size;
            (*packet).dropped = false;

            let mut after = self.tail;
            while !after.is_null() && (*after).time > stored {
                after = (*after).prev;
            }

            self.link_after(packet, after);
        }

        self.bytes = self.bytes.wrapping_add(u64::from(size));
        self.count = self.count.wrapping_add(1);
    }

    /// # Safety
    /// `packet` is unlinked; `after` is a member or null for the front.
    unsafe fn link_after(&mut self, packet: *mut Packet, after: *mut Packet) {
        // SAFETY: guaranteed by the caller.
        unsafe {
            let next = if after.is_null() {
                self.head
            } else {
                (*after).next
            };

            (*packet).prev = after;
            (*packet).next = next;

            if after.is_null() {
                self.head = packet;
            } else {
                (*after).next = packet;
            }

            if next.is_null() {
                self.tail = packet;
            } else {
                (*next).prev = packet;
            }
        }
    }

    /// # Safety
    /// `packet` is a member.
    unsafe fn unlink(&mut self, packet: *mut Packet) {
        // SAFETY: guaranteed by the caller.
        unsafe {
            let prev = (*packet).prev;
            let next = (*packet).next;

            if prev.is_null() {
                self.head = next;
            } else {
                (*prev).next = next;
            }

            if next.is_null() {
                self.tail = prev;
            } else {
                (*next).prev = prev;
            }

            (*packet).prev = null_mut();
            (*packet).next = null_mut();
        }
    }

    /// Release time of the last frame not dropped (0x91f93b90), or `now`
    /// when there is none.
    fn last_live_time(&self, now: u64) -> Option<ReleaseTime> {
        let packet = self.last_live();
        if packet.is_null() {
            return ReleaseTime::at(now);
        }

        // SAFETY: a non-null result of `last_live` is a member.
        unsafe { (*packet).release_time() }
    }

    fn last_live(&self) -> *mut Packet {
        let mut packet = self.tail;

        // SAFETY: members are live packets.
        unsafe {
            while !packet.is_null() && (*packet).dropped {
                packet = (*packet).prev;
            }
        }

        packet
    }

    /// Drop a member (0x91f93dd8): it stops counting and moves in front of
    /// the frames not dropped.
    ///
    /// # Safety
    /// `packet` is a member.
    unsafe fn drop_packet(&mut self, packet: *mut Packet) {
        // SAFETY: guaranteed by the caller; members are live packets.
        unsafe {
            if (*packet).dropped {
                return;
            }

            (*packet).dropped = true;
            self.bytes = self.bytes.wrapping_sub(u64::from((*packet).size));
            self.count = self.count.wrapping_sub(1);
            (*packet).set_release_time(ReleaseTime::at(0));

            let mut before = (*packet).prev;
            let mut skipped = false;
            while !before.is_null() && !(*before).dropped {
                before = (*before).prev;
                skipped = true;
            }

            if skipped {
                self.unlink(packet);
                self.link_after(packet, before);
            }
        }
    }

    /// Drop from the back until the limits hold (0x91f93ea0, 0x91f93ee0).
    /// Stock walks backward from each dropped frame's new position, which
    /// corrupts the list when more than one frame must go; this drops the
    /// last frame not dropped each time.
    fn enforce(&mut self, byte_limit: u64, packet_limit: Option<u32>) {
        while self.bytes > byte_limit {
            let packet = self.last_live();
            if packet.is_null() {
                break;
            }

            // SAFETY: a non-null result of `last_live` is a member.
            unsafe { self.drop_packet(packet) };
        }

        let Some(limit) = packet_limit else {
            return;
        };

        while self.count > limit {
            let packet = self.last_live();
            if packet.is_null() {
                break;
            }

            // SAFETY: as above.
            unsafe { self.drop_packet(packet) };
        }
    }

    /// # Safety
    /// The list is not empty.
    unsafe fn pop(&mut self) -> Released {
        // SAFETY: guaranteed by the caller.
        let packet = unsafe { NonNull::new_unchecked(self.head) };

        // SAFETY: the head is a live member; unlinking passes its ownership
        // to the result.
        let dropped = unsafe {
            self.unlink(packet.as_ptr());
            packet.as_ref().dropped
        };
        let packet = OwnedPacket(packet);

        if !dropped {
            self.bytes = self.bytes.wrapping_sub(u64::from(packet.size()));
            self.count = self.count.wrapping_sub(1);
        }

        Released { packet, dropped }
    }

    /// Release the front frame now (0x91f93c68).
    fn pop_now(&mut self) -> Option<Released> {
        // SAFETY: checked not empty.
        (!self.is_empty()).then(|| unsafe { self.pop() })
    }

    /// Release the front frame once its time has come or it is dropped
    /// (0x91f93d08). A frame never released is due only at time u64::MAX,
    /// as in stock.
    fn pop_due(&mut self, now: u64) -> Option<Released> {
        if self.is_empty() {
            return None;
        }

        // SAFETY: the head is a live packet.
        let (time, dropped) = unsafe { ((*self.head).time, (*self.head).dropped) };

        // SAFETY: checked not empty.
        (time <= now || dropped).then(|| unsafe { self.pop() })
    }

    /// Release time of the front frame, not earlier than `now`
    /// (0x91f93b10).
    #[inline(never)]
    fn next_time(&self, now: u64) -> Option<ReleaseTime> {
        if self.is_empty() {
            return None;
        }

        // SAFETY: the head is a live packet.
        from_stored(unsafe { (*self.head).time }.max(now))
    }

    /// Size the front frame needs from a token bucket; dropped frames need
    /// none.
    fn head_cost(&self) -> Option<u64> {
        // SAFETY: the head, when present, is a live packet.
        (!self.is_empty()).then(|| unsafe {
            if (*self.head).dropped {
                0
            } else {
                u64::from((*self.head).size)
            }
        })
    }

    fn free_all(&mut self) {
        while !self.is_empty() {
            // SAFETY: checked not empty.
            unsafe { self.pop() }.packet.free();
        }
    }
}

/// Transmission rate in bits per second (0x91f93f78); `None` is unlimited.
#[derive(Clone, Copy)]
pub(super) struct Rate(Option<u32>);

impl Rate {
    /// A settings rate: 0xffffffff is unlimited.
    fn from_setting(rate: u32) -> Self {
        Self((rate != u32::MAX).then_some(rate))
    }

    /// Ticks to send `bytes`, or `None` when nothing is sent.
    fn ticks(self, bytes: u32) -> Option<u64> {
        match self.0 {
            None => Some(0),
            Some(0) => None,
            Some(rate) => Some((u64::from(bytes) << 3) * TIMEBASE_FREQUENCY / u64::from(rate)),
        }
    }

    /// Release time of a frame of `bytes` that starts after the stage's
    /// last frame, or now.
    fn release_time(self, list: &PacketList, now: u64, bytes: u32) -> Option<ReleaseTime> {
        let start = to_stored(list.last_live_time(now));
        let ticks = self.ticks(bytes)?;

        from_stored(saturating_add(
            start,
            i64::try_from(ticks).unwrap_or(i64::MAX),
        ))
    }
}

/// Rate stage with queue limits (stock vtable 0x91f0f554): each frame
/// costs its wire size, at least 64 bytes with checksum plus 8 bytes of
/// preamble.
pub(super) struct LinkRate {
    list: PacketList,
    rate: Rate,

    byte_limit: u64,
    packet_limit: Option<u32>,
}

impl LinkRate {
    fn enqueue(&mut self, packet: OwnedPacket, length: u32, now: u64) {
        const FRAME_CHECK_SEQUENCE: u32 = 4;
        const MINIMUM_FRAME: u32 = 0x40;
        const PREAMBLE: u32 = 8;

        let wire = length.wrapping_add(FRAME_CHECK_SEQUENCE).max(MINIMUM_FRAME) + PREAMBLE;
        let time = self.rate.release_time(&self.list, now, wire);
        self.list.insert(packet, time, wire);
        self.list.enforce(self.byte_limit, self.packet_limit);
    }
}

/// Random latency stage (vtable 0x91f0f568).
pub(super) struct Latency {
    list: PacketList,

    minimum: u64,
    maximum: u64,
    reorder: bool,
}

impl Latency {
    fn enqueue(&mut self, packet: OwnedPacket, size: u32, now: u64, random: &mut dyn Random) {
        let delay = random.range64(self.minimum, self.maximum);
        let delayed = saturating_add(now, i64::try_from(delay).unwrap_or(i64::MAX));

        // `delayed` is not before `now`, so the fallback to `now` leaves it
        // unchanged when every frame is dropped.
        let time = if self.reorder {
            delayed
        } else {
            delayed.max(to_stored(self.list.last_live_time(now)))
        };

        self.list.insert(packet, from_stored(time), size);
    }
}

/// Random loss stage (vtable 0x91f0f57c).
pub(super) struct Loss {
    list: PacketList,
    /// Frames lost per [`LOSS_SCALE`].
    loss: u32,
}

impl Loss {
    fn enqueue(&mut self, packet: OwnedPacket, size: u32, now: u64, random: &mut dyn Random) {
        let member = packet.0.as_ptr();
        self.list.insert(packet, ReleaseTime::at(now), size);
        if self.loss == 0 {
            return;
        }

        let draw = if self.loss >= LOSS_SCALE {
            0
        } else {
            random.range32(0, LOSS_SCALE)
        };

        if draw <= self.loss {
            // SAFETY: `member` was just inserted and nothing removed it.
            unsafe { self.list.drop_packet(member) };
        }
    }
}

/// Token bucket with queue limits (vtable 0x91f0f52c). Every `period`
/// ticks adds `step` bytes up to `depth`.
pub(super) struct Bucket {
    list: PacketList,

    period: i64,
    step: u64,
    depth: u64,
    last: u64,
    tokens: u64,

    byte_limit: u64,
    packet_limit: Option<u32>,
}

impl Bucket {
    /// 0x91f93240.
    fn refill(&mut self, now: u64) {
        let periods = saturating_difference(self.last, now).wrapping_div(self.period);
        if periods <= 0 {
            return;
        }

        let added = self.step.wrapping_mul(periods as u64);
        self.tokens = if self.depth.wrapping_sub(self.tokens) > added {
            self.tokens.wrapping_add(added)
        } else {
            self.depth
        };
        self.last = saturating_add(self.last, self.period.wrapping_mul(periods));
    }

    fn enqueue(&mut self, packet: OwnedPacket, size: u32, now: u64) {
        self.list.insert(packet, ReleaseTime::at(now), size);
        self.list.enforce(self.byte_limit, self.packet_limit);
    }

    /// 0x91f932e8.
    fn dequeue(&mut self, now: u64) -> Option<Released> {
        self.list.head_cost()?;
        self.refill(now);

        let cost = self.list.head_cost()?;
        if self.tokens < cost {
            return None;
        }

        self.tokens -= cost;

        self.list.pop_now()
    }

    /// 0x91f93108.
    fn next_time(&self, now: u64) -> Option<ReleaseTime> {
        let cost = self.list.head_cost()?;
        if self.tokens >= cost {
            return ReleaseTime::at(now);
        }

        if self.step == 0 {
            return None;
        }

        let periods = (cost - self.tokens).div_ceil(self.step);

        from_stored(saturating_add(self.last, self.period.wrapping_mul(periods as i64)).max(now))
    }

    /// Token rate in bits per second (0x91f931b8, 0x91f93fc8): whole bytes
    /// per tick, or one byte per whole number of ticks.
    fn set_token_rate(&mut self, rate: u32) {
        if rate == 0 {
            self.period = 1;
            self.step = 0;
            return;
        }

        let bytes_per_tick = f64::from(rate) / TIMEBASE_FREQUENCY as f64 * 1.0 * 0.125;

        // SAFETY (both conversions): a nonzero u32 rate puts
        // `bytes_per_tick` in (0, 11) and its reciprocal below 4e8, finite
        // and within the i64 range.
        if bytes_per_tick >= 1.0 {
            self.period = 1;
            self.step = unsafe { bytes_per_tick.to_int_unchecked::<i64>() } as u64;
        } else {
            self.period = unsafe { (1.0 / bytes_per_tick * 1.0).to_int_unchecked::<i64>() };
            self.step = 1;
        }
    }
}

/// Plain rate stage (vtable 0x91f0f540).
pub(super) struct PacketListRate {
    list: PacketList,
    rate: Rate,
}

/// Frames of a queue (stock queue processor at queue +0x58).
pub(super) enum Pipeline {
    /// Arrival order, released at once (vtable 0x91f0f590).
    Unshaped(PacketList),
    /// Rate with limits, then latency, then loss (vtable 0x91f0f5a4,
    /// stages pulled front to back).
    Link {
        rate: LinkRate,
        latency: Latency,
        loss: Loss,
    },
    /// Token bucket with limits, then rate (vtable 0x91f0f5b8, stages
    /// pulled back to front).
    TokenBucket {
        bucket: Bucket,
        rate: PacketListRate,
    },
}

impl Pipeline {
    /// A new queue of `kind` with stock defaults (0x91f8cbc0).
    pub(super) fn new(kind: QueueKind) -> Self {
        /// Default limits of the first stage: 200 frames, 128 KiB.
        const DEFAULT_PACKET_LIMIT: u32 = 200;
        const DEFAULT_BYTE_LIMIT: u64 = 0x2_0000;

        match kind {
            QueueKind::Unshaped => Self::Unshaped(PacketList::new()),
            QueueKind::Link => Self::Link {
                rate: LinkRate {
                    list: PacketList::new(),
                    rate: Rate(None),
                    byte_limit: DEFAULT_BYTE_LIMIT,
                    packet_limit: Some(DEFAULT_PACKET_LIMIT),
                },
                latency: Latency {
                    list: PacketList::new(),
                    minimum: 0,
                    maximum: 0,
                    reorder: false,
                },
                loss: Loss {
                    list: PacketList::new(),
                    loss: 0,
                },
            },
            QueueKind::TokenBucket => Self::TokenBucket {
                bucket: Bucket {
                    list: PacketList::new(),
                    period: 1,
                    step: u64::MAX,
                    depth: u64::MAX,
                    last: 0,
                    tokens: u64::MAX,
                    byte_limit: DEFAULT_BYTE_LIMIT,
                    packet_limit: Some(DEFAULT_PACKET_LIMIT),
                },
                rate: PacketListRate {
                    list: PacketList::new(),
                    rate: Rate(None),
                },
            },
        }
    }

    /// Apply validated settings that [`QueueConfig::merge`] accepted for
    /// this kind (0x91f8e800).
    pub(super) fn configure(&mut self, update: &QueueConfig, now: u64) {
        let mask = update.mask;
        let packet_limit = (update.packet_limit != u32::MAX).then_some(update.packet_limit);

        match self {
            // An unshaped queue has no settings.
            Self::Unshaped(_) => {}
            Self::Link {
                rate,
                latency,
                loss,
            } => {
                if mask.contains(ConfigMask::LIMITS) {
                    rate.byte_limit = u64::from(update.byte_limit);
                    rate.packet_limit = packet_limit;
                    rate.list.enforce(rate.byte_limit, rate.packet_limit);
                }

                if mask.contains(ConfigMask::RATE) {
                    rate.rate = Rate::from_setting(update.rate);
                }

                if mask.contains(ConfigMask::LOSS) {
                    loss.loss = update.loss;
                }

                if mask.contains(ConfigMask::LATENCY) {
                    latency.minimum = u64::from(update.latency_min) * TICKS_PER_MILLISECOND;
                    latency.maximum = u64::from(update.latency_max) * TICKS_PER_MILLISECOND;
                    latency.reorder = mask.contains(ConfigMask::REORDER);
                }
            }
            Self::TokenBucket { bucket, rate } => {
                if mask.contains(ConfigMask::LIMITS) {
                    bucket.byte_limit = u64::from(update.byte_limit);
                    bucket.packet_limit = packet_limit;
                    bucket.list.enforce(bucket.byte_limit, bucket.packet_limit);
                }

                if mask.contains(ConfigMask::RATE) {
                    rate.rate = Rate::from_setting(update.rate);
                }

                if mask.contains(ConfigMask::TOKEN_RATE) {
                    bucket.set_token_rate(update.token_rate);
                }

                if mask.contains(ConfigMask::BUCKET) {
                    bucket.depth = u64::from(update.bucket_depth);
                    bucket.tokens = bucket.tokens.min(bucket.depth);

                    if mask.contains(ConfigMask::START_FULL) {
                        bucket.tokens = bucket.depth;
                        bucket.last = now;
                    } else if mask.contains(ConfigMask::START_EMPTY) {
                        bucket.tokens = 0;
                        bucket.last = now;
                    }
                }
            }
        }
    }

    /// Accept a frame (method 0).
    pub(super) fn enqueue(&mut self, packet: OwnedPacket, length: u32, now: u64) {
        match self {
            Self::Unshaped(list) => list.insert(packet, ReleaseTime::at(now), length),
            Self::Link { rate, .. } => rate.enqueue(packet, length, now),
            Self::TokenBucket { bucket, .. } => bucket.enqueue(packet, length, now),
        }
    }

    /// Release one frame (method 1): the front-to-back composition moves at
    /// most one frame per stage per call (0x91f94338); the back-to-front
    /// one refills the last stage until the first has nothing (0x91f94508).
    pub(super) fn dequeue(&mut self, now: u64, random: &mut dyn Random) -> Option<Released> {
        match self {
            Self::Unshaped(list) => list.pop_now(),
            Self::Link {
                rate,
                latency,
                loss,
            } => {
                if let Some(released) = rate.list.pop_due(now) {
                    if released.dropped {
                        return Some(released);
                    }

                    let size = released.packet.size();
                    latency.enqueue(released.packet, size, now, random);
                }

                if let Some(released) = latency.list.pop_due(now) {
                    if released.dropped {
                        return Some(released);
                    }

                    let size = released.packet.size();
                    loss.enqueue(released.packet, size, now, random);
                }

                loss.list.pop_now()
            }
            Self::TokenBucket { bucket, rate } => loop {
                if let Some(released) = rate.list.pop_due(now) {
                    return Some(released);
                }

                let released = bucket.dequeue(now)?;
                if released.dropped {
                    return Some(released);
                }

                let size = released.packet.size();
                let time = rate.rate.release_time(&rate.list, now, size);
                rate.list.insert(released.packet, time, size);
            },
        }
    }

    /// Next release time (method 2): the earliest stage (0x91f94490), or the
    /// last stage holding frames (0x91f94680).
    pub(super) fn next_time(&self, now: u64) -> Option<ReleaseTime> {
        match self {
            Self::Unshaped(list) => list.next_time(now),
            Self::Link {
                rate,
                latency,
                loss,
            } => earliest(
                earliest(rate.list.next_time(now), latency.list.next_time(now)),
                loss.list.next_time(now),
            ),
            Self::TokenBucket { bucket, rate } => {
                if rate.list.is_empty() {
                    bucket.next_time(now)
                } else {
                    rate.list.next_time(now)
                }
            }
        }
    }

    /// Free every frame; removing a queue drops its frames.
    pub(super) fn free_all(&mut self) {
        match self {
            Self::Unshaped(list) => list.free_all(),
            Self::Link {
                rate,
                latency,
                loss,
            } => {
                rate.list.free_all();
                latency.list.free_all();
                loss.list.free_all();
            }
            Self::TokenBucket { bucket, rate } => {
                bucket.list.free_all();
                rate.list.free_all();
            }
        }
    }
}

/// The earlier of two release times.
#[inline]
pub(super) fn earliest(a: Option<ReleaseTime>, b: Option<ReleaseTime>) -> Option<ReleaseTime> {
    from_stored(to_stored(a).min(to_stored(b)))
}

/// Whether `time` comes before release time `bound`.
#[inline]
pub(super) fn is_before(time: ReleaseTime, bound: Option<ReleaseTime>) -> bool {
    time.ticks() < to_stored(bound)
}

/// Stored form of a release time: never is u64::MAX, which stock compares
/// as a time.
#[inline]
const fn to_stored(time: Option<ReleaseTime>) -> u64 {
    match time {
        Some(time) => time.ticks(),
        None => u64::MAX,
    }
}

#[inline]
const fn from_stored(stored: u64) -> Option<ReleaseTime> {
    ReleaseTime::at(stored)
}

/// `start + delta` clamped to the time range (0x91f93a60).
fn saturating_add(start: u64, delta: i64) -> u64 {
    start
        .checked_add_signed(delta)
        .unwrap_or(if delta < 0 { 0 } else { u64::MAX })
}

/// `end - start` clamped to the signed range (0x91f93aa0).
fn saturating_difference(start: u64, end: u64) -> i64 {
    if end >= start {
        i64::try_from(end - start).unwrap_or(i64::MAX)
    } else {
        i64::try_from(start - end).map_or(i64::MIN, |difference| -difference)
    }
}
