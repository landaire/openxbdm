//! Queue and redirect blobs: the `cfg=` values of the `netsim` lines.

use crate::commands::network::netsim::InvalidConfig;
use crate::commands::network::netsim::NetsimError;
use crate::commands::network::netsim::Program;
use crate::commands::network::netsim::Source;

/// Bytes a `cfg=` value decodes into.
pub const CONFIG_CAPACITY: usize = 0xdc;
/// Version byte the serializers write; parsers accept any `0x1?`.
pub(super) const BLOB_VERSION: u8 = 0x10;
/// Bytes of a redirect blob.
const REDIRECT_BLOB_SIZE: usize = 0xf;
/// Loss rates count per this many frames.
pub const LOSS_SCALE: u32 = 100_000;

/// Stage composition of a queue (blob type byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueueKind {
    /// Frames pass in arrival order; accepts no settings.
    Unshaped = 1,
    /// Link model: transmission rate with queue limits, then random latency,
    /// then random loss.
    Link = 2,
    /// Token bucket with queue limits, then transmission rate.
    TokenBucket = 3,
}

impl QueueKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Unshaped),
            2 => Some(Self::Link),
            3 => Some(Self::TokenBucket),
            _ => None,
        }
    }
}

xbox360_sys::flags! {
    /// Field mask of a queue blob.
    pub struct ConfigMask(u32) {
        /// Packet and byte limits.
        LIMITS = 0x1,
        /// Transmission rate in bits per second.
        RATE = 0x2,
        /// Token rate in bits per second.
        TOKEN_RATE = 0x4,
        /// Bucket depth in bytes.
        BUCKET = 0x8,
        /// Loss per [`LOSS_SCALE`] frames.
        LOSS = 0x10,
        /// Latency range in milliseconds.
        LATENCY = 0x20,
        /// Latency may reorder frames.
        REORDER = 0x40,
        /// Fill the bucket when the depth is set.
        START_FULL = 0x80,
        /// Empty the bucket when the depth is set.
        START_EMPTY = 0x100,
    }
}

impl ConfigMask {
    /// Fields of the settings struct.
    const FIELDS: Self = Self::LIMITS
        .union(Self::RATE)
        .union(Self::TOKEN_RATE)
        .union(Self::BUCKET)
        .union(Self::LOSS)
        .union(Self::LATENCY);
}

/// Queue settings as the blob and the library hold them (0x24-byte
/// struct). Fields are meaningful only when their mask bit is set; a rate
/// of 0xffffffff is unlimited, as is a packet limit of 0xffffffff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct QueueConfig {
    pub mask: ConfigMask,
    pub packet_limit: u32,
    pub byte_limit: u32,
    pub rate: u32,
    pub token_rate: u32,
    pub bucket_depth: u32,
    pub loss: u32,
    pub latency_min: u16,
    pub latency_max: u16,
}

impl QueueConfig {
    /// Validate a parsed blob (stock 0x91f8bc38). The result keeps the
    /// known bits only: `REORDER` survives with `LATENCY`, the bucket start
    /// bits with `BUCKET`.
    pub fn validate(&self) -> Result<Self, InvalidConfig> {
        let mask = self.mask;
        let mut out = QueueConfig::default();

        if mask.contains(ConfigMask::LIMITS) {
            out.mask.insert(ConfigMask::LIMITS);
            out.packet_limit = self.packet_limit;
            out.byte_limit = self.byte_limit;
        }

        if mask.contains(ConfigMask::RATE) {
            if self.rate == 0 {
                return Err(InvalidConfig);
            }
            out.mask.insert(ConfigMask::RATE);
            out.rate = self.rate;
        }

        if mask.contains(ConfigMask::TOKEN_RATE) {
            if self.token_rate == 0 {
                return Err(InvalidConfig);
            }
            out.mask.insert(ConfigMask::TOKEN_RATE);
            out.token_rate = self.token_rate;
        }

        let both = ConfigMask::START_FULL.union(ConfigMask::START_EMPTY);
        let start = mask & both;
        if mask.contains(ConfigMask::BUCKET) {
            out.mask.insert(ConfigMask::BUCKET);
            out.bucket_depth = self.bucket_depth;
            if start == both {
                return Err(InvalidConfig);
            }
            out.mask.insert(start);
        } else if !start.is_empty() {
            return Err(InvalidConfig);
        }

        if mask.contains(ConfigMask::LOSS) {
            if self.loss > LOSS_SCALE {
                return Err(InvalidConfig);
            }
            out.mask.insert(ConfigMask::LOSS);
            out.loss = self.loss;
        }

        if mask.contains(ConfigMask::LATENCY) {
            if self.latency_min > self.latency_max {
                return Err(InvalidConfig);
            }
            out.mask
                .insert(ConfigMask::LATENCY | (mask & ConfigMask::REORDER));
            out.latency_min = self.latency_min;
            out.latency_max = self.latency_max;
        }

        Ok(out)
    }

    /// Merge validated `update` into the stored settings of a `kind` queue
    /// (stock 0x91f8e800). Fields a kind has no stage for reject the whole
    /// update; an unshaped queue keeps an empty mask.
    pub fn merge(&mut self, kind: QueueKind, update: &QueueConfig) -> Result<(), InvalidConfig> {
        let mask = update.mask;
        let rejected = match kind {
            QueueKind::Unshaped => ConfigMask::FIELDS,
            QueueKind::Link => ConfigMask::TOKEN_RATE.union(ConfigMask::BUCKET),
            QueueKind::TokenBucket => ConfigMask::LOSS.union(ConfigMask::LATENCY),
        };
        if mask.intersects(rejected) {
            return Err(InvalidConfig);
        }

        if kind == QueueKind::Unshaped {
            return Ok(());
        }

        if mask.contains(ConfigMask::LIMITS) {
            self.packet_limit = update.packet_limit;
            self.byte_limit = update.byte_limit;
        }

        if mask.contains(ConfigMask::RATE) {
            self.rate = update.rate;
        }

        if mask.contains(ConfigMask::TOKEN_RATE) {
            self.token_rate = update.token_rate;
        }

        if mask.contains(ConfigMask::BUCKET) {
            let start = ConfigMask::START_FULL.union(ConfigMask::START_EMPTY);
            if !mask.intersects(start) {
                self.mask.remove(start);
            }
            self.bucket_depth = update.bucket_depth;
        }

        if mask.contains(ConfigMask::LOSS) {
            self.loss = update.loss;
        }

        if mask.contains(ConfigMask::LATENCY) {
            self.latency_min = update.latency_min;
            self.latency_max = update.latency_max;
        }

        self.mask.insert(mask);

        Ok(())
    }
}

/// An IPv4 redirect: frames to (transmit) or from (receive) the match
/// endpoint are rewritten to the target endpoint. A zero match address or
/// port matches any; a zero target address or port keeps the frame's.
/// `sessions` slots remember rewritten flows so that replies are rewritten
/// back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct RedirectConfig {
    pub match_address: [u8; 4],
    pub match_port: u16,
    pub target_address: [u8; 4],
    pub target_port: u16,
    pub sessions: u16,
}

impl RedirectConfig {
    /// Parse a redirect blob (stock 0x91f8c548): version byte, match address
    /// and port, target address and port, session count, big-endian. Returns
    /// the trailing bytes, a classifier program.
    pub fn parse(blob: &[u8]) -> Result<(Self, &[u8]), InvalidConfig> {
        if blob.len() < REDIRECT_BLOB_SIZE || blob[0] & 0xf0 != BLOB_VERSION {
            return Err(InvalidConfig);
        }

        let mut reader = Reader { bytes: &blob[1..] };
        let config = Self {
            match_address: reader.take::<4>()?,
            match_port: reader.word()?,
            target_address: reader.take::<4>()?,
            target_port: reader.word()?,
            sessions: reader.word()?,
        };

        Ok((config, reader.bytes))
    }

    /// 0x91f8bf98: a target needs an address or a port, and at most 500
    /// sessions.
    pub fn validate(&self) -> Result<(), InvalidConfig> {
        /// Largest session table of a redirect.
        const REDIRECT_SESSION_LIMIT: u16 = 500;

        if (self.target_address == [0; 4] && self.target_port == 0)
            || self.sessions > REDIRECT_SESSION_LIMIT
        {
            return Err(InvalidConfig);
        }

        Ok(())
    }

    /// Serialize as a blob (stock 0x91f8c418).
    pub fn serialize(&self) -> [u8; REDIRECT_BLOB_SIZE] {
        let mut blob = [0u8; REDIRECT_BLOB_SIZE];
        blob[0] = BLOB_VERSION;
        blob[1..5].copy_from_slice(&self.match_address);
        blob[5..7].copy_from_slice(&self.match_port.to_be_bytes());
        blob[7..11].copy_from_slice(&self.target_address);
        blob[11..13].copy_from_slice(&self.target_port.to_be_bytes());
        blob[13..15].copy_from_slice(&self.sessions.to_be_bytes());

        blob
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], InvalidConfig> {
        let (head, rest) = self.bytes.split_first_chunk::<N>().ok_or(InvalidConfig)?;
        self.bytes = rest;
        Ok(*head)
    }

    fn dword(&mut self) -> Result<u32, InvalidConfig> {
        self.take::<4>().map(u32::from_be_bytes)
    }

    fn word(&mut self) -> Result<u16, InvalidConfig> {
        self.take::<2>().map(u16::from_be_bytes)
    }
}

/// A queue blob (stock 0x91f8c260): version byte `0x1?`, the type byte when
/// `with_kind`, a big-endian field mask, then the masked fields in bit
/// order. Returns the trailing bytes, a classifier program.
pub fn parse_queue_blob(
    blob: &[u8],
    with_kind: bool,
) -> Result<(Option<QueueKind>, QueueConfig, &[u8]), InvalidConfig> {
    let mut reader = Reader { bytes: blob };
    let [version] = reader.take::<1>()?;
    if version & 0xf0 != BLOB_VERSION {
        return Err(InvalidConfig);
    }

    let kind = if with_kind {
        let [kind] = reader.take::<1>()?;
        Some(QueueKind::from_byte(kind).ok_or(InvalidConfig)?)
    } else {
        None
    };

    let mut config = QueueConfig {
        mask: ConfigMask::from_bits_retain(reader.dword()?),
        ..QueueConfig::default()
    };
    let mask = config.mask;
    if mask.contains(ConfigMask::LIMITS) {
        config.packet_limit = reader.dword()?;
        config.byte_limit = reader.dword()?;
    }

    if mask.contains(ConfigMask::RATE) {
        config.rate = reader.dword()?;
    }

    if mask.contains(ConfigMask::TOKEN_RATE) {
        config.token_rate = reader.dword()?;
    }

    if mask.contains(ConfigMask::BUCKET) {
        config.bucket_depth = reader.dword()?;
    }

    if mask.contains(ConfigMask::LOSS) {
        config.loss = reader.dword()?;
    }

    if mask.contains(ConfigMask::LATENCY) {
        config.latency_min = reader.word()?;
        config.latency_max = reader.word()?;
    }

    Ok((kind, config, reader.bytes))
}

/// Parse the classifier program after a blob (0x91f8bb08) into `slot`; no
/// bytes, no program.
pub fn parse_program<'p>(
    bytes: &[u8],
    slot: &'p mut Program,
) -> Result<Option<&'p Program>, NetsimError> {
    if bytes.is_empty() {
        return Ok(None);
    }

    Program::parse(bytes, slot)?;

    Ok(Some(slot))
}

/// An `insertq` blob in stock order: the settings, the classifier program,
/// then validation (0x91f8c260, 0x91f8bb08, 0x91f8bc38).
pub(super) fn parse_insert_blob<'p>(
    blob: &[u8],
    slot: &'p mut Program,
) -> Result<(QueueKind, QueueConfig, Option<&'p Program>), NetsimError> {
    let (kind, config, program) = parse_queue_blob(blob, true)?;
    let kind = kind.ok_or(InvalidConfig)?;
    let program = parse_program(program, slot)?;

    Ok((kind, config.validate()?, program))
}

/// Append a program after `length` blob bytes (0x91f847c0 within
/// 0x91f8c058 and 0x91f8c418): a program that does not fit is 0x82da0026,
/// one holding a string item 0x80070545.
pub(super) fn append_program(
    program: Option<Source<'_>>,
    blob: &mut [u8; CONFIG_CAPACITY],
    length: usize,
) -> Result<usize, NetsimError> {
    let Some(program) = program else {
        return Ok(length);
    };
    Ok(length + program.serialize(&mut blob[length..])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::network::netsim::api;

    fn link_blob() -> [u8; 30] {
        let mut blob = [0u8; 30];
        blob[..2].copy_from_slice(&[0x10, 2]);
        blob[2..6].copy_from_slice(&0x0000_0033u32.to_be_bytes());
        blob[6..10].copy_from_slice(&10u32.to_be_bytes());
        blob[10..14].copy_from_slice(&0x4000u32.to_be_bytes());
        blob[14..18].copy_from_slice(&1_000_000u32.to_be_bytes());
        blob[18..22].copy_from_slice(&500u32.to_be_bytes());
        blob[22..26].copy_from_slice(&[0, 20, 0, 40]);
        blob[26..30].copy_from_slice(&[0; 4]);
        blob
    }

    #[test]
    fn queue_blob_fields_follow_the_mask() {
        let blob = link_blob();
        let (kind, config, program) = parse_queue_blob(&blob[..26], true).unwrap();
        assert!(program.is_empty());
        assert_eq!(kind, Some(QueueKind::Link));
        assert_eq!(
            config,
            QueueConfig {
                mask: ConfigMask(0x33),
                packet_limit: 10,
                byte_limit: 0x4000,
                rate: 1_000_000,
                loss: 500,
                latency_min: 20,
                latency_max: 40,
                ..QueueConfig::default()
            }
        );
        assert_eq!(parse_queue_blob(&blob[..25], true), Err(InvalidConfig));
        assert_eq!(
            parse_queue_blob(&blob[..27], true).map(|(_, _, program)| program),
            Ok(&blob[26..27])
        );
    }

    #[test]
    fn queue_blob_header_checks() {
        let kind =
            |blob: &[u8], with_kind| parse_queue_blob(blob, with_kind).map(|(kind, _, _)| kind);
        assert_eq!(
            kind(&[0x1f, 1, 0, 0, 0, 0], true),
            Ok(Some(QueueKind::Unshaped))
        );
        assert_eq!(kind(&[0x20, 1, 0, 0, 0, 0], true), Err(InvalidConfig));
        assert_eq!(kind(&[0x10, 4, 0, 0, 0, 0], true), Err(InvalidConfig));
        assert_eq!(kind(&[0x10, 0, 0, 0, 0, 0], true), Err(InvalidConfig));
        assert_eq!(kind(&[0x10, 0, 0, 0, 0], false), Ok(None));
        assert_eq!(kind(&[0x10], false), Err(InvalidConfig));
    }

    #[test]
    fn validation_keeps_known_bits() {
        let config = |mask: u32| QueueConfig {
            mask: ConfigMask(mask),
            rate: 1,
            token_rate: 1,
            ..QueueConfig::default()
        };
        assert_eq!(
            config(0x40).validate().map(|value| value.mask),
            Ok(ConfigMask(0))
        );
        assert_eq!(
            config(0x60).validate().map(|value| value.mask),
            Ok(ConfigMask(0x60))
        );
        assert_eq!(
            config(0x8_0002).validate().map(|value| value.mask),
            Ok(ConfigMask(0x2))
        );
        assert_eq!(
            config(0x88).validate().map(|value| value.mask),
            Ok(ConfigMask(0x88))
        );
        assert_eq!(config(0x188).validate(), Err(InvalidConfig));
        assert_eq!(config(0x100).validate(), Err(InvalidConfig));
        assert_eq!(
            QueueConfig {
                mask: ConfigMask::RATE,
                ..QueueConfig::default()
            }
            .validate(),
            Err(InvalidConfig)
        );
        assert_eq!(
            QueueConfig {
                mask: ConfigMask::LOSS,
                loss: LOSS_SCALE + 1,
                ..QueueConfig::default()
            }
            .validate(),
            Err(InvalidConfig)
        );
        assert_eq!(
            QueueConfig {
                mask: ConfigMask::LATENCY,
                latency_min: 2,
                latency_max: 1,
                ..QueueConfig::default()
            }
            .validate(),
            Err(InvalidConfig)
        );
    }

    #[test]
    fn merge_rejects_fields_without_a_stage() {
        let update = |mask: u32| QueueConfig {
            mask: ConfigMask(mask),
            ..QueueConfig::default()
        };
        let mut stored = QueueConfig::default();
        assert_eq!(
            stored.merge(QueueKind::Unshaped, &update(0x1)),
            Err(InvalidConfig)
        );
        assert_eq!(stored.merge(QueueKind::Unshaped, &update(0)), Ok(()));
        assert_eq!(
            stored.merge(QueueKind::Link, &update(0x8)),
            Err(InvalidConfig)
        );
        assert_eq!(
            stored.merge(QueueKind::TokenBucket, &update(0x20)),
            Err(InvalidConfig)
        );
        assert_eq!(stored.merge(QueueKind::TokenBucket, &update(0x88)), Ok(()));
        assert_eq!(stored.mask, ConfigMask(0x88));
        assert_eq!(stored.merge(QueueKind::TokenBucket, &update(0x8)), Ok(()));
        assert_eq!(stored.mask, ConfigMask(0x8));
    }

    #[test]
    fn serialization_round_trips() {
        let blob = link_blob();
        let (kind, config, _) = parse_queue_blob(&blob[..26], true).unwrap();
        let mut output = [0u8; CONFIG_CAPACITY];
        let length = api::queue_blob(kind.unwrap() as u32, &config, None, &mut output).unwrap();
        assert_eq!(&output[..length], &blob[..26]);
    }

    #[test]
    fn redirect_blob() {
        let blob = [0x10, 10, 0, 0, 1, 0x0c, 0x38, 10, 0, 0, 2, 0, 0, 0, 4];
        let (redirect, program) = RedirectConfig::parse(&blob).unwrap();
        assert!(program.is_empty());
        assert_eq!(
            redirect,
            RedirectConfig {
                match_address: [10, 0, 0, 1],
                match_port: 3128,
                target_address: [10, 0, 0, 2],
                target_port: 0,
                sessions: 4
            }
        );
        assert_eq!(redirect.validate(), Ok(()));
        assert_eq!(redirect.serialize(), blob);
        let validate =
            |blob: &[u8]| RedirectConfig::parse(blob).and_then(|(redirect, _)| redirect.validate());
        let mut no_target = blob;
        no_target[7..13].fill(0);
        assert_eq!(validate(&no_target), Err(InvalidConfig));
        let mut too_many = blob;
        too_many[13..15].copy_from_slice(&501u16.to_be_bytes());
        assert_eq!(validate(&too_many), Err(InvalidConfig));
        assert_eq!(
            RedirectConfig::parse(&blob[..14]).map(|(redirect, _)| redirect),
            Err(InvalidConfig)
        );
    }
}
