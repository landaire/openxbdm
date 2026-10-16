//! Structures of the `netsim` exports: the 0x24-byte queue settings, the
//! 0x20-byte queue counters, and the blobs the exports build from them
//! before calling the command helpers.

use super::BLOB_VERSION;
use super::CONFIG_CAPACITY;
use super::ConfigMask;
use super::InvalidConfig;
use super::NetsimError;
use super::QueueConfig;
use super::QueueStats;
use super::RedirectConfig;
use super::Source;
use super::append_program;

/// Bytes of the queue settings structure; its first dword holds the size.
pub const SETTINGS_SIZE: usize = 0x24;
/// Bytes of the queue counters structure; its first dword holds the size.
pub const STATS_SIZE: usize = 0x20;

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// Whether a caller structure declares `size` in its first dword.
pub fn declares_size(bytes: &[u8], size: usize) -> bool {
    bytes.len() >= 4 && dword(bytes, 0) as usize == size
}

/// Validate caller settings (0x91f8bc38); none means an empty mask. The
/// structure is `{size, mask, packet limit, byte limit, rate, token rate,
/// bucket depth, loss, u16 latency min, u16 latency max}`, big-endian.
pub fn decode_settings(
    settings: Option<&[u8; SETTINGS_SIZE]>,
) -> Result<QueueConfig, InvalidConfig> {
    let Some(raw) = settings else {
        return Ok(QueueConfig::default());
    };
    if !declares_size(raw, SETTINGS_SIZE) {
        return Err(InvalidConfig);
    }
    QueueConfig {
        mask: ConfigMask(dword(raw, 4)),
        packet_limit: dword(raw, 8),
        byte_limit: dword(raw, 0xc),
        rate: dword(raw, 0x10),
        token_rate: dword(raw, 0x14),
        bucket_depth: dword(raw, 0x18),
        loss: dword(raw, 0x1c),
        latency_min: word(raw, 0x20),
        latency_max: word(raw, 0x22),
    }
    .validate()
}

/// A queue's stored settings as the getq export copies them (queue +0x14):
/// the library never sets the size dword, so it reads 0.
pub fn encode_settings(config: &QueueConfig) -> [u8; SETTINGS_SIZE] {
    let mut raw = [0u8; SETTINGS_SIZE];
    for (offset, value) in [
        (4, config.mask.0),
        (8, config.packet_limit),
        (0xc, config.byte_limit),
        (0x10, config.rate),
        (0x14, config.token_rate),
        (0x18, config.bucket_depth),
        (0x1c, config.loss),
    ] {
        raw[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    raw[0x20..0x22].copy_from_slice(&config.latency_min.to_be_bytes());
    raw[0x22..0x24].copy_from_slice(&config.latency_max.to_be_bytes());
    raw
}

/// Queue counters as the library copies them (queue +0x38): a reserved
/// zero qword over the size dword, total bytes, dropped bytes, then the
/// total and dropped packet counts.
pub fn encode_stats(stats: &QueueStats) -> [u8; STATS_SIZE] {
    let mut raw = [0u8; STATS_SIZE];
    raw[8..0x10].copy_from_slice(&stats.total_bytes.to_be_bytes());
    raw[0x10..0x18].copy_from_slice(&stats.dropped_bytes.to_be_bytes());
    raw[0x18..0x1c].copy_from_slice(&stats.total_packets.to_be_bytes());
    raw[0x1c..0x20].copy_from_slice(&stats.dropped_packets.to_be_bytes());
    raw
}

/// Serialize validated settings as a queue blob (0x91f8c058): the type
/// byte only when `kind` is nonzero (its low byte), then the mask, the
/// masked fields, and the program.
pub fn queue_blob(
    kind: u32,
    config: &QueueConfig,
    program: Option<Source<'_>>,
    blob: &mut [u8; CONFIG_CAPACITY],
) -> Result<usize, NetsimError> {
    let mut length = 0;
    let mut put = |bytes: &[u8]| {
        blob[length..length + bytes.len()].copy_from_slice(bytes);
        length += bytes.len();
    };
    put(&[BLOB_VERSION]);
    if kind != 0 {
        put(&[kind as u8]);
    }
    let mask = config.mask;
    put(&mask.0.to_be_bytes());
    if mask.contains(ConfigMask::LIMITS) {
        put(&config.packet_limit.to_be_bytes());
        put(&config.byte_limit.to_be_bytes());
    }
    if mask.contains(ConfigMask::RATE) {
        put(&config.rate.to_be_bytes());
    }
    if mask.contains(ConfigMask::TOKEN_RATE) {
        put(&config.token_rate.to_be_bytes());
    }
    if mask.contains(ConfigMask::BUCKET) {
        put(&config.bucket_depth.to_be_bytes());
    }
    if mask.contains(ConfigMask::LOSS) {
        put(&config.loss.to_be_bytes());
    }
    if mask.contains(ConfigMask::LATENCY) {
        put(&config.latency_min.to_be_bytes());
        put(&config.latency_max.to_be_bytes());
    }
    append_program(program, blob, length)
}

/// Serialize a redirect blob with its program (0x91f8c418).
pub fn redirect_blob(
    config: &RedirectConfig,
    program: Option<Source<'_>>,
    blob: &mut [u8; CONFIG_CAPACITY],
) -> Result<usize, NetsimError> {
    let fixed = config.serialize();
    blob[..fixed.len()].copy_from_slice(&fixed);
    append_program(program, blob, fixed.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::network::netsim::QueueKind;
    use crate::commands::network::netsim::parse_queue_blob;

    fn settings(mask: u32, fields: [u32; 6], latency: (u16, u16)) -> [u8; SETTINGS_SIZE] {
        let mut raw = [0u8; SETTINGS_SIZE];
        raw[..4].copy_from_slice(&(SETTINGS_SIZE as u32).to_be_bytes());
        raw[4..8].copy_from_slice(&mask.to_be_bytes());
        for (index, value) in fields.iter().enumerate() {
            raw[8 + 4 * index..12 + 4 * index].copy_from_slice(&value.to_be_bytes());
        }
        raw[0x20..0x22].copy_from_slice(&latency.0.to_be_bytes());
        raw[0x22..0x24].copy_from_slice(&latency.1.to_be_bytes());
        raw
    }

    #[test]
    fn settings_require_the_size_and_valid_fields() {
        assert_eq!(decode_settings(None), Ok(QueueConfig::default()));
        let mut wrong_size = settings(0, [0; 6], (0, 0));
        wrong_size[3] = 0x20;
        assert_eq!(decode_settings(Some(&wrong_size)), Err(InvalidConfig));
        assert_eq!(
            decode_settings(Some(&settings(0x2, [0; 6], (0, 0)))),
            Err(InvalidConfig)
        );
        assert_eq!(
            decode_settings(Some(&settings(0x10, [0, 0, 0, 0, 0, 100_001], (0, 0)))),
            Err(InvalidConfig)
        );
        assert_eq!(
            decode_settings(Some(&settings(0x20, [0; 6], (5, 4)))),
            Err(InvalidConfig)
        );
        assert_eq!(
            decode_settings(Some(&settings(0x80, [0; 6], (0, 0)))),
            Err(InvalidConfig)
        );
        // Unknown bits are dropped; reorder survives with latency.
        let config = decode_settings(Some(&settings(
            0x1_0063,
            [10, 0x4000, 1_000_000, 0, 0, 0],
            (20, 40),
        )))
        .unwrap();
        assert_eq!(config.mask, ConfigMask(0x63));
        assert_eq!(
            (config.packet_limit, config.byte_limit, config.rate),
            (10, 0x4000, 1_000_000)
        );
        assert_eq!((config.latency_min, config.latency_max), (20, 40));
    }

    #[test]
    fn queue_blob_matches_the_command_blob() {
        let config = decode_settings(Some(&settings(
            0x23,
            [10, 0x4000, 1_000_000, 0, 0, 0],
            (20, 40),
        )))
        .unwrap();
        let mut blob = [0u8; CONFIG_CAPACITY];
        let length = queue_blob(2, &config, None, &mut blob).unwrap();
        let expected = [
            0x10, 0x02, 0, 0, 0, 0x23, 0, 0, 0, 10, 0, 0, 0x40, 0, 0, 0x0f, 0x42, 0x40, 0, 0x14, 0,
            0x28,
        ];
        assert_eq!(blob[..length], expected);
        assert_eq!(
            parse_queue_blob(&blob[..length], true),
            Ok((Some(QueueKind::Link), config, &[][..]))
        );
        // Without a type the blob parses as a modifyq blob.
        let length = queue_blob(0, &config, None, &mut blob).unwrap();
        assert_eq!(
            parse_queue_blob(&blob[..length], false),
            Ok((None, config, &[][..]))
        );
    }

    #[test]
    fn counters_and_stored_settings_layouts() {
        let stats = QueueStats {
            total_packets: 5,
            total_bytes: 0x1_0000_0002,
            dropped_packets: 1,
            dropped_bytes: 0x40,
        };
        let raw = encode_stats(&stats);
        assert_eq!(raw[..8], [0; 8]);
        assert_eq!(raw[8..0x10], 0x1_0000_0002u64.to_be_bytes());
        assert_eq!(raw[0x10..0x18], 0x40u64.to_be_bytes());
        assert_eq!(raw[0x18..], [0, 0, 0, 5, 0, 0, 0, 1]);

        let config = decode_settings(Some(&settings(0x21, [1, 2, 0, 0, 0, 0], (3, 4)))).unwrap();
        let raw = encode_settings(&config);
        assert_eq!(raw[..4], [0; 4]);
        let mut round = raw;
        round[..4].copy_from_slice(&(SETTINGS_SIZE as u32).to_be_bytes());
        assert_eq!(decode_settings(Some(&round)), Ok(config));
    }
}
