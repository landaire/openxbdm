//! `netsim` (stock 0x91f37418): the Ethernet-level network simulator. Frames
//! pass through ordered inbound and outbound queues that delay, limit, or
//! drop them, and IPv4 redirects rewrite their addresses. The configuration
//! is kept in a file of `netsim` lines that `reload` executes.

pub mod api;
pub mod classifier;

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

pub use self::classifier::Program;
use self::classifier::ProgramError;
use self::classifier::SerializeError;
pub use self::classifier::Source;
use super::SystemVersion;
use super::decode_hex;
use crate::backend::Backend as AnyBackend;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::commands::filesystem::CreateDisposition;
use crate::commands::filesystem::CreateOptions;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileAccess;
use crate::commands::filesystem::FileAttributes;
use crate::commands::filesystem::FileData;
use crate::commands::filesystem::FileHandle;
use crate::commands::filesystem::PoolBuffer;
use crate::commands::filesystem::PoolRange;
use crate::commands::filesystem::ShareAccess;
use crate::invocation::Invocation;
use crate::text::ResponseText;

/// First system version with the simulator.
const NETSIM_VERSION: SystemVersion = SystemVersion(0x2027_8700);
/// Bytes a `cfg=` value decodes into.
pub const CONFIG_CAPACITY: usize = 0xdc;
/// Characters of the stored file name (0x91f9fc88 holds 0x104 bytes).
const PATH_LIMIT: usize = 0x103;
/// Capacity of the `file=` copy, terminator included.
const FILE_PARAMETER_CAPACITY: usize = 0x104;
/// Pool buffer of the file reader and writer.
const FILE_BUFFER_SIZE: usize = 0x4000;
const LINE_END: &[u8] = b"\r\n";
/// Version byte the serializers write; parsers accept any `0x1?`.
const BLOB_VERSION: u8 = 0x10;
/// Bytes of a redirect blob.
const REDIRECT_BLOB_SIZE: usize = 0xf;
/// Largest session table of a redirect.
const REDIRECT_SESSION_LIMIT: u16 = 500;
/// Loss rates count per this many frames.
pub const LOSS_SCALE: u32 = 100_000;

/// Result codes of the simulator library and its handler helpers.
pub mod status {
    use openxbdm_core::status::Hresult;

    /// Success of every helper.
    pub const OK: Hresult = Hresult::OK;
    /// Results outside facility 0x2da are reported with this status.
    pub const GENERIC: Hresult = Hresult::error(0);
    pub const NO_INSTANCE: Hresult = Hresult::error(0x2);
    /// The instance already exists (0x91f365e8).
    pub const INSTANCE_EXISTS: Hresult = Hresult::error(0x8);
    /// No file name is stored or given.
    pub const NO_FILE: Hresult = Hresult::error(0xc);
    /// The Ethernet intercept is owned by another client (`WSAEALREADY`).
    pub const INTERCEPT_BUSY: Hresult = Hresult::error(0x10);
    /// Malformed or rejected blob, or an index past the end.
    pub const INVALID: Hresult = Hresult::error(0x17);
    /// The instance changed while it was being destroyed.
    pub const INSTANCE_CHANGED: Hresult = Hresult::error(0x1a);
    pub const OUT_OF_MEMORY: Hresult = Hresult::error(0x1c);
    /// A serialized blob does not fit its buffer.
    pub const SHORT_BUFFER: Hresult = Hresult::error(0x26);
    /// A reload is already running.
    pub const BUSY: Hresult = Hresult::error(0x150);
}

/// `WSAEALREADY` from `XnpEthernetInterceptSetCallbacks`.
pub const WSAEALREADY: u32 = 0x2735;

/// Global state of `netsim`.
#[derive(Debug)]
pub struct State {
    /// File the configuration is written to and reloaded from.
    pub file: FilePath,
    /// A reload is running (0x91f9f69c).
    pub reloading: bool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            file: FilePath::EMPTY,
            reloading: false,
        }
    }
}

/// Stored configuration file name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FilePath {
    bytes: [u8; PATH_LIMIT],
    len: usize,
}

impl FilePath {
    const EMPTY: Self = Self {
        bytes: [0; PATH_LIMIT],
        len: 0,
    };

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn set(&mut self, name: &[u8]) {
        let count = name.len().min(PATH_LIMIT);
        self.bytes[..count].copy_from_slice(&name[..count]);
        self.len = count;
    }
}

impl core::fmt::Debug for FilePath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(core::str::from_utf8(self.as_bytes()).unwrap_or("<binary>"))
    }
}

/// Direction of a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Received frames (stock direction 1, flag `in`).
    Inbound,
    /// Transmitted frames (stock direction 0, flag `out`).
    Outbound,
}

/// Position of a queue in its direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueueIndex(pub u32);

/// Position of a redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedirectIndex(pub u32);

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

/// Field mask of a queue blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ConfigMask(pub u32);

impl ConfigMask {
    /// Packet and byte limits.
    pub const LIMITS: Self = Self(0x1);
    /// Transmission rate in bits per second.
    pub const RATE: Self = Self(0x2);
    /// Token rate in bits per second.
    pub const TOKEN_RATE: Self = Self(0x4);
    /// Bucket depth in bytes.
    pub const BUCKET: Self = Self(0x8);
    /// Loss per [`LOSS_SCALE`] frames.
    pub const LOSS: Self = Self(0x10);
    /// Latency range in milliseconds.
    pub const LATENCY: Self = Self(0x20);
    /// Latency may reorder frames.
    pub const REORDER: Self = Self(0x40);
    /// Fill the bucket when the depth is set.
    pub const START_FULL: Self = Self(0x80);
    /// Empty the bucket when the depth is set.
    pub const START_EMPTY: Self = Self(0x100);
    /// Fields of the settings struct.
    const FIELDS: Self = Self(0x3f);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
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

/// A rejected blob (0x82da0017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidConfig;

impl From<InvalidConfig> for Hresult {
    fn from(_: InvalidConfig) -> Self {
        status::INVALID
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
        mask: ConfigMask(reader.dword()?),
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
) -> Result<Option<&'p Program>, Hresult> {
    if bytes.is_empty() {
        return Ok(None);
    }
    match Program::parse(bytes, slot) {
        Ok(()) => Ok(Some(slot)),
        Err(ProgramError::Invalid) => Err(status::INVALID),
        Err(ProgramError::OutOfMemory) => Err(status::OUT_OF_MEMORY),
    }
}

/// An `insertq` blob in stock order: the settings, the classifier program,
/// then validation (0x91f8c260, 0x91f8bb08, 0x91f8bc38).
fn parse_insert_blob<'p>(
    blob: &[u8],
    slot: &'p mut Program,
) -> Result<(QueueKind, QueueConfig, Option<&'p Program>), Hresult> {
    let (kind, config, program) = parse_queue_blob(blob, true)?;
    let kind = kind.ok_or(InvalidConfig)?;
    let program = parse_program(program, slot)?;
    Ok((kind, config.validate()?, program))
}

/// Append a program after `length` blob bytes (0x91f847c0 within
/// 0x91f8c058 and 0x91f8c418): a program that does not fit is 0x82da0026,
/// one holding a string item 0x80070545.
fn append_program(
    program: Option<Source<'_>>,
    blob: &mut [u8; CONFIG_CAPACITY],
    length: usize,
) -> Result<usize, Hresult> {
    let Some(program) = program else {
        return Ok(length);
    };
    match program.serialize(&mut blob[length..]) {
        Ok(written) => Ok(length + written),
        Err(SerializeError::TooLarge) => Err(status::SHORT_BUFFER),
        Err(SerializeError::Unencodable) => Err(UNENCODABLE),
    }
}

/// The item value encoder's refusal of strings.
const UNENCODABLE: Hresult = Hresult(0x8007_0545);

impl QueueSnapshot {
    /// The `cfg=` blob of `getq` and the settings file.
    pub fn serialize(&self, blob: &mut [u8; CONFIG_CAPACITY]) -> Result<usize, Hresult> {
        api::queue_blob(
            self.kind as u32,
            &self.config,
            self.program.as_ref().map(Source::Parsed),
            blob,
        )
    }
}

impl RedirectSnapshot {
    /// The `cfg=` blob of the settings file.
    pub fn serialize(&self, blob: &mut [u8; CONFIG_CAPACITY]) -> Result<usize, Hresult> {
        api::redirect_blob(
            &self.config,
            self.program.as_ref().map(Source::Parsed),
            blob,
        )
    }
}

impl QueueConfig {
    /// Validate a parsed blob (stock 0x91f8bc38). The result keeps the
    /// known bits only: `REORDER` survives with `LATENCY`, the bucket start
    /// bits with `BUCKET`.
    pub fn validate(&self) -> Result<Self, InvalidConfig> {
        let mask = self.mask;
        let mut out = QueueConfig::default();
        if mask.contains(ConfigMask::LIMITS) {
            out.mask.0 |= ConfigMask::LIMITS.0;
            out.packet_limit = self.packet_limit;
            out.byte_limit = self.byte_limit;
        }
        if mask.contains(ConfigMask::RATE) {
            if self.rate == 0 {
                return Err(InvalidConfig);
            }
            out.mask.0 |= ConfigMask::RATE.0;
            out.rate = self.rate;
        }
        if mask.contains(ConfigMask::TOKEN_RATE) {
            if self.token_rate == 0 {
                return Err(InvalidConfig);
            }
            out.mask.0 |= ConfigMask::TOKEN_RATE.0;
            out.token_rate = self.token_rate;
        }
        let start = mask.0 & (ConfigMask::START_FULL.0 | ConfigMask::START_EMPTY.0);
        if mask.contains(ConfigMask::BUCKET) {
            out.mask.0 |= ConfigMask::BUCKET.0;
            out.bucket_depth = self.bucket_depth;
            if start == ConfigMask::START_FULL.0 | ConfigMask::START_EMPTY.0 {
                return Err(InvalidConfig);
            }
            out.mask.0 |= start;
        } else if start != 0 {
            return Err(InvalidConfig);
        }
        if mask.contains(ConfigMask::LOSS) {
            if self.loss > LOSS_SCALE {
                return Err(InvalidConfig);
            }
            out.mask.0 |= ConfigMask::LOSS.0;
            out.loss = self.loss;
        }
        if mask.contains(ConfigMask::LATENCY) {
            if self.latency_min > self.latency_max {
                return Err(InvalidConfig);
            }
            out.mask.0 |= ConfigMask::LATENCY.0 | (mask.0 & ConfigMask::REORDER.0);
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
            QueueKind::Link => ConfigMask(ConfigMask::TOKEN_RATE.0 | ConfigMask::BUCKET.0),
            QueueKind::TokenBucket => ConfigMask(ConfigMask::LOSS.0 | ConfigMask::LATENCY.0),
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
            if !mask.intersects(ConfigMask(
                ConfigMask::START_FULL.0 | ConfigMask::START_EMPTY.0,
            )) {
                self.mask.0 &= !(ConfigMask::START_FULL.0 | ConfigMask::START_EMPTY.0);
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
        self.mask.0 |= mask.0;
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

/// Counters of a queue (queue +0x40..+0x57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueStats {
    pub total_packets: u32,
    pub total_bytes: u64,
    pub dropped_packets: u32,
    pub dropped_bytes: u64,
}

/// A queue's type, stored settings, and classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub kind: QueueKind,
    pub config: QueueConfig,
    pub program: Option<Program>,
}

/// A redirect with its classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectSnapshot {
    pub config: RedirectConfig,
    pub program: Option<Program>,
}

/// `XeKeysGetStatus` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStatus(pub u32);

impl KeyStatus {
    /// Settings-file `netsim reload` lines are skipped while this status
    /// bit is set (DoIniLine 0x91f311b8); its meaning is not identified.
    pub const SKIP_SETTINGS_RELOAD: u32 = 0x8;
}

/// Platform services `netsim` needs: the simulator library. Every queue and
/// redirect operation is called only while the instance exists.
pub trait Backend {
    /// Whether the instance exists (0x91f9fc84).
    fn simulator_exists(&mut self) -> bool;
    /// Create the instance and attach it to the Ethernet intercept
    /// (0x91f365e8).
    fn create_simulator(&mut self) -> Result<(), Hresult>;
    /// Detach and free the instance, restoring a running capture's own
    /// intercept (0x91f36750).
    fn destroy_simulator(&mut self) -> Result<(), Hresult>;
    fn queue_count(&mut self, direction: Direction) -> u32;
    fn redirect_count(&mut self) -> u32;
    /// Create a queue from validated settings and insert it before
    /// `position`, or append it (0x91f8ea98).
    fn insert_queue(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, Hresult>;
    /// Apply validated settings to a queue (0x91f8ec80).
    fn modify_queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), Hresult>;
    /// Remove the queue at `position`, or every queue (0x91f8e0e8); returns
    /// the number removed.
    fn remove_queues(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, Hresult>;
    fn queue_stats(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, Hresult>;
    fn queue(&mut self, direction: Direction, index: QueueIndex) -> Result<QueueSnapshot, Hresult>;
    /// Insert a redirect before `position`, or append it (0x91f8d7c0).
    fn insert_redirect(
        &mut self,
        position: Option<RedirectIndex>,
        redirect: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, Hresult>;
    /// Remove the redirect at `position`, or every redirect (0x91f8d960).
    fn remove_redirects(&mut self, position: Option<RedirectIndex>) -> Result<u32, Hresult>;
    fn redirect(&mut self, index: RedirectIndex) -> Option<RedirectSnapshot>;
    fn key_status(&mut self) -> KeyStatus;
}

/// Facility 0x2da results keep their status; others are reported as
/// 0x82da0000 (the common exit of the stock helpers).
pub fn reported(result: Hresult) -> Hresult {
    if result.0 & 0x1fff_0000 == status::OK.0 & 0x1fff_0000 {
        result
    } else {
        status::GENERIC
    }
}

fn fail(invocation: &mut Invocation<'_>, result: Hresult) -> Hresult {
    invocation.set_text(format_args!("err=0x{:08x}", result.0));
    reported(result)
}

/// Parameters shared by the queue and redirect subcommands.
struct Selection {
    inbound: bool,
    outbound: bool,
    index: Option<u32>,
}

impl Selection {
    /// The single direction `in` or `out` names.
    fn direction(&self) -> Option<Direction> {
        match (self.inbound, self.outbound) {
            (true, false) => Some(Direction::Inbound),
            (false, true) => Some(Direction::Outbound),
            _ => None,
        }
    }
}

/// Subcommands that take a [`Selection`] and an optional `cfg=` blob.
#[derive(Clone, Copy)]
enum Edit {
    InsertQueue,
    RemoveQueues,
    ModifyQueue,
    QueueStats,
    Queue,
    InsertRedirect,
    RemoveRedirects,
}

/// A parsed `netsim` line. Execution does not read the line, so settings
/// file lines run from the reader's pool buffer without a copy.
enum Request {
    Reload {
        file: [u8; FILE_PARAMETER_CAPACITY],
        length: usize,
    },
    QueueCounts,
    RedirectCount,
    Edit {
        edit: Option<Edit>,
        selection: Selection,
        blob: [u8; CONFIG_CAPACITY],
        blob_length: usize,
    },
}

impl Request {
    /// A bad `cfg=` digit is an unknown command.
    fn parse(line: CommandLine<'_>) -> Result<Self, Hresult> {
        if line.has("reload") {
            let mut file = [0u8; FILE_PARAMETER_CAPACITY];
            let length = match line.param("file") {
                Some(value) => value.copy_into(&mut file).len(),
                None => 0,
            };
            return Ok(Self::Reload { file, length });
        }
        if line.has("getnumqs") {
            return Ok(Self::QueueCounts);
        }
        if line.has("getnumipv4redirs") {
            return Ok(Self::RedirectCount);
        }
        let selection = Selection {
            inbound: line.has("in"),
            outbound: line.has("out"),
            index: line
                .param("index")
                .and_then(|value| value.dword())
                .filter(|&index| index != u32::MAX),
        };
        let mut blob = [0u8; CONFIG_CAPACITY];
        let blob_length = match line.param("cfg") {
            Some(value) => {
                let raw = value.raw();
                let text = raw.strip_prefix(b"\"").unwrap_or(raw);
                decode_hex(text, &mut blob)
                    .ok_or(Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND))?
            }
            None => 0,
        };
        const EDITS: [(&str, Edit); 7] = [
            ("insertq", Edit::InsertQueue),
            ("removeq", Edit::RemoveQueues),
            ("modifyq", Edit::ModifyQueue),
            ("getqstats", Edit::QueueStats),
            ("getq", Edit::Queue),
            ("insertipv4redir", Edit::InsertRedirect),
            ("removeipv4redir", Edit::RemoveRedirects),
        ];
        let edit = EDITS
            .iter()
            .find(|(name, _)| line.has(name))
            .map(|&(_, edit)| edit);
        Ok(Self::Edit {
            edit,
            selection,
            blob,
            blob_length,
        })
    }
}

/// `netsim reload [file=<name>] | getnumqs | getnumipv4redirs |
/// insertq in|out [index=<n>] cfg=<hex> | removeq [in] [out] [index=<n>] |
/// modifyq in|out index=<n> cfg=<hex> | getqstats in|out index=<n> |
/// getq in|out index=<n> | insertipv4redir [index=<n>] cfg=<hex> |
/// removeipv4redir [index=<n>]`.
pub(super) fn netsim(invocation: &mut Invocation<'_>) -> Hresult {
    let request = Request::parse(invocation.line);
    execute(invocation, request)
}

#[inline(never)]
fn execute(invocation: &mut Invocation<'_>, request: Result<Request, Hresult>) -> Hresult {
    if super::Backend::system_version(invocation.backend) < NETSIM_VERSION {
        return Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND);
    }
    let (edit, selection, blob, blob_length) = match request {
        Err(error) => return error,
        Ok(Request::Reload { file, length }) => return reload(invocation, &file[..length]),
        Ok(Request::QueueCounts) => return queue_counts_command(invocation),
        Ok(Request::RedirectCount) => {
            let count = redirect_count(invocation.backend);
            invocation.set_text(format_args!("num={count}"));
            return status::OK;
        }
        Ok(Request::Edit {
            edit,
            selection,
            blob,
            blob_length,
        }) => (edit, selection, blob, blob_length),
    };
    // An empty `cfg=` counts as missing.
    let blob = (blob_length != 0).then_some(&blob[..blob_length]);
    let persist = invocation.session.is_some();
    let Some(edit) = edit else {
        return status::INVALID;
    };
    match edit {
        Edit::InsertQueue => {
            let (Some(direction), Some(blob)) = (selection.direction(), blob) else {
                return status::INVALID;
            };
            insert_queue_command(
                invocation,
                direction,
                selection.index.map(QueueIndex),
                blob,
                persist,
            )
        }
        Edit::RemoveQueues => {
            let (inbound, outbound) = match selection.index {
                None if !selection.inbound && !selection.outbound => (true, true),
                None => (selection.inbound, selection.outbound),
                Some(_) if selection.direction().is_none() => return status::INVALID,
                Some(_) => (selection.inbound, selection.outbound),
            };
            remove_queues_command(
                invocation,
                inbound,
                outbound,
                selection.index.map(QueueIndex),
                persist,
            )
        }
        Edit::ModifyQueue => {
            let (Some(direction), Some(index), Some(blob)) =
                (selection.direction(), selection.index, blob)
            else {
                return status::INVALID;
            };
            modify_queue_command(invocation, direction, QueueIndex(index), blob, persist)
        }
        Edit::QueueStats | Edit::Queue => {
            let (Some(direction), Some(index)) = (selection.direction(), selection.index) else {
                return status::INVALID;
            };
            if matches!(edit, Edit::QueueStats) {
                queue_stats_command(invocation, direction, QueueIndex(index))
            } else {
                queue_config(invocation, direction, QueueIndex(index))
            }
        }
        Edit::InsertRedirect => {
            let Some(blob) = blob else {
                return status::INVALID;
            };
            insert_redirect_command(
                invocation,
                selection.index.map(RedirectIndex),
                blob,
                persist,
            )
        }
        Edit::RemoveRedirects => {
            remove_redirects_command(invocation, selection.index.map(RedirectIndex), persist)
        }
    }
}

/// Settings-file `netsim` line (DoIniLine 0x91f311b8).
pub(crate) fn ini_netsim(invocation: &mut Invocation<'_>) {
    let KeyStatus(key_status) = invocation.backend.key_status();
    if key_status & KeyStatus::SKIP_SETTINGS_RELOAD != 0 && invocation.line.has("reload") {
        return;
    }
    let _ = netsim(invocation);
}

/// Queue counts per direction; zero without an instance (0x91f37028).
pub fn queue_counts(backend: &mut dyn AnyBackend) -> (u32, u32) {
    if backend.simulator_exists() {
        (
            backend.queue_count(Direction::Inbound),
            backend.queue_count(Direction::Outbound),
        )
    } else {
        (0, 0)
    }
}

/// Redirect count; zero without an instance.
pub fn redirect_count(backend: &mut dyn AnyBackend) -> u32 {
    if backend.simulator_exists() {
        backend.redirect_count()
    } else {
        0
    }
}

fn queue_counts_command(invocation: &mut Invocation<'_>) -> Hresult {
    let (inbound, outbound) = queue_counts(invocation.backend);
    invocation.set_text(format_args!("in={inbound} out={outbound}"));
    status::OK
}

/// Create the instance when it is missing; returns whether it was created.
fn ensure_simulator(backend: &mut dyn AnyBackend) -> Result<bool, Hresult> {
    if backend.simulator_exists() {
        return Ok(false);
    }
    backend.create_simulator().map(|()| true)
}

/// Destroy the instance once it has no queues and no redirects.
fn release_if_idle(backend: &mut dyn AnyBackend) -> Result<(), Hresult> {
    let idle = backend.queue_count(Direction::Inbound) == 0
        && backend.queue_count(Direction::Outbound) == 0
        && backend.redirect_count() == 0;
    if idle {
        backend.destroy_simulator()
    } else {
        Ok(())
    }
}

fn persist_file(state: &State, backend: &mut dyn AnyBackend, persist: bool) {
    if persist {
        write_file(state.file.as_bytes(), backend);
    }
}

/// Insert a queue from an `insertq` blob, creating the instance on demand
/// (0x91f36a18); `persist` rewrites the configuration file.
pub fn insert_queue(
    state: &State,
    backend: &mut dyn AnyBackend,
    direction: Direction,
    position: Option<QueueIndex>,
    blob: &[u8],
    persist: bool,
) -> Result<QueueIndex, Hresult> {
    let created = ensure_simulator(backend)?;
    let mut slot = Program::EMPTY;
    let inserted = parse_insert_blob(blob, &mut slot).and_then(|(kind, update, program)| {
        backend.insert_queue(direction, position, kind, &update, program)
    });
    match inserted {
        Ok(index) => {
            persist_file(state, backend, persist);
            Ok(index)
        }
        Err(error) => {
            if created {
                let _ = backend.destroy_simulator();
            }
            Err(error)
        }
    }
}

fn insert_queue_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    position: Option<QueueIndex>,
    blob: &[u8],
    persist: bool,
) -> Hresult {
    match insert_queue(
        &invocation.state.network.netsim,
        invocation.backend,
        direction,
        position,
        blob,
        persist,
    ) {
        Ok(QueueIndex(index)) => {
            invocation.set_text(format_args!("index={index}"));
            status::OK
        }
        Err(error) => fail(invocation, error),
    }
}

/// Queues removed and left by [`remove_queues`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueRemoval {
    pub removed: u32,
    pub inbound_left: u32,
    pub outbound_left: u32,
}

/// Remove the queue at `position`, or every queue, of the selected
/// directions and release an idle instance (0x91f36b50).
pub fn remove_queues(
    state: &State,
    backend: &mut dyn AnyBackend,
    inbound: bool,
    outbound: bool,
    position: Option<QueueIndex>,
    persist: bool,
) -> Result<QueueRemoval, Hresult> {
    if !backend.simulator_exists() {
        if position.is_some() {
            return Err(status::NO_INSTANCE);
        }
        return Ok(QueueRemoval {
            removed: 0,
            inbound_left: 0,
            outbound_left: 0,
        });
    }
    let mut removed = 0u32;
    for (selected, direction) in [
        (inbound, Direction::Inbound),
        (outbound, Direction::Outbound),
    ] {
        if selected {
            removed = removed.wrapping_add(backend.remove_queues(direction, position)?);
        }
    }
    let inbound_left = backend.queue_count(Direction::Inbound);
    let outbound_left = backend.queue_count(Direction::Outbound);
    release_if_idle(backend)?;
    persist_file(state, backend, persist);
    Ok(QueueRemoval {
        removed,
        inbound_left,
        outbound_left,
    })
}

fn remove_queues_command(
    invocation: &mut Invocation<'_>,
    inbound: bool,
    outbound: bool,
    position: Option<QueueIndex>,
    persist: bool,
) -> Hresult {
    match remove_queues(
        &invocation.state.network.netsim,
        invocation.backend,
        inbound,
        outbound,
        position,
        persist,
    ) {
        Ok(QueueRemoval {
            removed,
            inbound_left,
            outbound_left,
        }) => {
            invocation.set_text(format_args!(
                "removed={removed} inleft={inbound_left} outleft={outbound_left}"
            ));
            status::OK
        }
        Err(error) => fail(invocation, error),
    }
}

/// Apply a `modifyq` blob (no type byte) to a queue (0x91f36cf0).
pub fn modify_queue(
    state: &State,
    backend: &mut dyn AnyBackend,
    direction: Direction,
    index: QueueIndex,
    blob: &[u8],
    persist: bool,
) -> Result<(), Hresult> {
    if !backend.simulator_exists() {
        return Err(status::NO_INSTANCE);
    }
    let update = parse_queue_blob(blob, false).and_then(|(_, config, program)| {
        if program.is_empty() {
            config.validate()
        } else {
            Err(InvalidConfig)
        }
    })?;
    backend.modify_queue(direction, index, &update)?;
    persist_file(state, backend, persist);
    Ok(())
}

fn modify_queue_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
    blob: &[u8],
    persist: bool,
) -> Hresult {
    match modify_queue(
        &invocation.state.network.netsim,
        invocation.backend,
        direction,
        index,
        blob,
        persist,
    ) {
        Ok(()) => status::OK,
        Err(error) => fail(invocation, error),
    }
}

/// Counters of a queue (0x91f36da8).
pub fn queue_stats(
    backend: &mut dyn AnyBackend,
    direction: Direction,
    index: QueueIndex,
) -> Result<QueueStats, Hresult> {
    if !backend.simulator_exists() {
        return Err(status::NO_INSTANCE);
    }
    backend.queue_stats(direction, index)
}

fn queue_stats_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
) -> Hresult {
    match queue_stats(invocation.backend, direction, index) {
        Ok(stats) => {
            invocation.set_text(format_args!(
                "totalpkts={} totalbytes=0q{:08x}{:08x} droppkts={} dropbytes=0q{:08x}{:08x}",
                stats.total_packets,
                (stats.total_bytes >> 32) as u32,
                stats.total_bytes as u32,
                stats.dropped_packets,
                (stats.dropped_bytes >> 32) as u32,
                stats.dropped_bytes as u32,
            ));
            status::OK
        }
        Err(error) => fail(invocation, error),
    }
}

/// 0x91f36ef0.
fn queue_config(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
) -> Hresult {
    let result = if invocation.backend.simulator_exists() {
        invocation.backend.queue(direction, index)
    } else {
        Err(status::NO_INSTANCE)
    };
    match result {
        Ok(snapshot) => {
            let mut blob = [0u8; CONFIG_CAPACITY];
            match snapshot.serialize(&mut blob) {
                Ok(length) => {
                    invocation.text.clear();
                    let _ = invocation.text.write_str("cfg=");
                    write_hex(invocation.text, &blob[..length]);
                    status::OK
                }
                Err(error) => fail(invocation, error),
            }
        }
        Err(error) => fail(invocation, error),
    }
}

/// Insert a redirect from an `insertipv4redir` blob, creating the instance
/// on demand (0x91f370f0).
pub fn insert_redirect(
    state: &State,
    backend: &mut dyn AnyBackend,
    position: Option<RedirectIndex>,
    blob: &[u8],
    persist: bool,
) -> Result<RedirectIndex, Hresult> {
    let created = ensure_simulator(backend)?;
    let mut slot = Program::EMPTY;
    let inserted =
        RedirectConfig::parse(blob)
            .map_err(Hresult::from)
            .and_then(|(redirect, program)| {
                let program = parse_program(program, &mut slot)?;
                redirect.validate()?;
                backend.insert_redirect(position, &redirect, program)
            });
    match inserted {
        Ok(index) => {
            persist_file(state, backend, persist);
            Ok(index)
        }
        Err(error) => {
            if created {
                let _ = backend.destroy_simulator();
            }
            Err(error)
        }
    }
}

fn insert_redirect_command(
    invocation: &mut Invocation<'_>,
    position: Option<RedirectIndex>,
    blob: &[u8],
    persist: bool,
) -> Hresult {
    match insert_redirect(
        &invocation.state.network.netsim,
        invocation.backend,
        position,
        blob,
        persist,
    ) {
        Ok(RedirectIndex(index)) => {
            invocation.set_text(format_args!("index={index}"));
            status::OK
        }
        Err(error) => fail(invocation, error),
    }
}

/// Redirects removed and left by [`remove_redirects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectRemoval {
    pub removed: u32,
    pub left: u32,
}

/// Remove the redirect at `position`, or every redirect, and release an
/// idle instance (0x91f37220).
pub fn remove_redirects(
    state: &State,
    backend: &mut dyn AnyBackend,
    position: Option<RedirectIndex>,
    persist: bool,
) -> Result<RedirectRemoval, Hresult> {
    if !backend.simulator_exists() {
        if position.is_some() {
            return Err(status::NO_INSTANCE);
        }
        return Ok(RedirectRemoval {
            removed: 0,
            left: 0,
        });
    }
    let removed = backend.remove_redirects(position)?;
    let left = backend.redirect_count();
    release_if_idle(backend)?;
    persist_file(state, backend, persist);
    Ok(RedirectRemoval { removed, left })
}

fn remove_redirects_command(
    invocation: &mut Invocation<'_>,
    position: Option<RedirectIndex>,
    persist: bool,
) -> Hresult {
    match remove_redirects(
        &invocation.state.network.netsim,
        invocation.backend,
        position,
        persist,
    ) {
        Ok(RedirectRemoval { removed, left }) => {
            invocation.set_text(format_args!("removed={removed} left={left}"));
            status::OK
        }
        Err(error) => fail(invocation, error),
    }
}

fn write_hex(text: &mut ResponseText, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(text, "{byte:02X}");
    }
}

/// `reload` (0x91f36818): replace the instance with the file's
/// configuration. The reply text is always `file="<stored name>"`.
fn reload(invocation: &mut Invocation<'_>, name: &[u8]) -> Hresult {
    if invocation.state.network.netsim.reloading {
        return status::BUSY;
    }
    invocation.state.network.netsim.reloading = true;
    let result = run_reload(invocation, name);
    invocation.text.clear();
    let _ = invocation.text.write_str("file=\"");
    let _ = invocation
        .text
        .push_bytes(invocation.state.network.netsim.file.as_bytes());
    let _ = invocation.text.write_str("\"");
    invocation.state.network.netsim.reloading = false;
    result
}

fn run_reload(invocation: &mut Invocation<'_>, name: &[u8]) -> Hresult {
    if !name.is_empty() {
        let translated = invocation
            .state
            .filesystem
            .drives
            .translate(invocation.backend, name);
        let file = &mut invocation.state.network.netsim.file;
        match translated {
            Some(path) => file.set(path.as_bytes()),
            None => file.set(name),
        }
    } else if invocation.state.network.netsim.file.as_bytes().is_empty() {
        return status::NO_FILE;
    }
    if invocation.backend.simulator_exists()
        && let Err(error) = invocation.backend.destroy_simulator()
    {
        return error;
    }
    let file = &invocation.state.network.netsim.file;
    let request = CreateRequest {
        access: FileAccess::GENERIC_READ,
        allocation_size: None,
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::Open,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match invocation.backend.create_file(file.as_bytes(), &request) {
        Ok(handle) => handle,
        Err(status) => return Hresult::from_nt_status(status, status::GENERIC),
    };
    let result = match invocation.backend.allocate_pool(FILE_BUFFER_SIZE as u32) {
        Some(buffer) => {
            let failed = execute_file(invocation, handle, buffer);
            invocation.backend.free_pool(buffer);
            // Stock rewrites before closing the reader, whose handle shares
            // nothing.
            if failed {
                write_file(
                    invocation.state.network.netsim.file.as_bytes(),
                    invocation.backend,
                );
            }
            status::OK
        }
        None => status::OUT_OF_MEMORY,
    };
    invocation.backend.close_file(handle);
    result
}

/// Execute the file's lines (reader 0x91f315a0, line callback 0x91f35f88).
/// Lines end at CR or LF; a remainder that starts with NUL ends the file,
/// and text that fills the buffer or ends the file without a terminator
/// loses its last byte. Returns whether a line failed.
fn execute_file(invocation: &mut Invocation<'_>, handle: FileHandle, buffer: PoolBuffer) -> bool {
    let mut failed = false;
    let mut count = 0usize;
    loop {
        if count != 0 {
            let mut start = 0;
            let mut position = 0;
            while position < count {
                let byte = invocation.backend.pool(buffer)[position];
                if matches!(byte, b'\n' | b'\r') {
                    failed |= execute_line(invocation, buffer, start..position);
                    start = position + 1;
                }
                position += 1;
            }
            // The byte past the data is taken as nonzero.
            if start < count && invocation.backend.pool(buffer)[start] == 0 {
                return failed;
            }
            if start != 0 {
                invocation.backend.pool(buffer).copy_within(start..count, 0);
                count -= start;
            } else {
                failed |= execute_line(invocation, buffer, 0..count - 1);
                count = 0;
            }
        }
        let target = PoolRange {
            buffer,
            offset: count as u32,
            length: (FILE_BUFFER_SIZE - count) as u32,
        };
        if let Ok(read) = invocation.backend.read_file(handle, None, target) {
            count += read as usize;
        }
        if count == 0 {
            return failed;
        }
    }
}

/// A file line the reader executes. One value lives briefly on the stack;
/// there is no allocator to box the larger variant.
#[allow(clippy::large_enum_variant)]
enum FileLine {
    Netsim(Result<Request, Hresult>),
    LinkState(Result<Option<super::LinkFlags>, Hresult>),
}

/// Run a `netsim` or `linkstate` line of the reader's buffer without a
/// connection; other lines are ignored. Returns whether it failed.
fn execute_line(
    invocation: &mut Invocation<'_>,
    buffer: PoolBuffer,
    range: core::ops::Range<usize>,
) -> bool {
    trace_line(
        invocation.state.console.trace_mask,
        invocation.backend,
        buffer,
        range.clone(),
    );
    let line = CommandLine::new(&invocation.backend.pool(buffer)[range]);
    let request = if line.is_command("netsim") {
        FileLine::Netsim(Request::parse(line))
    } else if line.is_command("linkstate") {
        FileLine::LinkState(super::parse_link_state(line))
    } else {
        return false;
    };
    let mut text = ResponseText::new();
    let mut nested = Invocation {
        line: CommandLine::new(&[]),
        buffer: &[],
        text: &mut text,
        session: None,
        state: &mut *invocation.state,
        backend: &mut *invocation.backend,
        network: &mut *invocation.network,
    };
    let result = match request {
        FileLine::Netsim(request) => execute(&mut nested, request),
        FileLine::LinkState(flags) => super::execute_link_state(&mut nested, flags),
    };
    if result.is_failure() {
        console::trace(
            invocation.state,
            invocation.backend,
            TraceMask::SETTINGS,
            format_args!(
                "XBDM: NetSimReadIniLine processing command failed (0x{:08x})\n",
                result.0
            ),
        );
    }
    result.is_failure()
}

#[inline(never)]
fn trace_line(
    mask: TraceMask,
    backend: &mut dyn AnyBackend,
    buffer: PoolBuffer,
    range: core::ops::Range<usize>,
) {
    if !mask.contains(TraceMask::SETTINGS) {
        return;
    }
    let mut message = console::MessageText::new();
    let _ = message.write_str("XBDM: NetSimReadIniLine '");
    let _ = message.push_bytes(console::c_string(&backend.pool(buffer)[range]));
    let _ = message.write_str("'\n");
    backend.debug_print(message.as_bytes());
}

/// Buffered writer over a pool block (0x91f319c8 and 0x91f31860).
struct PoolWriter {
    handle: FileHandle,
    buffer: PoolBuffer,
    used: usize,
}

impl PoolWriter {
    fn push(&mut self, backend: &mut dyn AnyBackend, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let count = bytes.len().min(FILE_BUFFER_SIZE - self.used);
            backend.pool(self.buffer)[self.used..self.used + count]
                .copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == FILE_BUFFER_SIZE {
                self.flush(backend);
            }
        }
    }

    /// Stock stops the system on a failed write; the result is ignored here.
    fn flush(&mut self, backend: &mut dyn AnyBackend) {
        if self.used != 0 {
            let range = PoolRange {
                buffer: self.buffer,
                offset: 0,
                length: self.used as u32,
            };
            let _ = backend.write_file(self.handle, None, FileData::Pool(range));
            self.used = 0;
        }
    }

    fn line(&mut self, backend: &mut dyn AnyBackend, prefix: &[u8], blob: &[u8]) {
        self.push(backend, prefix);
        for &byte in blob {
            let mut digits = [0u8; 2];
            let mut text = crate::text::Text::<2>::new();
            let _ = write!(text, "{byte:02X}");
            digits.copy_from_slice(text.as_bytes());
            self.push(backend, &digits);
        }
        self.push(backend, LINE_END);
    }
}

/// NetSimWriteIniFile (0x91f36290): replace the file with one line per in
/// queue, out queue, and redirect. Nothing is written without a stored
/// name, pool memory, or a created file.
fn write_file(name: &[u8], backend: &mut dyn AnyBackend) {
    let mask = console::Backend::trace_mask(backend);
    let trace = |backend: &mut dyn AnyBackend, arguments: core::fmt::Arguments<'_>| {
        console::trace_text(mask, backend, TraceMask::SETTINGS, |message| {
            let _ = message.write_fmt(arguments);
        });
    };
    if name.is_empty() {
        trace(
            backend,
            format_args!("XBDM: NetSimWriteIniFile - No filename configured.\n"),
        );
        return;
    }
    console::trace_text(mask, backend, TraceMask::SETTINGS, |message| {
        let _ = message.write_str("XBDM: NetSimWriteIniFile - Starting to write \"");
        let _ = message.push_bytes(console::c_string(name));
        let _ = message.write_str("\".\n");
    });
    let Some(buffer) = backend.allocate_pool(FILE_BUFFER_SIZE as u32) else {
        trace(
            backend,
            format_args!("XBDM: NetSimWriteIniFile - No memory!\n"),
        );
        return;
    };
    backend.pool(buffer).fill(0);
    let request = CreateRequest {
        access: FileAccess::GENERIC_WRITE,
        allocation_size: None,
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match backend.create_file(name, &request) {
        Ok(handle) => handle,
        Err(status) => {
            trace(
                backend,
                format_args!(
                    "XBDM: NetSimWriteIniFile - Failed to create file: 0x{:08x}\n",
                    status.0
                ),
            );
            backend.free_pool(buffer);
            return;
        }
    };
    let mut writer = PoolWriter {
        handle,
        buffer,
        used: 0,
    };
    writer.push(backend, b"[xbdm]");
    writer.push(backend, LINE_END);
    let exists = backend.simulator_exists();
    for (direction, prefix) in [
        (Direction::Inbound, b"netsim insertq in cfg=".as_slice()),
        (Direction::Outbound, b"netsim insertq out cfg=".as_slice()),
    ] {
        let count = if exists {
            backend.queue_count(direction)
        } else {
            0
        };
        for index in 0..count {
            let Ok(snapshot) = backend.queue(direction, QueueIndex(index)) else {
                break;
            };
            let mut blob = [0u8; CONFIG_CAPACITY];
            let Ok(length) = snapshot.serialize(&mut blob) else {
                break;
            };
            writer.line(backend, prefix, &blob[..length]);
        }
    }
    let count = if exists { backend.redirect_count() } else { 0 };
    for index in 0..count {
        let Some(redirect) = backend.redirect(RedirectIndex(index)) else {
            break;
        };
        let mut blob = [0u8; CONFIG_CAPACITY];
        let Ok(length) = redirect.serialize(&mut blob) else {
            break;
        };
        writer.line(backend, b"netsim insertipv4redir cfg=", &blob[..length]);
    }
    writer.flush(backend);
    backend.close_file(handle);
    trace(
        backend,
        format_args!("XBDM: NetSimWriteIniFile - Done writing ini file.\n"),
    );
    backend.free_pool(buffer);
}

#[cfg(test)]
mod tests {
    use super::*;

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
