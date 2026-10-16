//! Profile-guided optimization runtime logic (stock 0x91f6b900..0x91f71600):
//! count block layout, value buckets, profile path construction, the
//! runtime's text conversions, and `pogo.ini` handling. The Xbox backend
//! applies the results to the instrumented modules; see
//! `docs/re-notes/pgo.md`.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem;
use crate::commands::filesystem::CreateDisposition;
use crate::commands::filesystem::CreateOptions;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileAccess;
use crate::commands::filesystem::FileAttributes;
use crate::commands::filesystem::PoolRange;
use crate::commands::filesystem::ShareAccess;
use crate::state::ServerState;

/// Allocation granularity of count blocks (0x91fa36a4).
pub const PAGE_SIZE: u32 = 0x1000;
/// Capacity in UTF-16 units of every path and phase buffer.
pub const PATH_UNITS: usize = 0x104;
/// Capacity in bytes of a profile file name.
pub const FILE_NAME_BYTES: usize = 0x104;

/// `pogo.ini` cannot be located for the module path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadModulePath;

/// Result of export 107: `0x82da000c`.
impl From<BadModulePath> for Hresult {
    fn from(BadModulePath: BadModulePath) -> Self {
        Hresult::from_error_code(ErrorCode::FilenameInvalid)
    }
}

/// Layout family of a count block. The runtime compares the version word
/// with the extended value only; every other value is standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockFormat {
    /// Version 0x11000000: 8-byte counters, allocation scale applies.
    Standard,
    /// Version 0x030000c0: 4-byte counters, sweeps on a full buffer.
    Extended,
}

impl BlockFormat {
    pub const STANDARD_VERSION: u32 = 0x1100_0000;
    pub const EXTENDED_VERSION: u32 = 0x0300_00c0;

    pub const fn from_version(version: u32) -> Self {
        if version == Self::EXTENDED_VERSION {
            Self::Extended
        } else {
            Self::Standard
        }
    }

    pub const fn version(self) -> u32 {
        match self {
            Self::Standard => Self::STANDARD_VERSION,
            Self::Extended => Self::EXTENDED_VERSION,
        }
    }

    /// Counter width and entry alignment.
    pub const fn width(self) -> u32 {
        match self {
            Self::Standard => 8,
            Self::Extended => 4,
        }
    }

    pub const fn header_size(self) -> u32 {
        match self {
            Self::Standard => 0x2a0,
            Self::Extended => 0x78,
        }
    }

    /// Bytes of a value list entry `{value, count, next}` with 32-bit
    /// values (exports 184, 185, 187, 188).
    pub const fn word_entry_size(self) -> u32 {
        align_up(0xc, self.width())
    }

    /// Bytes of a call tree entry `{key, left, right, pad, counters[c],
    /// lists[l]}` (exports 182 and 193).
    pub const fn tree_entry_size(self, descriptor: TreeDescriptor) -> u32 {
        align_up(
            (descriptor.counters as u32 + descriptor.lists as u32) * 4 + 0x10,
            self.width(),
        )
    }

    /// Bytes of a path tree entry with 8-byte slots (export 181).
    pub const fn path_entry_size(self, descriptor: TreeDescriptor) -> u32 {
        align_up(
            (descriptor.counters as u32 + descriptor.lists as u32) * 8 + 0x10,
            self.width(),
        )
    }
}

/// Bytes of a value list entry `{u64 value, u64 count, next}` (exports
/// 183 and 186), the same in both formats.
pub const WIDE_ENTRY_SIZE: u32 = 0x18;

/// Round `value` up to a multiple of the power of two `alignment`.
pub const fn align_up(value: u32, alignment: u32) -> u32 {
    value.wrapping_add(alignment - 1) & !(alignment - 1)
}

/// Offsets in a count block.
pub mod block {
    /// `"OGOP"` as stored big endian.
    pub const MAGIC: u32 = 0x00;
    pub const MAGIC_VALUE: u32 = 0x4f47_4f50;
    pub const VERSION: u32 = 0x04;
    /// Copy of the module header word +8.
    pub const MODULE_WORD: u32 = 0x08;
    /// Allocation pointer: bytes in use from the block start.
    pub const USED: u32 = 0x0c;
    /// FILETIME of creation or of the last reset, in whole milliseconds.
    pub const TIME: u32 = 0x10;
    pub const COUNT_SLOTS: u32 = 0x18;
    pub const COUNTS: u32 = 0x1c;
    pub const LIST_COUNT: u32 = 0x20;
    pub const LISTS: u32 = 0x24;
    /// Entries inserted by exports 183 and 186.
    pub const WIDE_ENTRIES: u32 = 0x28;
    pub const TREE_COUNT: u32 = 0x2c;
    pub const TREES: u32 = 0x30;
    /// Entries inserted by export 181.
    pub const PATH_ENTRIES: u32 = 0x34;
    pub const WORD_COUNT: u32 = 0x38;
    pub const WORDS: u32 = 0x3c;
    /// Byte 1 in both formats.
    pub const PRESENT: u32 = 0x50;
    pub const HAS_CALLERS: u32 = 0x51;
    pub const COMMITTED: u32 = 0x54;
    pub const RESERVED: u32 = 0x58;
    /// Extended: byte, the [`super::SweepKind`] of the profile being written.
    /// Standard: dword 1.
    pub const SWEEP_KIND: u32 = 0x5c;
    /// Extended: byte 1 until the shutdown profile.
    pub const LIVE: u32 = 0x5d;
    /// Extended: byte, counts are reset after the profile being written.
    pub const RESETTING: u32 = 0x5e;
    /// Extended: bytes set while a full-buffer profile is written.
    pub const FULL_BUFFER: u32 = 0x5f;
    /// Extended: byte; standard: dword 1 until the shutdown profile.
    pub const FULL_BUFFER_OR_LIVE: u32 = 0x60;
    /// Byte: a probe dropped data.
    pub const LOST: u32 = 0x61;
    pub const THREADS: u32 = 0x64;
    /// Sweep generation; changes when a full-buffer sweep clears entries.
    pub const GENERATION: u32 = 0x6c;
    /// Probes running on threads without a thread record.
    pub const UNTRACKED: u32 = 0x70;
    /// Extended only: module word written to records whose probe failed.
    pub const SCRATCH: u32 = 0x74;
}

/// Why a profile is written (count block +0x5c, extended format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepKind {
    /// `pogoctrl snapshot`.
    Control = 1,
    /// Export 110.
    Export = 2,
    Shutdown = 3,
    FullBuffer = 4,
    Overflow = 5,
}

/// One call tree descriptor of the module header (+0x60, 8 bytes each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeDescriptor {
    /// Counter slots per entry (+0).
    pub counters: u16,
    /// Value lists per entry (+2).
    pub lists: u16,
}

/// Module record fields the count block layout depends on (0x91f6bd68).
#[derive(Debug, Clone, Copy)]
pub struct ModuleShape<D> {
    pub format: BlockFormat,
    /// Record +0x74.
    pub module_word: u32,
    /// Record +0x6a0.
    pub has_callers: bool,
    /// Record +0x6a4.
    pub count_slots: u32,
    /// Record +0x6ac.
    pub list_count: u32,
    /// Record +0x6a8; also the number of `descriptors`.
    pub tree_count: u32,
    /// Record +0x6b0.
    pub word_count: u32,
    /// Record +0x6c4.
    pub scratch: u32,
    /// Record +0x70, `MaxTitleMemory`; 0 sizes the block from the layout.
    pub title_memory: u32,
    /// Record +0x6c8: three more scale steps in the standard format.
    pub scale_bonus: bool,
    /// Record +0x6c, `AllocScale`.
    pub allocation_scale: u32,
    pub descriptors: D,
}

/// A count of items and their block offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub count: u32,
    pub offset: u32,
}

/// The count block header before creation time is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountBlockHeader {
    pub format: BlockFormat,
    pub module_word: u32,
    pub used: u32,
    pub counts: Region,
    pub lists: Region,
    pub trees: Region,
    pub words: Region,
    pub has_callers: bool,
    pub committed: u32,
    pub reserved: u32,
    pub scratch: u32,
}

impl CountBlockHeader {
    /// Lay out the block of a module (0x91f6bd68). Region counts are one
    /// more than the module's; entry 0 of each is unused.
    pub fn new<D: Iterator<Item = TreeDescriptor> + Clone>(shape: &ModuleShape<D>) -> Self {
        let format = shape.format;
        let width = format.width();
        let header = format.header_size();
        let counts = Region {
            count: shape.count_slots.wrapping_add(1),
            offset: header,
        };
        let lists_offset = width.wrapping_mul(counts.count).wrapping_add(header);
        let lists = Region {
            count: shape.list_count.wrapping_add(1),
            offset: lists_offset,
        };
        let list_head = match format {
            BlockFormat::Standard => 8,
            BlockFormat::Extended => 4,
        };
        let trees_offset = align_up(
            lists
                .count
                .wrapping_mul(list_head)
                .wrapping_add(lists.offset),
            width,
        );
        let trees = Region {
            count: shape.tree_count.wrapping_add(1),
            offset: trees_offset,
        };
        let words_offset = align_up(
            trees.count.wrapping_mul(8).wrapping_add(trees.offset),
            width,
        );
        let words = Region {
            count: shape.word_count,
            offset: words_offset,
        };
        let used = align_up(
            words.count.wrapping_mul(4).wrapping_add(words.offset),
            width,
        );
        let committed = align_up(used, PAGE_SIZE);
        let descriptors = shape.descriptors.clone().take(shape.tree_count as usize);
        let size = match format {
            BlockFormat::Extended => {
                let largest = descriptors
                    .clone()
                    .map(|descriptor| {
                        let size = u32::from(descriptor.counters) * width
                            + (u32::from(descriptor.lists) + 4) * 4;
                        if descriptor.lists != 0 {
                            size + 0xc
                        } else {
                            size
                        }
                    })
                    .max()
                    .unwrap_or(0);
                let minimum = used.wrapping_add(largest);
                let mut size = align_up(shape.title_memory, PAGE_SIZE);
                if size == 0 {
                    let per_tree = descriptors.fold(0u32, |sum, descriptor| {
                        sum.wrapping_add(
                            u32::from(descriptor.counters) * width
                                + (u32::from(descriptor.lists) + 1) * 16,
                        )
                    });
                    size = lists
                        .count
                        .wrapping_mul(0xc)
                        .wrapping_add(used)
                        .wrapping_add(per_tree.wrapping_mul(0xb));
                }
                size.max(minimum)
            }
            BlockFormat::Standard => {
                let per_tree = descriptors.fold(0u32, |sum, descriptor| {
                    sum.wrapping_add(
                        u32::from(descriptor.counters) * width
                            + u32::from(descriptor.lists) * 0xf8
                            + 0x10,
                    )
                });
                lists
                    .count
                    .wrapping_mul(0xf0)
                    .wrapping_add(used)
                    .wrapping_add(per_tree.wrapping_mul(7))
                    .wrapping_mul(4)
            }
        };
        let mut reserved = align_up(size, PAGE_SIZE);
        if format == BlockFormat::Standard {
            let scale = u32::from(shape.scale_bonus) * 3 + shape.allocation_scale;
            if scale != 0 {
                reserved = align_up(scale.wrapping_mul(reserved), PAGE_SIZE);
            }
        }
        Self {
            format,
            module_word: shape.module_word,
            used,
            counts,
            lists,
            trees,
            words,
            has_callers: shape.has_callers,
            committed,
            reserved,
            scratch: shape.scratch,
        }
    }

    /// Store the header as the block's first [`BlockFormat::header_size`]
    /// bytes, with `time` at +0x10.
    pub fn encode(&self, time: u64, out: &mut [u8]) {
        let size = self.format.header_size() as usize;
        let out = &mut out[..size];
        out.fill(0);
        let mut put = |offset: u32, value: u32| {
            out[offset as usize..offset as usize + 4].copy_from_slice(&value.to_be_bytes());
        };
        put(block::MAGIC, block::MAGIC_VALUE);
        put(block::VERSION, self.format.version());
        put(block::MODULE_WORD, self.module_word);
        put(block::USED, self.used);
        put(block::TIME, (time >> 32) as u32);
        put(block::TIME + 4, time as u32);
        put(block::COUNT_SLOTS, self.counts.count);
        put(block::COUNTS, self.counts.offset);
        put(block::LIST_COUNT, self.lists.count);
        put(block::LISTS, self.lists.offset);
        put(block::TREE_COUNT, self.trees.count);
        put(block::TREES, self.trees.offset);
        put(block::WORD_COUNT, self.words.count);
        put(block::WORDS, self.words.offset);
        put(block::COMMITTED, self.committed);
        put(block::RESERVED, self.reserved);
        match self.format {
            BlockFormat::Standard => {
                put(block::SWEEP_KIND, 1);
                put(block::FULL_BUFFER_OR_LIVE, 1);
            }
            BlockFormat::Extended => put(block::SCRATCH, self.scratch),
        }
        out[block::PRESENT as usize] = 1;
        out[block::HAS_CALLERS as usize] = u8::from(self.has_callers);
        if self.format == BlockFormat::Extended {
            out[block::LIVE as usize] = 1;
        }
    }
}

/// Head word of a 32-bit value list: entry offset in bits 2..30 and a
/// 4-bit insertion counter split over bits 30..32 (high) and 0..2 (low).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListHead(pub u32);

impl ListHead {
    const OFFSET_MASK: u32 = 0x3fff_fffc;

    pub const fn offset(self) -> u32 {
        self.0 & Self::OFFSET_MASK
    }

    pub const fn counter(self) -> u32 {
        (self.0 >> 30) << 2 | (self.0 & 3)
    }

    /// The head after one more insertion, pointing at `offset`.
    pub const fn advanced(self, offset: u32) -> Self {
        let counter = self.counter() + 1;
        Self(counter.rotate_left(28) & 0xc000_0000 | counter & 3 | offset & Self::OFFSET_MASK)
    }
}

/// Distinct values a counted list holds before new values go to
/// [`OVERFLOW_VALUE`] (exports 186, 187, 188).
pub const LIST_LIMIT: u32 = 10;
/// Shared entry for values beyond [`LIST_LIMIT`].
pub const OVERFLOW_VALUE: u64 = 0x7fff_ffff;

/// Key under which a call tree stores `key` (0x91f70c80 table lookup):
/// the reversed bits with alternate bits inverted.
#[inline(never)]
pub const fn tree_key(mut key: u32) -> u32 {
    // A bit loop: `reverse_bits` expands to about 25 instructions on PPC.
    let mut reversed = 0;
    let mut bit = 0;
    while bit < 32 {
        reversed = (reversed << 1) | (key & 1);
        key >>= 1;
        bit += 1;
    }
    reversed ^ 0xaaaa_aaaa
}

/// Range table of exports 189-191: `count` at +4, flags at +6 (bit 0
/// 8-byte entries, bit 1 signed), sorted entries from +8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeTable {
    pub count: u16,
    pub flags: u16,
}

impl RangeTable {
    pub const fn wide(self) -> bool {
        self.flags & 1 != 0
    }

    pub const fn signed(self) -> bool {
        self.flags & 2 != 0
    }

    /// Bucket of `value` (0x91f6ca28): `2i + 2` for an exact match with
    /// entry `i`, `2i + 1` or `2i + 3` for the gap below or above the
    /// last entry compared. The image keeps the below flag once any step
    /// went down, so a later match or upward step still yields `2i + 1`.
    /// `entry` reads entry `i` (zero-extended when narrow); an empty table
    /// compares against entry 0 as the image does.
    pub fn bucket(self, value: u64, entry: impl Fn(u32) -> u64) -> u32 {
        let mut low: i32 = 0;
        let mut high = i32::from(self.count) - 1;
        let mut went_below = false;
        let mut found = false;
        let mut middle;
        loop {
            middle = high.wrapping_add(low) / 2;
            let element = entry(middle as u32);
            let ordering = match (self.wide(), self.signed()) {
                (true, true) => (value as i64).cmp(&(element as i64)),
                (true, false) => value.cmp(&element),
                (false, true) => (value as u32 as i32).cmp(&(element as u32 as i32)),
                (false, false) => (value as u32).cmp(&(element as u32)),
            };
            match ordering {
                core::cmp::Ordering::Equal => {
                    found = true;
                    break;
                }
                core::cmp::Ordering::Less => {
                    went_below = true;
                    high = middle - 1;
                }
                core::cmp::Ordering::Greater => low = middle + 1,
            }
            if low > high {
                break;
            }
        }
        let base = (middle as u32).wrapping_add(1).wrapping_mul(2);
        if went_below {
            base.wrapping_sub(1)
        } else if found {
            base
        } else {
            base.wrapping_add(1)
        }
    }
}

/// A runtime failure that stops the console (0x91f74280 prints the text,
/// then KeBugCheck(0x1e)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fatal {
    ClientAbort,
    BaseNameUnreadable,
    NodeAllocation,
    BlockLookup,
    BlockAllocation,
    BinaryPathTooLong,
    ModuleNameFailed,
    ModuleNameTooLong,
    BuildPathTooLong,
    BaseNameTooLong,
    BaseModuleNameFailed,
    BaseModuleNameTooLong,
    WriteFailed,
    PhaseUnconvertible,
    InvalidSignature,
    InvalidVersion,
    InvalidValueListHead,
    InvalidTreeHead,
    InvalidValueListEntry,
    TlsAllocation,
    EventCreation,
    ThreadListAllocation,
    ThreadHandle,
    CounterOverflow,
    /// Count block reservation exhausted: the image prints an empty text.
    ReservationExhausted,
}

impl Fatal {
    /// Texts in declaration order.
    const TEXTS: [&'static str; 25] = [
        "IrtClientAbort",
        "Could not read base filename from object.",
        "PCIAllocate: VirtualAlloc failed\n",
        "PCILookupPGCHdr: CLIENTINFO not found\n",
        "CreateMemoryRegion: MapViewOfFileEx failed\n",
        "Pogo runtime: binary pathname too long",
        "IrtPogoInit: GetModuleFileName failed\n",
        "IrtPogoInit: GetModuleFileName result too long\n",
        "Pogo Runtime BuildPath: path too long",
        "Pogo Runtime Create Paths: Base PGC file name too long",
        "Pogo Runtime Create Paths: GetModuleFileName failed",
        "Pogo Runtime Create Paths: GetModuleFileName too long",
        "Unable to write PGC file",
        "Could not convert sweep phase name to Unicode.",
        "Pogo Runtime: Invalid header signature",
        "Pogo Runtime: Invalid header version",
        "Invalid VPLH*\n",
        "Invalid EPLH*\n",
        "Invalid VPLE*\n",
        "TlsAlloc failed\n",
        "CreateEvent failed\n",
        "IrtThreadList allocation failed\n",
        "IrtThreadList DuplicateHandle(GetCurrentThread()) failed\n",
        "counter overflowed 2^31\n",
        "",
    ];

    pub const fn text(self) -> &'static str {
        Self::TEXTS[self as usize]
    }
}

/// Profile write failures the runtime reports on the debug output and
/// otherwise ignores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteWarning {
    Write,
    Flush,
    Close,
}

impl WriteWarning {
    /// Texts in declaration order.
    const TEXTS: [&'static str; 3] = [
        "WritePGC: WriteFile failed\n",
        "WritePGC: FlushFileBuffers failed\n",
        "WritePGC: CloseHandle(hFile) failed\n",
    ];

    pub const fn text(self) -> &'static str {
        Self::TEXTS[self as usize]
    }
}

/// Byte offset in a profile file of the completion byte, written as 1
/// after the count block.
pub const COMPLETION_OFFSET: u64 = 0x52;

/// Debug output of an illegal UTF-8 sequence during conversion.
pub const ILLEGAL_UTF8_WARNING: &str = "XAPI[WRN]: UTF8ToUnicode(): illegal UTF-8 string\n";

/// The output buffer was too small (error 0x7a); the units or bytes that
/// fit were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall;

/// Result of a UTF-8 conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// Units produced, or `Err` when they exceed the output.
    pub units: Result<usize, BufferTooSmall>,
    /// Illegal sequences seen; each prints [`ILLEGAL_UTF8_WARNING`].
    pub illegal: u32,
}

/// Length of a C string.
pub fn c_len(bytes: &[u8]) -> usize {
    crate::commands::console::c_string(bytes).len()
}

/// Length of a wide C string; an unterminated buffer counts its length.
pub fn wide_len(units: &[u16]) -> usize {
    units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len())
}

/// Trailing byte count of a UTF-8 lead byte (0x91f99508).
const fn trailing(lead: u8) -> usize {
    match lead {
        0x00..=0xbf => 0,
        0xc0..=0xdf => 1,
        0xe0..=0xef => 2,
        0xf0..=0xf7 => 3,
        0xf8..=0xfb => 4,
        0xfc..=0xff => 5,
    }
}

/// Value subtracted from the accumulated sequence (0x91f994f0).
const UTF8_OFFSETS: [u32; 6] = [0, 0x3080, 0xe_2080, 0x3c8_2080, 0xfa08_2080, 0x8208_2080];

/// UTF-8 to UTF-16 (MultiByteToWideChar with CP_UTF8, 0x91f74738) of the C
/// string `input` and its terminator. A sequence that would run past the
/// terminator ends the conversion. Legality only affects the warning: up
/// to four bytes, all continuations in 0x80..=0xbf.
pub fn decode_utf8(input: &[u8], output: &mut [u16]) -> Decoded {
    let length = c_len(input) + 1;
    let byte = |index: usize| input.get(index).copied().unwrap_or(0);
    let mut position = 0;
    let mut units = 0usize;
    let mut illegal = 0;
    let mut put = |units: &mut usize, unit: u16| {
        if *units < output.len() {
            output[*units] = unit;
        }
        *units += 1;
    };
    while position < length {
        let extra = trailing(byte(position));
        if position + extra >= length {
            break;
        }
        let legal =
            extra < 4 && (1..=extra).all(|index| (0x80..=0xbf).contains(&byte(position + index)));
        if !legal {
            illegal += 1;
        }
        let mut character = 0u32;
        for index in 0..=extra {
            if index != 0 {
                character <<= 6;
            }
            character = character.wrapping_add(u32::from(byte(position + index)));
        }
        position += extra + 1;
        let character = character.wrapping_sub(UTF8_OFFSETS[extra]);
        if character <= 0xffff {
            put(&mut units, character as u16);
        } else if character > 0x10_ffff {
            put(&mut units, 0xfffd);
        } else {
            let scalar = character - 0x1_0000;
            put(&mut units, ((scalar >> 10) + 0xd800) as u16);
            put(&mut units, ((scalar & 0x3ff) + 0xdc00) as u16);
        }
    }
    let units = if units > output.len() {
        Err(BufferTooSmall)
    } else {
        Ok(units)
    };
    Decoded { units, illegal }
}

/// UTF-16 to UTF-8 (WideCharToMultiByte with CP_UTF8, 0x91f74600), one
/// to three bytes per unit; surrogates are encoded one by one. Bytes past
/// the output are counted but not written.
pub fn encode_utf8(input: &[u16], output: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let mut count = 0usize;
    let mut put = |byte: u8| {
        if count < output.len() {
            output[count] = byte;
        }
        count += 1;
    };
    for &unit in input {
        if unit <= 0x7f {
            put(unit as u8);
        } else if unit <= 0x7ff {
            put(0xc0 | (unit >> 6) as u8 & 0x1f);
            put(0x80 | unit as u8 & 0x3f);
        } else {
            put(0xe0 | (unit >> 12) as u8 & 0xf);
            put(0x80 | (unit >> 6) as u8 & 0x3f);
            put(0x80 | unit as u8 & 0x3f);
        }
    }
    if count > output.len() {
        Err(BufferTooSmall)
    } else {
        Ok(count)
    }
}

/// A NUL-padded UTF-16 path buffer of [`PATH_UNITS`] units.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WidePath(pub [u16; PATH_UNITS]);

impl Default for WidePath {
    fn default() -> Self {
        Self([0; PATH_UNITS])
    }
}

impl core::fmt::Debug for WidePath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = char::decode_utf16(self.units().iter().copied())
            .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER));
        formatter.write_str("\"")?;
        for character in text {
            core::fmt::Write::write_char(formatter, character)?;
        }
        formatter.write_str("\"")
    }
}

impl WidePath {
    pub fn units(&self) -> &[u16] {
        &self.0[..wide_len(&self.0)]
    }

    /// `wcsncpy(path, source, 0x104)`: copies up to the terminator and pads
    /// with zeros; a longer source leaves the buffer unterminated.
    pub fn copy_from(source: &[u16]) -> Self {
        let mut path = Self::default();
        let length = wide_len(source).min(PATH_UNITS);
        path.0[..length].copy_from_slice(&source[..length]);
        path
    }

    fn set(&mut self, parts: &[&[u16]]) {
        self.0 = [0; PATH_UNITS];
        let mut length = 0;
        for part in parts {
            for &unit in part.iter() {
                self.0[length] = unit;
                length += 1;
            }
        }
    }
}

const BACKSLASH: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const COLON: u16 = b':' as u16;

fn to_backslashes(units: &mut [u16]) {
    for unit in units.iter_mut() {
        if *unit == SLASH {
            *unit = BACKSLASH;
        }
    }
}

fn to_lowercase(units: &mut [u16]) {
    for unit in units.iter_mut() {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(unit) {
            *unit += 0x20;
        }
    }
}

fn last_backslash(units: &[u16]) -> Option<usize> {
    units.iter().rposition(|&unit| unit == BACKSLASH)
}

/// Join a module path and the base name into the profile base path
/// (0x91f6cd40): an absolute name stands alone, a rooted one takes the
/// module's drive, a relative one replaces the module's file name.
pub fn build_path(module: &[u16], base: &[u16], extension: &[u16]) -> Result<WidePath, Fatal> {
    let module = &module[..wide_len(module)];
    let base = &base[..wide_len(base)];
    let extension = &extension[..wide_len(extension)];
    let length = base.len() + extension.len();
    if length >= PATH_UNITS {
        return Err(Fatal::BuildPathTooLong);
    }
    let unit = |units: &[u16], index: usize| units.get(index).copied().unwrap_or(0);
    let mut path = WidePath::default();
    if unit(base, 1) == COLON {
        path.set(&[base, extension]);
    } else if unit(base, 0) == BACKSLASH && unit(module, 1) == COLON {
        if length + 2 >= PATH_UNITS {
            return Err(Fatal::BuildPathTooLong);
        }
        path.set(&[&module[..2], base, extension]);
    } else {
        if module.len() >= PATH_UNITS {
            return Err(Fatal::BuildPathTooLong);
        }
        match last_backslash(module) {
            None => path.set(&[base, extension]),
            Some(separator) => {
                if separator + length + 1 >= PATH_UNITS {
                    return Err(Fatal::BuildPathTooLong);
                }
                path.set(&[&module[..=separator], base, extension]);
                to_backslashes(&mut path.0);
            }
        }
    }
    Ok(path)
}

/// The profile base path of a module (0x91f6d298): the base name from
/// export 113 with `/` as `\`, joined to the lowercased module file name
/// (`module` holds the name's units, without terminator).
pub fn base_path(base_name: &[u16], module: &[u16]) -> Result<WidePath, Fatal> {
    if wide_len(base_name) >= PATH_UNITS {
        return Err(Fatal::BaseNameTooLong);
    }
    let mut base = WidePath::copy_from(base_name);
    to_backslashes(&mut base.0);
    if module.is_empty() {
        return Err(Fatal::BaseModuleNameFailed);
    }
    if module.len() >= PATH_UNITS {
        return Err(Fatal::BaseModuleNameTooLong);
    }
    let mut name = WidePath::copy_from(module);
    to_backslashes(&mut name.0);
    to_lowercase(&mut name.0);
    build_path(name.units(), base.units(), &[])
}

/// Replace the directory of a base path with an `OutputPath` directory
/// (0x91f70b18), lowercased, with `\` separators and a trailing `\`.
/// `directory` is NUL-terminated UTF-8; the path is unchanged when it does
/// not convert or the result does not fit.
pub fn output_path(path: &mut WidePath, directory: &[u8]) -> Decoded {
    let mut converted = [0u16; PATH_UNITS + 1];
    let decoded = decode_utf8(directory, &mut converted[..PATH_UNITS - 1]);
    let Ok(units) = decoded.units else {
        return decoded;
    };
    if units == 0 {
        return decoded;
    }
    let mut length = wide_len(&converted);
    to_lowercase(&mut converted[..length]);
    to_backslashes(&mut converted[..length]);
    // The image reads the unit before an empty directory from its stack;
    // it is taken as not a separator.
    if length == 0 || converted[length - 1] != BACKSLASH {
        converted[length] = BACKSLASH;
        length += 1;
        converted[length] = 0;
    }
    // A path without a separator would fault the image; it is kept.
    let Some(separator) = last_backslash(path.units()) else {
        return decoded;
    };
    let mut name = [0u16; PATH_UNITS];
    let tail = &path.units()[separator + 1..];
    name[..tail.len()].copy_from_slice(tail);
    let name = &name[..tail.len()];
    if name.len() + length >= PATH_UNITS {
        return decoded;
    }
    path.set(&[&converted[..length], name]);
    decoded
}

/// Directory of the profile when the module's directory cannot be written
/// (0x91f6d420).
pub const FALLBACK_DIRECTORY: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT";

/// The fallback base path: [`FALLBACK_DIRECTORY`] and the base path's
/// last component with its separator. The image appends without a bound;
/// the result is cut to the units the name builder copies.
pub fn fallback_path(path: &WidePath) -> WidePath {
    let mut fallback = WidePath::default();
    let tail = last_backslash(path.units()).map_or(&[][..], |separator| &path.units()[separator..]);
    for (slot, unit) in fallback.0.iter_mut().zip(
        FALLBACK_DIRECTORY
            .encode_utf16()
            .chain(tail.iter().copied()),
    ) {
        *slot = unit;
    }
    fallback
}

/// A profile name without its number (0x91f6d038).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileName {
    units: [u16; PATH_UNITS + 1],
    length: usize,
}

impl ProfileName {
    /// `<base>` or `<base>-<phase>` when a phase is set. `phase` is the
    /// record's phase buffer; an unterminated phase continues into the
    /// module file name that follows it in the record (`continuation`).
    pub fn new(
        base: &WidePath,
        phase: Option<(&[u16; PATH_UNITS], &[u16])>,
    ) -> Result<Self, Fatal> {
        let mut units = [0u16; PATH_UNITS + 1];
        units[..PATH_UNITS].copy_from_slice(&base.0);
        let mut length = wide_len(&units);
        if let Some((phase, continuation)) = phase {
            let phase_length = wide_len(phase);
            let extra = if phase_length == PATH_UNITS {
                wide_len(continuation)
            } else {
                0
            };
            if length + phase_length + extra + 1 > PATH_UNITS {
                return Err(Fatal::BuildPathTooLong);
            }
            units[length] = u16::from(b'-');
            length += 1;
            units[length..length + phase_length].copy_from_slice(&phase[..phase_length]);
            length += phase_length;
        }
        if length + "!*.pgc".len() > PATH_UNITS {
            return Err(Fatal::BuildPathTooLong);
        }
        Ok(Self { units, length })
    }

    pub fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// Object name of profile `number` (0x91f712f8): the UTF-8 name, then
    /// `!<number>.pgc` written at the name's length in units. The image
    /// leaves an exactly filling name unterminated; it ends at the buffer.
    pub fn file_name(&self, number: u32, out: &mut [u8; FILE_NAME_BYTES]) -> usize {
        // A name longer in bytes than the buffer keeps the bytes that fit.
        let _ = encode_utf8(self.units(), out);
        let suffix = profile_suffix(number);
        let suffix_length = c_len(&suffix);
        let start = self.length;
        let room = FILE_NAME_BYTES - start;
        let count = suffix_length.min(room);
        out[start..start + count].copy_from_slice(&suffix[..count]);
        if suffix_length < room {
            out[start + count] = 0;
        }
        c_len(out)
    }
}

/// `"!%u.pgc"` and a terminator.
fn profile_suffix(number: u32) -> [u8; 16] {
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut rest = number;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let mut suffix = [0u8; 16];
    suffix[0] = b'!';
    for index in 0..count {
        suffix[1 + index] = digits[count - 1 - index];
    }
    suffix[1 + count..5 + count].copy_from_slice(b".pgc");
    suffix
}

/// Option numbers of record option setting (0x91f709e0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgoOption {
    /// Standard format when set (record +0x6c9 cleared).
    StandardPgc = 0,
    /// Fill counters with 0x7f bytes (record +0x6ca).
    TestCounterOverflow = 1,
    /// Reservation of extended blocks (record +0x70).
    MaxTitleMemory = 2,
    ValidateEplh = 3,
    ValidateVplh = 4,
    ValidateVple = 5,
    EnableSweepOnOverflow = 6,
    EnableSweepFullBuffer = 7,
}

/// One `pogo.ini` setting for the module (0x91f3dcb8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IniDirective<'a> {
    AllocScale(u32),
    /// Object path, or the value when it does not translate.
    OutputPath(&'a [u8]),
    DisableDataCollection,
    Option {
        option: PgoOption,
        value: u32,
    },
}

/// Keys in the order the handler compares them; a key matches when the
/// line's key is a case-insensitive prefix of it (an empty key matches
/// `AllocScale`).
const KEYS: [&[u8]; 11] = [
    b"AllocScale",
    b"OutputPath",
    b"DisableDataCollection",
    b"StandardPGC",
    b"TestCounterOverflow",
    b"MaxTitleMemory",
    b"ValidateEPLH",
    b"ValidateVPLH",
    b"ValidateVPLE",
    b"EnableSweepOnOverflow",
    b"EnableSweepFullBuffer",
];

/// `_strnicmp(text, key, count) == 0`.
fn key_matches(text: &[u8], key: &[u8]) -> bool {
    text.len() <= key.len() && text.eq_ignore_ascii_case(&key[..text.len()])
}

/// Decimal number of a setting (0x91f3dc48): C `strtoul` base 10 followed
/// by the end, a space, a tab, or `;`.
pub fn ini_number(text: &[u8]) -> Option<u32> {
    let text = &text[..c_len(text)];
    let mut position = 0;
    while matches!(
        text.get(position),
        Some(b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
    ) {
        position += 1;
    }
    let negative = text.get(position) == Some(&b'-');
    if matches!(text.get(position), Some(b'-' | b'+')) {
        position += 1;
    }
    let mut value = 0u32;
    let mut digits = false;
    let mut overflow = false;
    while let Some(&byte) = text.get(position).filter(|byte| byte.is_ascii_digit()) {
        digits = true;
        match value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
        {
            Some(next) if !overflow => value = next,
            _ => overflow = true,
        }
        position += 1;
    }
    let end = if digits { position } else { 0 };
    if !digits {
        value = 0;
    } else if overflow {
        value = u32::MAX;
    }
    if negative {
        value = value.wrapping_neg();
    }
    matches!(text.get(end), None | Some(b' ' | b'\t' | b';')).then_some(value)
}

/// Run one `pogo.ini` line (0x91f3dcb8). `[name]` opens the module's
/// section when `name` equals the module path, its drive path, or (without
/// a `\` on the line) its file name; other lines apply only inside it.
pub fn ini_line<'a>(
    line: &'a [u8],
    in_section: &mut bool,
    module_path: &[u8],
    drive_path: &[u8],
) -> Option<IniDirective<'a>> {
    let line = &line[..c_len(line)];
    match line.first() {
        Some(b'[') => {
            *in_section = false;
            let close = line.iter().position(|&byte| byte == b']')?;
            let name = &line[1..close];
            let equals = |candidate: &[u8]| {
                candidate.len() == name.len() && candidate.eq_ignore_ascii_case(name)
            };
            if equals(module_path) || equals(drive_path) {
                *in_section = true;
            } else if !line[1..].contains(&b'\\') {
                let separator = module_path.iter().rposition(|&byte| byte == b'\\')?;
                if equals(&module_path[separator + 1..]) {
                    *in_section = true;
                }
            }
            None
        }
        Some(b';') => None,
        _ if !*in_section => None,
        _ => {
            let equals = line.iter().position(|&byte| byte == b'=')?;
            let key = &line[..equals];
            let value = &line[equals + 1..];
            let flag = u32::from(value.first() == Some(&b'1'));
            let index = KEYS
                .iter()
                .position(|candidate| key_matches(key, candidate))?;
            let option = |option| {
                Some(IniDirective::Option {
                    option,
                    value: flag,
                })
            };
            match index {
                0 => ini_number(value).map(IniDirective::AllocScale),
                1 => Some(IniDirective::OutputPath(value)),
                2 => (flag != 0).then_some(IniDirective::DisableDataCollection),
                3 => option(PgoOption::StandardPgc),
                4 => option(PgoOption::TestCounterOverflow),
                5 => ini_number(value).map(|value| IniDirective::Option {
                    option: PgoOption::MaxTitleMemory,
                    value,
                }),
                6 => option(PgoOption::ValidateEplh),
                7 => option(PgoOption::ValidateVplh),
                8 => option(PgoOption::ValidateVple),
                9 => option(PgoOption::EnableSweepOnOverflow),
                _ => option(PgoOption::EnableSweepFullBuffer),
            }
        }
    }
}

/// Bytes of the `pogo.ini` read buffer.
const INI_BUFFER_SIZE: usize = 0x1000;
/// Longest module path the loader accepts, in bytes.
const INI_MODULE_PATH_LIMIT: usize = 0x140;
/// Capacity of the drive path and the `pogo.ini` path.
const INI_PATH_CAPACITY: usize = 0x104;
/// The last `\` of the drive path must lie before this offset.
const INI_DIRECTORY_LIMIT: usize = 0xfc;

/// Load `pogo.ini` for a module (export 107, 0x91f3e038): from the
/// directory of `module_path` (an object path) as a drive path, else
/// `xe:\pogo.ini`, passing each setting of the module's section to
/// `apply`. The stop-on-`pogomodstart` event is the caller's.
pub fn load_ini(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    module_path: &[u8],
    apply: &mut dyn FnMut(&ServerState, &mut dyn AnyBackend, IniDirective<'_>),
) -> Result<(), BadModulePath> {
    let module_path = &module_path[..c_len(module_path)];
    if module_path.len() >= INI_MODULE_PATH_LIMIT {
        return Err(BadModulePath);
    }
    let mut drive_path = [0u8; INI_PATH_CAPACITY];
    let drive_length =
        state
            .filesystem
            .drives
            .object_path_to_drive_path(backend, module_path, &mut drive_path);
    let drive_path = &drive_path[..drive_length];
    let Some(separator) = drive_path.iter().rposition(|&byte| byte == b'\\') else {
        return Err(BadModulePath);
    };
    if separator + 1 >= INI_DIRECTORY_LIMIT {
        return Err(BadModulePath);
    }
    let mut ini_path = [0u8; INI_PATH_CAPACITY];
    ini_path[..=separator].copy_from_slice(&drive_path[..=separator]);
    ini_path[separator + 1..separator + 9].copy_from_slice(b"pogo.ini");
    let ini_path = &ini_path[..separator + 9];
    let request = CreateRequest {
        access: FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::Open,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match filesystem::open_translated(state, backend, ini_path, &request) {
        Ok(handle) => Some(handle),
        Err(_) => filesystem::open_translated(state, backend, b"xe:\\pogo.ini", &request).ok(),
    };
    let Some(handle) = handle else {
        return Ok(());
    };
    if let Some(buffer) = backend.allocate_pool(INI_BUFFER_SIZE as u32) {
        let mut in_section = false;
        let mut line = [0u8; INI_BUFFER_SIZE];
        let mut run = |state: &ServerState, backend: &mut dyn AnyBackend, bytes: &[u8]| {
            if let Some(directive) = ini_line(bytes, &mut in_section, module_path, drive_path) {
                match directive {
                    IniDirective::OutputPath(value) => {
                        match state.filesystem.drives.translate(backend, value) {
                            Some(object) => {
                                apply(state, backend, IniDirective::OutputPath(object.as_bytes()))
                            }
                            None => apply(state, backend, directive),
                        }
                    }
                    directive => apply(state, backend, directive),
                }
            }
        };
        let mut count = 0usize;
        loop {
            if count != 0 {
                let mut start = 0;
                let mut position = 0;
                while position < count {
                    if matches!(backend.pool(buffer)[position], b'\n' | b'\r') {
                        let length = position - start;
                        line[..length].copy_from_slice(&backend.pool(buffer)[start..position]);
                        run(state, backend, &line[..length]);
                        start = position + 1;
                    }
                    position += 1;
                }
                // The byte past the data is taken as nonzero.
                if start < count && backend.pool(buffer)[start] == 0 {
                    break;
                }
                if start != 0 {
                    backend.pool(buffer).copy_within(start..count, 0);
                    count -= start;
                } else {
                    let length = count - 1;
                    line[..length].copy_from_slice(&backend.pool(buffer)[..length]);
                    run(state, backend, &line[..length]);
                    count = 0;
                }
            }
            let target = PoolRange {
                buffer,
                offset: count as u32,
                length: (INI_BUFFER_SIZE - count) as u32,
            };
            if let Ok(read) = backend.read_file(handle, None, target) {
                count += read as usize;
            }
            if count == 0 {
                break;
            }
        }
        backend.free_pool(buffer);
    }
    backend.close_file(handle);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn shape(
        format: BlockFormat,
        descriptors: &[TreeDescriptor],
    ) -> ModuleShape<core::iter::Copied<core::slice::Iter<'_, TreeDescriptor>>> {
        ModuleShape {
            format,
            module_word: 0x1234_5678,
            has_callers: true,
            count_slots: 0x30,
            list_count: 5,
            tree_count: descriptors.len() as u32,
            word_count: 3,
            scratch: 0,
            title_memory: 0,
            scale_bonus: false,
            allocation_scale: 1,
            descriptors: descriptors.iter().copied(),
        }
    }

    const DESCRIPTORS: [TreeDescriptor; 3] = [
        TreeDescriptor {
            counters: 4,
            lists: 0,
        },
        TreeDescriptor {
            counters: 2,
            lists: 3,
        },
        TreeDescriptor {
            counters: 0,
            lists: 1,
        },
    ];

    #[test]
    fn count_block_layouts() {
        let standard = CountBlockHeader::new(&shape(BlockFormat::Standard, &DESCRIPTORS));
        let extended = CountBlockHeader::new(&shape(BlockFormat::Extended, &DESCRIPTORS));
        let scaled = CountBlockHeader::new(&ModuleShape {
            scale_bonus: true,
            allocation_scale: 2,
            ..shape(BlockFormat::Standard, &DESCRIPTORS)
        });
        let capped = CountBlockHeader::new(&ModuleShape {
            title_memory: 0x1800,
            ..shape(BlockFormat::Extended, &DESCRIPTORS)
        });
        insta::assert_debug_snapshot!([standard, extended, scaled, capped]);
    }

    #[test]
    fn count_block_header_bytes() {
        let header = CountBlockHeader::new(&shape(BlockFormat::Extended, &DESCRIPTORS));
        let mut bytes = [0xeeu8; 0x78];
        header.encode(0x01d0_0000_0000_2710, &mut bytes);
        let text: String = bytes
            .chunks(16)
            .map(|row| format!("{:02x?}\n", row))
            .collect();
        insta::assert_snapshot!(text);
    }

    #[test]
    fn list_head_counter_wraps_after_sixteen_inserts() {
        let mut head = ListHead(0);
        for count in 1..=17u32 {
            head = head.advanced(count * 0x10);
            assert_eq!(head.counter(), count % 16);
            assert_eq!(head.offset(), count * 0x10);
        }
        assert_eq!(ListHead(0xc000_0003).advanced(0x40), ListHead(0x40));
    }

    #[test]
    fn tree_keys_reverse_and_invert() {
        assert_eq!(tree_key(0), 0xaaaa_aaaa);
        assert_eq!(tree_key(1), 0x2aaa_aaaa);
        assert_eq!(tree_key(0x8000_0000), 0xaaaa_aaab);
    }

    #[test]
    fn range_buckets() {
        let entries = [10u64, 20, 30, 40, 50];
        let table = RangeTable { count: 5, flags: 0 };
        let bucket = |value| table.bucket(value, |index| entries[index as usize]);
        // Exact matches reached without a downward step.
        assert_eq!(bucket(30), 6);
        assert_eq!(bucket(40), 8);
        // A downward step marks every later result as the gap below.
        assert_eq!(bucket(20), 3);
        assert_eq!(bucket(10), 1);
        assert_eq!(bucket(25), 3);
        assert_eq!(bucket(60), 11);
        let signed = RangeTable { count: 2, flags: 2 };
        let negative = [(-5i32) as u32 as u64, 5];
        assert_eq!(
            signed.bucket((-7i32) as u32 as u64, |index| negative[index as usize]),
            1
        );
        assert_eq!(
            RangeTable { count: 1, flags: 0 }.bucket(30, |index| [30u64][index as usize]),
            2
        );
        let empty = RangeTable { count: 0, flags: 0 };
        assert_eq!(empty.bucket(7, |_| 7), 2);
    }

    #[test]
    fn utf8_round_trips_and_marks_illegal_sequences() {
        let mut output = [0u16; 8];
        let decoded = decode_utf8("a\u{e9}\u{20ac}\u{1f600}\0".as_bytes(), &mut output);
        assert_eq!(
            decoded,
            Decoded {
                units: Ok(6),
                illegal: 0
            }
        );
        assert_eq!(&output[..6], &[0x61, 0xe9, 0x20ac, 0xd83d, 0xde00, 0]);
        let decoded = decode_utf8(&[0xc3, 0x41, 0x80, 0], &mut output);
        assert_eq!(
            decoded,
            Decoded {
                units: Ok(3),
                illegal: 1
            }
        );
        assert_eq!(&output[..3], &[0x81, 0x80, 0]);
        // A sequence may take the terminator as a continuation byte.
        assert_eq!(
            decode_utf8(&[0x41, 0xe2, 0x82, 0], &mut output),
            Decoded {
                units: Ok(2),
                illegal: 1
            }
        );
        // One that would run past it ends the conversion.
        assert_eq!(
            decode_utf8(&[0x41, 0xe2, 0], &mut output),
            Decoded {
                units: Ok(1),
                illegal: 0
            }
        );
        assert_eq!(
            decode_utf8(b"abc\0", &mut output[..2]).units,
            Err(BufferTooSmall)
        );
        let mut bytes = [0u8; 8];
        assert_eq!(encode_utf8(&[0x61, 0xe9, 0xd83d], &mut bytes), Ok(6));
        assert_eq!(&bytes[..6], &[0x61, 0xc3, 0xa9, 0xed, 0xa0, 0xbd]);
        assert_eq!(
            encode_utf8(&[0x20ac, 0x20ac, 0x20ac], &mut bytes),
            Err(BufferTooSmall)
        );
        assert_eq!(
            &bytes[..8],
            &[0xe2, 0x82, 0xac, 0xe2, 0x82, 0xac, 0xe2, 0x82]
        );
    }

    fn render(path: Result<WidePath, Fatal>) -> String {
        match path {
            Ok(path) => format!("{path:?}"),
            Err(fatal) => format!("{fatal:?}"),
        }
    }

    #[test]
    fn profile_paths() {
        let module = wide("\\Device\\Harddisk0\\Partition1\\DEVKIT\\Game\\Default.XEX");
        let results = [
            render(base_path(&wide("game/pgo"), &module)),
            render(base_path(&wide("d:\\pgo\\game"), &module)),
            render(base_path(
                &wide("\\pgo\\game"),
                &wide("e:\\dir\\default.xex"),
            )),
            render(base_path(&wide("pgo"), &wide("default.xex"))),
            render(base_path(&wide("pgo"), &[])),
            render(base_path(&wide(&"x".repeat(0x104)), &module)),
            render(base_path(&wide(&"x".repeat(0xd0)), &module)),
        ];
        insta::assert_debug_snapshot!(results);
    }

    #[test]
    fn profile_file_names() {
        let base = base_path(
            &wide("game"),
            &wide("\\Device\\Harddisk0\\Partition1\\DEVKIT\\default.xex"),
        )
        .unwrap();
        let mut phase = [0u16; PATH_UNITS];
        phase[..4].copy_from_slice(&wide("boot"));
        let mut names = Vec::new();
        let mut out = [0u8; FILE_NAME_BYTES];
        for (phase, number) in [(None, 1), (Some((&phase, &[][..])), 12)] {
            let name = ProfileName::new(&base, phase).unwrap();
            let length = name.file_name(number, &mut out);
            names.push(String::from_utf8_lossy(&out[..length]).into_owned());
        }
        let empty = [0u16; PATH_UNITS];
        let name = ProfileName::new(&base, Some((&empty, &[][..]))).unwrap();
        let length = name.file_name(3, &mut out);
        names.push(String::from_utf8_lossy(&out[..length]).into_owned());
        let wide_base =
            base_path(&wide("\u{e9}t\u{e9}"), &wide("\\Device\\x\\default.xex")).unwrap();
        let length = ProfileName::new(&wide_base, None)
            .unwrap()
            .file_name(1, &mut out);
        names.push(String::from_utf8_lossy(&out[..length]).into_owned());
        let long_phase = [u16::from(b'p'); PATH_UNITS];
        names.push(format!(
            "{:?}",
            ProfileName::new(&base, Some((&long_phase, &wide("x")))).err()
        ));
        names.push(format!("{:?}", fallback_path(&base)));
        insta::assert_debug_snapshot!(names);
    }

    #[test]
    fn output_path_replaces_directory() {
        let mut path = base_path(&wide("game"), &wide("\\Device\\Cdrom0\\default.xex")).unwrap();
        output_path(&mut path, b"\\Device\\Harddisk0\\Partition1\\DEVKIT/PGO\0");
        assert_eq!(
            format!("{path:?}"),
            "\"\\device\\harddisk0\\partition1\\devkit\\pgo\\game\""
        );
        output_path(&mut path, b"e:\\out\\\0");
        assert_eq!(format!("{path:?}"), "\"e:\\out\\game\"");
        let long = [b'a'; 0x104];
        let before = path;
        output_path(&mut path, &long);
        assert_eq!(path, before);
    }

    #[test]
    fn ini_lines() {
        let module = b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\game\\default.xex";
        let drive = b"DEVKIT:\\game\\default.xex";
        let lines: [&[u8]; 17] = [
            b"AllocScale=4",
            b"[other]",
            b"AllocScale=4",
            b"[DEFAULT.XEX]",
            b"alloc=3 ; comment",
            b"=2",
            b"AllocScale=x",
            b"AllocScale=",
            b"OutputPath=e:\\pgo",
            b"DisableDataCollection=1",
            b"DisableDataCollection=0",
            b"StandardPGC=1",
            b"MaxTitleMemory=-1",
            b"EnableSweepFullBuffer=0",
            b"; AllocScale=9",
            b"[devkit:\\game\\default.xex]",
            b"Validate=1",
        ];
        let mut in_section = false;
        let results: Vec<String> = lines
            .iter()
            .map(|line| {
                format!(
                    "{:?} {}",
                    ini_line(line, &mut in_section, module, drive).map(
                        |directive| match directive {
                            IniDirective::OutputPath(value) =>
                                format!("OutputPath({})", String::from_utf8_lossy(value)),
                            other => format!("{other:?}"),
                        }
                    ),
                    in_section
                )
            })
            .collect();
        insta::assert_debug_snapshot!(results);
        let mut in_section = true;
        ini_line(b"[a\\default.xex]", &mut in_section, module, drive);
        assert!(!in_section);
    }

    #[test]
    fn ini_numbers() {
        assert_eq!(ini_number(b" 42\t"), Some(42));
        assert_eq!(ini_number(b"42x"), None);
        assert_eq!(ini_number(b""), Some(0));
        assert_eq!(ini_number(b"-2"), Some(0xffff_fffe));
        assert_eq!(ini_number(b"99999999999"), Some(u32::MAX));
        assert_eq!(ini_number(b"-99999999999"), Some(1));
        assert_eq!(ini_number(b"x"), None);
    }
}
