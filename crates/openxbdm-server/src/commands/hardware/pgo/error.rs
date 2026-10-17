use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

/// `pogo.ini` cannot be located for the module path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadModulePath;

/// Result of export 107: `0x82da000c`.
impl From<BadModulePath> for Hresult {
    fn from(BadModulePath: BadModulePath) -> Self {
        ErrorCode::FilenameInvalid.hresult()
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

/// The output buffer was too small (error 0x7a); the units or bytes that
/// fit were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall;
