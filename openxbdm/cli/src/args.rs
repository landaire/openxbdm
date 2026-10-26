//! Command-line definitions and argument value parsing.

use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use openxbdm_client::ParseError;
use openxbdm_client::XBDM_PORT;
use openxbdm_client::commands::DataBreakKind;
use openxbdm_client::commands::MacAddress;
use openxbdm_client::commands::ThreadId;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::parity::ParityCommand;

#[derive(Parser, Debug)]
#[command(
    name = "xeedee",
    about = "Async-first XBDM (Xbox Debug Monitor) client",
    version
)]
pub struct Cli {
    /// Host, IP, or `host:port` of the target XBDM console.
    ///
    /// Accepts `192.168.1.26`, `192.168.1.26:730`, `deanxbox`,
    /// `deanxbox:730`, `[fe80::1]:730`, or a bare IPv6 literal. Not
    /// required for the `discover` and `resolve` subcommands.
    #[arg(short = 'H', long, env = "OPENXBDM_HOST", global = true)]
    pub host: Option<String>,

    /// Port override. Ignored when `--host` already carries a port.
    #[arg(short = 'p', long, default_value_t = XBDM_PORT, env = "OPENXBDM_PORT")]
    pub port: u16,

    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    /// Record the byte-level conversation to this file for later replay
    /// into tests via `MockTransport`.
    #[arg(long, value_name = "PATH")]
    pub capture: Option<PathBuf>,

    /// Tracing filter (e.g. `openxbdm_client=debug`). Defaults to `info`.
    #[arg(long, default_value = "info")]
    pub log: String,

    /// Disable progress bars on transfers. Automatically disabled when
    /// stderr isn't a TTY.
    #[arg(long, global = true)]
    pub no_progress: bool,

    /// Table output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Report file sizes as raw byte counts instead of humanised units
    /// (`1.23 MiB`). Memory/address sizes are always shown as hex.
    #[arg(long, global = true)]
    pub bytes: bool,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Broadcast an XBDM NAP discovery probe and list all consoles that
    /// reply within the listen window.
    Discover {
        /// Listen for replies for this many milliseconds after the probe.
        #[arg(long, default_value_t = 1500)]
        listen_ms: u64,
        /// Override the broadcast destination. Defaults to
        /// `255.255.255.255:730`.
        #[arg(long)]
        broadcast: Option<String>,
    },

    /// Resolve a named console to its IP via the NAP lookup protocol.
    Resolve {
        /// Console `dbgname` to resolve.
        name: String,
        /// Listen window in milliseconds.
        #[arg(long, default_value_t = 1500)]
        listen_ms: u64,
    },

    /// Open a connection, read the banner, and disconnect. Useful for
    /// validating reachability and generating an initial capture.
    Ping,

    /// Read or set the debuggable name of the console.
    Dbgname {
        /// New dbgname to write. Omit to just read the current value.
        #[arg(long)]
        set: Option<String>,
    },

    /// Report the console's clock as both a FILETIME and a SystemTime.
    Systime,

    /// Report the XBDM build identifier.
    Dmversion,

    /// Report the hardware kit type (retail/devkit/testkit).
    Consoletype,

    /// List the feature flags advertised by the kernel.
    Consolefeatures,

    /// List accessible drives.
    Drivelist,

    /// Report free/total bytes on a drive.
    Df {
        /// Drive root, e.g. `DEVKIT:\` or `E:\`.
        drive: String,
    },

    /// File-system operations (ls, tree, stat, get, put, ...).
    #[command(subcommand)]
    File(FileCommand),

    /// Show the alternate (debug) IPv4 address.
    Altaddr,

    /// Show the running title's process id.
    Getpid,

    /// Show the console memory class.
    Consolemem,

    /// Show the debug and title network-address blobs.
    Netaddrs,

    /// List loaded kernel and user modules.
    Modules,

    /// Read one loaded module to a host file without modifying console state.
    DumpModule {
        /// Module name as reported by `modules` (e.g. `xboxkrnl.exe`).
        module: String,
        /// Host output path.
        output: PathBuf,
    },

    /// List sections of a named module.
    Modsections {
        /// Module name as reported by `modules` (e.g. `xboxkrnl.exe`).
        module: String,
    },

    /// List live thread ids.
    Threads,

    /// Show detailed info for one thread id (hex, `0x...`).
    Threadinfo {
        /// Thread id in hex (e.g. `0xF8001234`).
        thread: String,
    },

    /// Show metadata for the currently running title (or a named xex).
    Xbeinfo {
        /// Path to a specific xex (e.g. `DEVKIT:\game.xex`). Omit for
        /// the running title.
        #[arg(long)]
        name: Option<String>,
    },

    /// Enumerate the console's virtual-address ranges.
    Walkmem,

    /// Read memory into a hex dump (and mark unmapped pages).
    Getmem {
        /// Starting virtual address (hex, `0x...`).
        address: String,
        /// Length in bytes (decimal or `0x...`).
        length: String,
    },

    /// List every performance counter the kernel and running title have
    /// registered, as `type<TAB>name` pairs. The set is dynamic: a
    /// freshly-booted dashboard typically exposes only a handful of
    /// counters (CPU, audio, net), and a running title may add many more
    /// (GPU pipeline stages, VMX usage, cmd-buffer bytes, etc.). Pipe
    /// into a counter name to `querypc` to sample it.
    Pclist,

    /// Sample a single performance counter by name. Returns the
    /// counter's type tag, its cumulative value, and its current rate
    /// (units depend on the counter). Names come from `pclist`; pass the
    /// matching `type` from that listing as `--kind`, or just leave the
    /// default if the counter only has one kind.
    ///
    /// Example:
    ///   xeedee pclist                         # discover names + types
    ///   xeedee querypc DX9Framerate --kind 1  # sample one
    #[command(verbatim_doc_comment)]
    Querypc {
        /// Counter name, exactly as it appears in the `name` column of
        /// `pclist` (case-sensitive). Quote it if it contains spaces.
        name: String,
        /// Counter-type selector (the `type` column from `pclist`).
        /// XBDM uses this to disambiguate counters that share a name
        /// but report different families of values. Most counters only
        /// expose one kind, so the default (`1`) usually works.
        #[arg(long, default_value_t = 1)]
        kind: u32,
    },

    /// List the active sockets of the console network stack.
    Sockets,

    /// Report whether a thread id is halted, and why.
    Isstopped {
        /// Thread id in hex (e.g. `0xF8001234`).
        thread: String,
    },

    /// Reboot the console.
    Reboot {
        /// Stop at the title entry point after the reboot.
        #[arg(long)]
        stop: bool,
        /// Wait for a debugger connection after the reboot.
        #[arg(long)]
        wait: bool,
        /// Reset through the system management controller.
        #[arg(long = "smcreset")]
        smc_reset: bool,
    },

    /// Launch a title, relaunching in place unless `--cold` is given.
    Magicboot {
        /// Always reboot the console.
        #[arg(long)]
        cold: bool,
        /// Wait for a debugger connection after a reboot.
        #[arg(long)]
        wait: bool,
        /// Stop at the title entry point after a reboot.
        #[arg(long)]
        stop: bool,
        /// Drive path of the title image.
        #[arg(long)]
        title: Option<String>,
        /// Drive path of the title directory.
        #[arg(long)]
        directory: Option<String>,
        /// Title command line.
        #[arg(long = "cmdline")]
        cmd_line: Option<String>,
    },

    /// Set (or clear via `--nopersist`) the default title.
    SetTitle {
        /// Clear the persistent default-title setting.
        #[arg(long)]
        nopersist: bool,
        /// Path to the xex to set as default title.
        #[arg(conflicts_with = "nopersist")]
        name: Option<String>,
    },

    /// Write bytes to console memory. Accepts a hex string of data.
    Setmem {
        /// Address (hex, `0x...`).
        address: String,
        /// Hex byte string (e.g. `DEADBEEF`). Must be even-length.
        hex: String,
    },

    /// Set or clear an execution breakpoint.
    Bp {
        /// Breakpoint address in hex (e.g. `0x8123ABCD`).
        address: String,
        /// Remove the breakpoint at `address` instead of setting it.
        #[arg(long)]
        clear: bool,
    },

    /// Set or clear the hardware data breakpoint (read / write / readwrite).
    Databp {
        /// Watched address in hex (e.g. `0x8123ABCD`).
        address: String,
        /// Size in bytes of the watched region (at most 8, within one
        /// aligned doubleword).
        size: u32,
        /// Access kind to trap on.
        #[arg(long, value_enum, default_value_t = DataBreakKindArg::Write)]
        kind: DataBreakKindArg,
        /// Remove the data breakpoint instead of setting it.
        #[arg(long)]
        clear: bool,
    },

    /// Capture a screenshot and save it as PNG (or raw framebuffer when
    /// `--raw` is set).
    Screenshot {
        /// Destination path. `.png` for a PNG (default). Pass `--raw` to
        /// emit the raw framebuffer bytes instead.
        #[arg(short, long, default_value = "screenshot.png")]
        output: String,
        /// Write the raw framebuffer bytes + a `.meta` sidecar instead
        /// of encoding a PNG. Useful for formats we haven't decoded yet.
        #[arg(long)]
        raw: bool,
    },

    /// Drive an xbmovie-style PIX! movie capture session against the
    /// title currently registered as the PIX handler (dash.xex,
    /// xshell.xex, or the running game). Emits intermediate capture
    /// segments to the console's HDD, downloads them back, and (by
    /// default) auto-converts each to H.264 MP4 via ffmpeg.
    #[cfg(feature = "capture")]
    Capture {
        /// Device-side filename. The path is sent verbatim to the PIX
        /// handler. xbmovie uses the full NT device form
        /// `\Device\Harddisk0\Partition1\DEVKIT\<name>.xbm` and the
        /// handler produces numbered segment files `<name>N.xbm`. The
        /// default matches xbmovie's.
        #[arg(
            long,
            default_value = r"\Device\Harddisk0\Partition1\DEVKIT\openxbdm_capture.xbm"
        )]
        remote: String,
        /// Per-segment size cap in megabytes. xbmovie's default is
        /// 12285 (effectively "whole HDD"); we match that.
        #[arg(long, default_value_t = 12285)]
        size_limit_mb: u32,
        /// Capture duration in seconds. If unset, capture runs until
        /// Enter is pressed.
        #[arg(long)]
        duration: Option<u64>,
        /// Local directory to drop downloaded segments into.
        #[arg(long, default_value = "./openxbdm-capture")]
        output_dir: String,
        /// Skip the automatic `.xbm` -> `.mp4` conversion and leave
        /// the raw intermediate files in place for later processing.
        /// Without this flag the command shells out to ffmpeg after
        /// download, encodes each segment alongside as `<name>.mp4`,
        /// and deletes the `.xbm` on success.
        #[arg(long)]
        no_conversion: bool,
    },

    /// Send a raw `pixcmd <subcommand>` (the PIX performance profiler,
    /// not video capture) and print the reply. Used for poking at the
    /// xbdm-resident profiler subsystem.
    #[cfg(feature = "capture")]
    PixcmdProbe {
        /// Positional subcommand, e.g. `v 0 0 0 0`. Sent verbatim
        /// after `pixcmd `.
        subcommand: String,
    },

    /// Listen to the xbdm notification channel and log every line
    /// tagged with its parsed classification (capture notifications,
    /// PIX profiler events, or raw). Useful to correlate commands
    /// with the async events they emit.
    #[cfg(feature = "capture")]
    PixNotify {
        /// How long to listen (seconds). 0 = until Ctrl-C.
        #[arg(long, default_value_t = 0)]
        duration: u64,
        /// Also tee every line to this file.
        #[arg(long)]
        log: Option<String>,
    },

    /// Operate on a local `.xbm` capture file (xbmovie intermediate
    /// format produced by the `capture` subcommand).
    #[cfg(feature = "capture")]
    #[command(subcommand)]
    Xbm(XbmCommand),

    /// Send a raw command line and print the parsed response.
    Raw {
        /// The command line to send (no trailing CRLF).
        line: String,
    },

    /// Route debug exceptions to the kernel debugger or the debug monitor.
    #[command(subcommand)]
    Kd(KdCommand),

    /// Set or clear the persistent kernel debugger lite setting. Both
    /// subcommands write the console configuration.
    #[command(subcommand)]
    Kdlite(KdLiteCommand),

    /// Read or change the network kernel debugger record. `set`,
    /// `enable` and `disable` write the console flash.
    #[command(subcommand)]
    Kdnet(KdNetCommand),

    /// Record replies to a command list, or compare two recordings.
    #[command(subcommand)]
    Parity(ParityCommand),

    /// Dangerous, low-level operations that write into xbdm's memory
    /// image. Each subcommand is gated behind the `dangerous` feature
    /// and documented with what it touches.
    #[cfg(feature = "dangerous")]
    #[command(subcommand)]
    Dangerous(DangerousCommand),
}

#[derive(Subcommand, Debug)]
pub enum FileCommand {
    /// List a directory's entries.
    Ls {
        /// Remote path, e.g. `DEVKIT:\`. Quote paths in your shell: 'DEVKIT:\'.
        path: String,

        /// Field to sort by.
        #[arg(long, value_enum, default_value_t = LsSortBy::Name)]
        sort_by: LsSortBy,

        /// Sort direction.
        #[arg(long, value_enum, default_value_t = SortOrder::Desc)]
        sort_order: SortOrder,
    },

    /// Recursively enumerate a directory tree. With no path, walks every
    /// drive returned by `drivelist`.
    Tree {
        /// Remote path (e.g. `DEVKIT:\`). Omit to walk every drive.
        /// Quote paths in your shell: 'DEVKIT:\'.
        path: Option<String>,
        /// Maximum recursion depth. 0 means unlimited.
        #[arg(long, default_value_t = 0u32)]
        max_depth: u32,
        /// Hide files and print only directories (like `tree -d`). Off
        /// by default, so leaf files are shown alongside directories.
        #[arg(long = "dirs-only", short = 'd')]
        dirs_only: bool,
    },

    /// Show metadata for a remote file or directory.
    Stat {
        /// Remote path.
        path: String,
    },

    /// Create a remote directory.
    Mkdir {
        /// Remote directory path to create (e.g. `DEVKIT:\new`).
        path: String,
    },

    /// Delete a remote file (or directory with `--dir`).
    Rm {
        /// Remote path to delete.
        path: String,
        /// Target is a directory; required to delete non-empty dirs.
        #[arg(long)]
        dir: bool,
    },

    /// Rename / move a remote path.
    Mv {
        /// Source remote path.
        from: String,
        /// Destination remote path.
        to: String,
    },

    /// Download a file (or, with `-r`, a directory tree) from the console.
    Get {
        /// Remote path to download.
        remote: String,
        /// Local destination. For a file, defaults to the remote's
        /// basename in the current directory; if this names an existing
        /// directory the file is written inside it. For a recursive
        /// download, defaults to a new directory named after the
        /// remote's basename in the current directory.
        #[arg(short, long)]
        output: Option<String>,
        /// Recursively download a directory tree, mirroring it under
        /// the local destination.
        #[arg(short, long)]
        recursive: bool,
        /// Optional start offset. Without `--size`, reads to the end of
        /// the file. File mode only.
        #[arg(long)]
        offset: Option<u32>,
        /// Optional byte count; requires `--offset`. File mode only.
        #[arg(long, requires = "offset")]
        size: Option<NonZeroU32>,
    },

    /// Upload a local file to a console path.
    Put {
        /// Local source file.
        local: String,
        /// Remote destination path.
        remote: String,
    },

    /// Write a local file's contents to a byte range of an existing
    /// console file.
    Writeto {
        /// Local source file whose bytes will be written.
        local: String,
        /// Existing remote file to patch.
        remote: String,
        /// Byte offset in the remote file where the write begins.
        offset: u32,
        /// Number of bytes to read from `local` and write.
        length: u32,
    },

    /// Set the end of file of a file on the console.
    Fileeof {
        /// Remote file path.
        path: String,
        /// New end-of-file size in bytes.
        size: u32,
        /// Create the file; fail if it already exists.
        #[arg(long, conflicts_with = "cancreate")]
        mustcreate: bool,
        /// Create the file if it is missing; an existing file is truncated
        /// before the size is applied.
        #[arg(long)]
        cancreate: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum KdCommand {
    /// Pass debug exceptions to the kernel debugger.
    Enable,
    /// Handle debug exceptions in the debug monitor.
    Disable,
    /// Enable the kernel debugger, then release every stopped thread.
    Except,
    /// Perform `except` only when a kernel debugger is present.
    Exceptif,
}

#[derive(Subcommand, Debug)]
pub enum KdLiteCommand {
    /// Enable kernel debugger lite. Writes the console configuration.
    Enable,
    /// Disable kernel debugger lite. Writes the console configuration.
    Disable,
}

#[derive(Subcommand, Debug)]
pub enum KdNetCommand {
    /// Print the network kernel debugger record stored in flash.
    Show,
    /// Set the record's enable field. Writes the console flash.
    Enable,
    /// Clear the record's enable field. Writes the console flash.
    Disable,
    /// Write the debugger host address, port and target MAC, and set the
    /// enable field. Writes the console flash.
    Set {
        /// IPv4 address of the debugger host.
        #[arg(long)]
        ip: Ipv4Addr,
        /// UDP port of the debugger host.
        #[arg(long)]
        port: u16,
        /// Target MAC address, `AA-BB-CC-DD-EE-FF`. When omitted, the
        /// stored MAC is kept; an all-zero stored MAC is replaced by the
        /// console MAC with its last octet decremented.
        #[arg(long, value_name = "AA-BB-CC-DD-EE-FF")]
        mac: Option<MacAddress>,
    },
}

#[cfg(feature = "capture")]
#[derive(Subcommand, Debug)]
pub enum XbmCommand {
    /// Print the .xbm file's top-level header plus a summary of
    /// frame records (count, total duration, audio bytes).
    Info {
        /// Path to the `.xbm` file on the local filesystem.
        file: String,
    },
    /// Extract each frame's pixel data into a sequence of raw
    /// files. By default the on-device tiled layout is converted to
    /// plain NV12 so ffmpeg can consume the result directly.
    Extract {
        /// Path to the `.xbm` file on the local filesystem.
        file: String,
        /// Output directory; created if missing.
        #[arg(short, long, default_value = "./xbm-frames")]
        output_dir: String,
        /// Concatenate all frames into a single `frames.nv12` (or
        /// `.tiled` for `--raw`) alongside the per-frame files.
        #[arg(long)]
        concat: bool,
        /// Skip detiling; emit the raw on-device 16-wide column
        /// layout verbatim. Only useful for format research.
        #[arg(long)]
        raw: bool,
    },

    /// Encode a `.xbm` to an MP4 (or anything ffmpeg groks) by
    /// streaming detiled NV12 frames to ffmpeg over stdin. No
    /// temporary files. Requires `ffmpeg` on $PATH.
    Encode {
        /// Source `.xbm` file.
        file: String,
        /// Output file. Extension picks the container (e.g.
        /// `out.mp4`, `out.mkv`).
        #[arg(short, long, default_value = "capture.mp4")]
        output: String,
        /// Crop the aligned frame down to the meaningful pixel
        /// rectangle before encoding. Default is the header's
        /// `frame_width x frame_height` (drops the 32-alignment
        /// tail). Set to `source` to crop to the smaller
        /// `source_width x source_height` rectangle instead, or
        /// `none` for the full aligned frame.
        #[arg(long, default_value = "frame")]
        crop: String,
        /// Override the computed fps. Leave at 0 to use the value
        /// derived from the file's timestamp span.
        #[arg(long, default_value_t = 0.0)]
        fps: f64,
        /// x264 quality (lower = better, ~18-23 typical).
        #[arg(long, default_value_t = 20)]
        crf: u32,
        /// Extra ffmpeg args appended verbatim before the output
        /// file. Useful for `-ss`, `-t`, `-vf` filters, etc.
        #[arg(long)]
        ffmpeg_args: Vec<String>,
    },
}

#[cfg(feature = "dangerous")]
#[derive(Subcommand, Debug)]
pub enum DangerousCommand {
    /// Enable `drivemap internal=1` for this session by calling xbdm's
    /// own symlink-setup routine via a one-shot command-table swap. No
    /// flash writes; the effect lasts until reboot.
    DrivemapEnable,
    /// Report current state of the drivemap flag + visible drives.
    DrivemapStatus,
    /// Write `[xbdm]\r\ndrivemap internal=1\r\n` to `FLASH:\recint.ini`
    /// so the setting survives reboots. Requires `drivemap-enable` to
    /// have been run already so `FLASH:` is mounted.
    DrivemapPersist,
    /// Dump the raw NAND flash image by `getfile`-ing `FLASH:\`. Makes
    /// sure the internal drivemap is enabled first (running the enable
    /// flow if it isn't already).
    NandDump {
        /// Local file to write. Defaults to `nand.bin` in the current
        /// directory.
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Tab-separated values. Parse-friendly, no color, no borders.
    Plain,
    /// Boxed tables with light color accents via `tabled` + `owo-colors`.
    Pretty,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LsSortBy {
    /// Alphabetical by entry name (case-insensitive).
    Name,
    /// Numeric by file size. Directories compare as zero.
    Size,
    /// Group by kind: directories first (or last, depending on order).
    Kind,
    /// Last-change timestamp.
    Modified,
    /// Creation timestamp.
    Created,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SortOrder {
    /// Ascending (A-Z, smallest first, oldest first).
    Asc,
    /// Descending (Z-A, largest first, newest first).
    Desc,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum DataBreakKindArg {
    Read,
    Write,
    #[value(alias = "rw")]
    Readwrite,
}

impl From<DataBreakKindArg> for DataBreakKind {
    fn from(kind: DataBreakKindArg) -> Self {
        match kind {
            DataBreakKindArg::Read => Self::Read,
            DataBreakKindArg::Write => Self::Write,
            DataBreakKindArg::Readwrite => Self::ReadWrite,
        }
    }
}

/// Decode an even-length string of hex digit pairs.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, Error> {
    let invalid = || Error::from(ParseError::InvalidHexDigits { key: "hex-bytes" });

    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(invalid());
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks(2) {
        let digits = core::str::from_utf8(pair).map_err(|_| invalid())?;
        bytes.push(u8::from_str_radix(digits, 16).map_err(|_| invalid())?);
    }

    Ok(bytes)
}

/// Parse a decimal number, or a hex number with a `0x` prefix.
pub fn parse_u32(input: &str) -> Result<u32, Error> {
    let trimmed = input.trim();
    let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    else {
        return trimmed
            .parse::<u32>()
            .map_err(|_| Error::from(ParseError::InvalidDecimalU32 { key: "cli" }));
    };

    u32::from_str_radix(hex, 16)
        .map_err(|_| Error::from(ParseError::InvalidHexDigits { key: "cli" }))
}

pub fn parse_thread_id(input: &str) -> Result<ThreadId, Report<Error>> {
    parse_u32(input)
        .map(ThreadId)
        .map_err(Report::new)
        .attach_with(|| format!("invalid thread id {input:?}"))
}
