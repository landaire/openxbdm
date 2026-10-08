use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use indicatif::ProgressBar;
use owo_colors::OwoColorize;
use rootcause::prelude::*;
use tokio::io::AsyncWriteExt;
use tabled::Tabled;

mod ui;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use xeedee::commands::AltAddr;
use xeedee::commands::Breakpoint;
use xeedee::commands::DataBreakKind;
use xeedee::commands::DataBreakpoint;
use xeedee::commands::DbgName;
use xeedee::commands::Delete;
use xeedee::commands::DirList;
use xeedee::commands::DmVersion;
use xeedee::commands::DriveFreeSpace;
use xeedee::commands::DriveList;
use xeedee::commands::FileEof;
use xeedee::commands::FileUploadKind;
use xeedee::commands::GetConsoleFeatures;
use xeedee::commands::GetConsoleMem;
use xeedee::commands::GetConsoleType;
use xeedee::commands::GetFileAttributes;
use xeedee::commands::GetFileRange;
use xeedee::commands::GetMem;
use xeedee::commands::GetNetAddrs;
use xeedee::commands::GetPid;
use xeedee::commands::GetSocketInfo;
use xeedee::commands::IsStopped;
use xeedee::commands::MakeDirectory;
use xeedee::commands::ModuleSections;
use xeedee::commands::Modules;
use xeedee::commands::PerfCounterList;
use xeedee::commands::QueryPerfCounter;
use xeedee::commands::Reboot;
use xeedee::commands::RebootFlags;
use xeedee::commands::Rename;
use xeedee::commands::SetMem;
use xeedee::commands::SysTime;
use xeedee::commands::ThreadId;
use xeedee::commands::ThreadInfo;
use xeedee::commands::Threads;
use xeedee::commands::Title;
use xeedee::commands::WalkMem;
use xeedee::commands::XbeInfo;
#[cfg(feature = "dangerous")]
use xeedee::commands::dangerous::drivemap as dm;
#[cfg(feature = "capture")]
use xeedee::commands::pix::CaptureSession;
#[cfg(feature = "capture")]
use xeedee::commands::pix::Notification;
#[cfg(feature = "capture")]
use xeedee::commands::pix::PixCmd;
use xeedee::error::Error;
use xeedee::transport::CaptureLog;
use xeedee::transport::RecordingTransport;

use xeedee::Client;
use xeedee::XBDM_PORT;
use xeedee::discovery::DiscoveryConfig;
use xeedee::discovery::NAP_PORT;
use xeedee::discovery::discover_all;
use xeedee::discovery::find_by_name;
use xeedee::transport::tokio::Target;
use xeedee::transport::tokio::connect_target_timeout;

#[derive(Parser, Debug)]
#[command(
    name = "xeedee",
    about = "Async-first XBDM (Xbox Debug Monitor) client",
    version
)]
struct Cli {
    /// Host, IP, or `host:port` of the target XBDM console.
    ///
    /// Accepts `192.168.1.26`, `192.168.1.26:730`, `deanxbox`,
    /// `deanxbox:730`, `[fe80::1]:730`, or a bare IPv6 literal. Not
    /// required for the `discover` and `resolve` subcommands.
    #[arg(short = 'H', long, env = "XEEDEE_HOST", global = true)]
    host: Option<String>,

    /// Port override. Ignored when `--host` already carries a port.
    #[arg(short = 'p', long, default_value_t = XBDM_PORT, env = "XEEDEE_PORT")]
    port: u16,

    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Record the byte-level conversation to this file for later replay
    /// into tests via `MockTransport`.
    #[arg(long, value_name = "PATH")]
    capture: Option<PathBuf>,

    /// Tracing filter (e.g. `xeedee=debug`). Defaults to `info`.
    #[arg(long, default_value = "info")]
    log: String,

    /// Disable progress bars on transfers. Automatically disabled when
    /// stderr isn't a TTY.
    #[arg(long, global = true)]
    no_progress: bool,

    /// Table output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,

    /// Report file sizes as raw byte counts instead of humanised units
    /// (`1.23 MiB`). Memory/address sizes are always shown as hex.
    #[arg(long, global = true)]
    bytes: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    /// Tab-separated values. Parse-friendly, no color, no borders.
    Plain,
    /// Boxed tables with light color accents via `tabled` + `owo-colors`.
    Pretty,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum LsSortBy {
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
enum SortOrder {
    /// Ascending (A-Z, smallest first, oldest first).
    Asc,
    /// Descending (Z-A, largest first, newest first).
    Desc,
}

#[derive(Subcommand, Debug)]
enum Command {
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

    /// List the sockets XBDM is currently tracking.
    Sockets,

    /// Report whether a thread id is halted, and why.
    Isstopped {
        /// Thread id in hex (e.g. `0xF8001234`).
        thread: String,
    },

    /// Reboot the console. Flags may be combined.
    Reboot {
        /// Warm reboot: keep the current title loaded.
        #[arg(long)]
        warm: bool,
        /// Halt on entry so a debugger can attach before code runs.
        #[arg(long = "stop")]
        stop_on_start: bool,
        /// Reboot without the debug monitor attached.
        #[arg(long = "nodebug")]
        no_debug: bool,
        /// Block until the console comes back up on XBDM.
        #[arg(long)]
        wait: bool,
        /// Launch this title after reboot instead of the default.
        #[arg(long)]
        title: Option<String>,
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

    /// Set or clear a data-access breakpoint (read / write / rw / exec).
    Databp {
        /// Watched address in hex (e.g. `0x8123ABCD`).
        address: String,
        /// Size in bytes of the watched region.
        size: u32,
        /// Access kind to trap on: `read`, `write`, `readwrite`, or
        /// `execute` (default `write`).
        #[arg(long, default_value = "write")]
        kind: String,
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
            default_value = r"\Device\Harddisk0\Partition1\DEVKIT\xeedee_capture.xbm"
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
        #[arg(long, default_value = "./xeedee-capture")]
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

    /// Dangerous, low-level operations that write into xbdm's memory
    /// image. Each subcommand is gated behind the `dangerous` feature
    /// and documented with what it touches.
    #[cfg(feature = "dangerous")]
    #[command(subcommand)]
    Dangerous(DangerousCommand),
}

#[derive(Subcommand, Debug)]
enum FileCommand {
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
        /// Optional start offset. File mode only.
        #[arg(long)]
        offset: Option<u64>,
        /// Optional byte count (required if `--offset` is set). File
        /// mode only.
        #[arg(long)]
        size: Option<u64>,
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
        offset: u64,
        /// Number of bytes to read from `local` and write.
        length: u64,
    },

    /// Truncate or extend a file on the console.
    Fileeof {
        /// Remote file path.
        path: String,
        /// New end-of-file size in bytes.
        size: u64,
        /// Create the file if it doesn't already exist.
        #[arg(long)]
        create: bool,
    },
}

#[cfg(feature = "capture")]
#[derive(Subcommand, Debug)]
enum XbmCommand {
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
enum DangerousCommand {
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

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("error: {report:?}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct UiCtx {
    format: OutputFormat,
    no_progress: bool,
    raw_bytes: bool,
}

impl UiCtx {
    fn pretty(&self) -> bool {
        self.format == OutputFormat::Pretty
    }
    fn progress(&self, total: u64, label: &str) -> ProgressBar {
        ui::transfer_bar(total, label, self.no_progress)
    }
    fn fmt_bytes(&self, n: u64) -> String {
        if self.raw_bytes {
            n.to_string()
        } else {
            humanize_bytes(n)
        }
    }
    /// Render a `FileTime` for humans as a local-time ISO-8601 string
    /// ("2026-04-20 15:42:10"). Falls back to the raw FILETIME hex only
    /// if the value is outside jiff's representable range.
    fn fmt_time(&self, ft: xeedee::FileTime) -> String {
        match ft.into_jiff_timestamp() {
            Ok(ts) => ts
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string(),
            Err(_) => format!("{:#018x}", ft.as_raw()),
        }
    }
}

fn sort_dir_entries(
    entries: &mut [xeedee::commands::DirEntry],
    sort_by: LsSortBy,
    order: SortOrder,
) {
    use core::cmp::Ordering;
    entries.sort_by(|a, b| {
        let primary = match sort_by {
            LsSortBy::Name => a
                .name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase()),
            LsSortBy::Size => a.size.cmp(&b.size),
            LsSortBy::Kind => a.is_directory.cmp(&b.is_directory),
            LsSortBy::Modified => a.change_time.as_raw().cmp(&b.change_time.as_raw()),
            LsSortBy::Created => a.create_time.as_raw().cmp(&b.create_time.as_raw()),
        };
        let ordered = match order {
            SortOrder::Asc => primary,
            SortOrder::Desc => primary.reverse(),
        };
        if ordered != Ordering::Equal {
            return ordered;
        }
        // Stable tie-breaker: name ascending so adjacent equal keys stay readable.
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
}

fn humanize_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut idx = 0usize;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{v:.2} {}", UNITS[idx])
}

async fn run(cli: Cli) -> Result<(), rootcause::Report<Error>> {
    let ui = UiCtx {
        format: cli.format,
        no_progress: cli.no_progress,
        raw_bytes: cli.bytes,
    };

    match &cli.cmd {
        Command::Discover {
            listen_ms,
            broadcast,
        } => {
            return run_discover(*listen_ms, broadcast.as_deref(), ui).await;
        }
        Command::Resolve { name, listen_ms } => {
            return run_resolve(name, *listen_ms).await;
        }
        _ => {}
    }

    // `xbm` operates on local files only; no console connection needed.
    #[cfg(feature = "capture")]
    if let Command::Xbm(sub) = &cli.cmd {
        return run_xbm(sub).await;
    }

    let host = cli.host.as_deref().ok_or_else(|| {
        rootcause::Report::new(Error::from(xeedee::error::ArgumentError::EmptyFilename))
            .attach("--host is required for this subcommand")
    })?;
    let target = Target::parse(host, cli.port);
    let conn_timeout = Duration::from_secs(cli.timeout);
    tracing::info!(target: "xeedee", console = %target, "connecting");

    // drivemap-enable and nand-dump each need to open their own
    // connection(s) (enable abandons one with a hung read; nand-dump
    // may run enable internally first), so they bypass the shared
    // single-client flow and are not recorded under --capture.
    #[cfg(feature = "dangerous")]
    match &cli.cmd {
        Command::Dangerous(DangerousCommand::DrivemapEnable) => {
            return run_drivemap_enable(&target, conn_timeout).await;
        }
        Command::Dangerous(DangerousCommand::NandDump { output }) => {
            return run_nand_dump(&target, conn_timeout, output.clone(), ui).await;
        }
        _ => {}
    }

    #[cfg(feature = "capture")]
    match &cli.cmd {
        Command::PixNotify { duration, log } => {
            return run_pix_notify(&target, conn_timeout, *duration, log.clone()).await;
        }
        Command::Capture {
            remote,
            size_limit_mb,
            duration,
            output_dir,
            no_conversion,
        } => {
            return run_capture(
                &target,
                conn_timeout,
                remote.clone(),
                *size_limit_mb,
                duration.map(Duration::from_secs),
                output_dir.clone(),
                *no_conversion,
                ui,
            )
            .await;
        }
        _ => {}
    }

    let transport = connect_target_timeout(&target, conn_timeout).await?;

    if let Some(path) = cli.capture.clone() {
        let recording = RecordingTransport::new(transport);
        let log_handle = recording.log_handle();

        let outcome = drive(recording.into_client(), cli.cmd, ui).await;
        write_capture(&path, &log_handle)?;

        outcome
    } else {
        let client = Client::new(transport).read_banner().await?;
        drive_connected(client, cli.cmd, ui).await
    }
}

#[cfg(feature = "dangerous")]
async fn run_drivemap_enable(
    target: &Target,
    conn_timeout: Duration,
) -> Result<(), rootcause::Report<Error>> {
    let hijack_transport = connect_target_timeout(target, conn_timeout).await?;
    let hijack = Client::new(hijack_transport).read_banner().await?;

    let target_for_reconnect = target.clone();
    let reconnect = move || {
        let target = target_for_reconnect.clone();
        async move {
            let t = connect_target_timeout(&target, conn_timeout).await?;
            let c = Client::new(t).read_banner().await?;
            Ok::<_, rootcause::Report<Error>>(c)
        }
    };

    let report = dm::enable(hijack, reconnect, Duration::from_secs(3)).await?;
    if report.already_enabled {
        eprintln!(
            "{} drivemap flag already set; skipped hijack. {} drive{} visible.",
            ok_tag("no-op"),
            report.drives_after.len(),
            if report.drives_after.len() == 1 {
                ""
            } else {
                "s"
            }
        );
    } else {
        eprintln!(
            "{} drivemap internal enabled. drives went from {} -> {} entries.",
            ok_tag("done"),
            report.drives_before.len(),
            report.drives_after.len()
        );
    }
    for drive in &report.drives_after {
        println!("{drive}");
    }
    Ok(())
}

#[cfg(feature = "dangerous")]
async fn run_nand_dump(
    target: &Target,
    conn_timeout: Duration,
    output: Option<String>,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>> {
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("nand.bin"));

    // Quick probe: if FLASH is already in the drivelist we can skip the
    // hijack entirely. Saves the full .text/.rdata/.data readback that
    // dm::discover does.
    let probe_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut probe = Client::new(probe_transport).read_banner().await?;
    let drives = probe.run(DriveList).await.unwrap_or_default();
    let flash_visible = drives.iter().any(|d| d.eq_ignore_ascii_case("flash"));
    let _ = probe.bye().await;

    if !flash_visible {
        eprintln!(
            "{} FLASH: not mounted; running drivemap-enable first",
            warn_tag("note:")
        );
        let hijack_transport = connect_target_timeout(target, conn_timeout).await?;
        let hijack = Client::new(hijack_transport).read_banner().await?;
        let target_for_reconnect = target.clone();
        let reconnect = move || {
            let target = target_for_reconnect.clone();
            async move {
                let t = connect_target_timeout(&target, conn_timeout).await?;
                let c = Client::new(t).read_banner().await?;
                Ok::<_, rootcause::Report<Error>>(c)
            }
        };
        let report = dm::enable(hijack, reconnect, Duration::from_secs(3)).await?;
        if !report
            .drives_after
            .iter()
            .any(|d| d.eq_ignore_ascii_case("flash"))
        {
            return Err(rootcause::Report::new(Error::from(
                xeedee::error::ArgumentError::EmptyFilename,
            ))
            .attach("drivemap-enable completed but FLASH: is still not mounted"));
        }
    }

    let dl_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut dl_client = Client::new(dl_transport).read_banner().await?;
    // Bypass the stat-based directory check -- xbdm serves the raw
    // NAND image when `FLASH:\` is getfile'd even though stat reports
    // it as a directory.
    let DownloadResult { copied, total } = download_single_file(
        &mut dl_client,
        "FLASH:\\",
        &output_path,
        GetFileRange::WholeFile,
        ui,
    )
    .await?;
    eprintln!(
        "{} NAND dump: {copied} bytes ({total} declared) to {}",
        ok_tag("done"),
        output_path.display()
    );
    let _ = dl_client.bye().await;
    Ok(())
}

trait RecordingExt<T> {
    fn into_client(self) -> Client<RecordingTransport<T>>;
}

impl<T> RecordingExt<T> for RecordingTransport<T>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    fn into_client(self) -> Client<RecordingTransport<T>> {
        Client::new(self)
    }
}

async fn drive<T>(
    client: Client<T>,
    cmd: Command,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    let client = client.read_banner().await?;
    drive_connected(client, cmd, ui).await
}

async fn drive_connected<T>(
    mut client: Client<T, xeedee::Connected>,
    cmd: Command,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    // Each arm wraps its body in `Box::pin(async move { ... }).await?` so the
    // arm's state machine and resume frame live on the heap. Without this,
    // the giant `match cmd` collapses into a single async state machine whose
    // resume function overflows the main thread's 1 MiB stack on Windows in
    // debug builds. The per-arm `let client = &mut client;` reborrow lets the
    // `async move` block consume a mutable borrow without taking ownership of
    // the connection (which we still need for `client.bye()` after the match).
    match cmd {
        Command::Discover { .. } | Command::Resolve { .. } => unreachable!(),
        Command::Ping => {
            println!("connected");
        }
        Command::Dbgname { set } => {
            let client = &mut client;
            Box::pin(async move {
                let name = client
                    .run(match set {
                        Some(value) => DbgName::Set(value),
                        None => DbgName::Get,
                    })
                    .await?;
                println!("{name}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Systime => {
            let client = &mut client;
            Box::pin(async move {
                let result = client.run(SysTime).await?;
                println!("{}", ui.fmt_time(result.file_time));
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Dmversion => {
            let client = &mut client;
            Box::pin(async move {
                let version = client.run(DmVersion).await?;
                println!("{version}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Consoletype => {
            let client = &mut client;
            Box::pin(async move {
                let kind = client.run(GetConsoleType).await?;
                println!("{kind:?}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Consolefeatures => {
            let client = &mut client;
            Box::pin(async move {
                let features = client.run(GetConsoleFeatures).await?;
                for flag in features.flags {
                    println!("{flag}");
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Drivelist => {
            let client = &mut client;
            Box::pin(async move {
                let drives = client.run(DriveList).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row<'a> {
                        #[tabled(rename = "drive")]
                        name: &'a str,
                    }
                    let rows: Vec<Row<'_>> = drives.iter().map(|d| Row { name: d }).collect();
                    print_colored_table(&heading_label("drives", &ui), rows, &ui);
                } else {
                    for d in drives {
                        println!("{d}");
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Df { drive } => {
            let client = &mut client;
            Box::pin(async move {
                let space = client
                    .run(DriveFreeSpace {
                        drive: drive.clone(),
                    })
                    .await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        #[tabled(rename = "metric")]
                        key: String,
                        size: String,
                    }
                    let rows = vec![
                        Row {
                            key: "free_to_caller".into(),
                            size: ui.fmt_bytes(space.free_to_caller_bytes),
                        },
                        Row {
                            key: "total".into(),
                            size: ui.fmt_bytes(space.total_bytes),
                        },
                        Row {
                            key: "total_free".into(),
                            size: ui.fmt_bytes(space.total_free_bytes),
                        },
                    ];
                    print_colored_table(&heading_label(&format!("df {drive}"), &ui), rows, &ui);
                } else {
                    println!(
                        "free_to_caller={} total={} total_free={}",
                        ui.fmt_bytes(space.free_to_caller_bytes),
                        ui.fmt_bytes(space.total_bytes),
                        ui.fmt_bytes(space.total_free_bytes)
                    );
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::File(fc) => {
            let client = &mut client;
            Box::pin(async move {
                match fc {
                    FileCommand::Tree {
                        path,
                        max_depth,
                        dirs_only,
                    } => {
                        run_tree(client, path, max_depth, !dirs_only, ui).await?;
                    }
                    FileCommand::Ls {
                        path,
                        sort_by,
                        sort_order,
                    } => {
                        let mut entries = client.run(DirList { path: path.clone() }).await?;
                        sort_dir_entries(&mut entries, sort_by, sort_order);
                        if ui.pretty() {
                            #[derive(Tabled)]
                            struct Row {
                                name: String,
                                size: String,
                                kind: String,
                                #[tabled(rename = "changed")]
                                changed: String,
                            }
                            let rows: Vec<Row> = entries
                                .iter()
                                .map(|e| Row {
                                    name: e.name.clone(),
                                    size: if e.is_directory {
                                        "-".into()
                                    } else {
                                        ui.fmt_bytes(e.size)
                                    },
                                    kind: if e.is_directory {
                                        "DIR".into()
                                    } else {
                                        "FILE".into()
                                    },
                                    changed: ui.fmt_time(e.change_time),
                                })
                                .collect();
                            print_colored_table(
                                &heading_label(&format!("ls {path}"), &ui),
                                rows,
                                &ui,
                            );
                        } else {
                            for entry in entries {
                                println!(
                                    "{}\t{}\t{}\t{}",
                                    entry.name,
                                    if entry.is_directory {
                                        "-".into()
                                    } else {
                                        ui.fmt_bytes(entry.size)
                                    },
                                    if entry.is_directory { "DIR" } else { "FILE" },
                                    ui.fmt_time(entry.change_time),
                                );
                            }
                        }
                    }
                    FileCommand::Stat { path } => {
                        let attrs = client.run(GetFileAttributes { path }).await?;
                        println!(
                            "size={} created={} changed={} is_directory={}",
                            if attrs.is_directory {
                                "-".into()
                            } else {
                                ui.fmt_bytes(attrs.size)
                            },
                            ui.fmt_time(attrs.create_time),
                            ui.fmt_time(attrs.change_time),
                            attrs.is_directory,
                        );
                    }
                    FileCommand::Mkdir { path } => {
                        client.run(MakeDirectory { path }).await?;
                    }
                    FileCommand::Rm { path, dir } => {
                        client
                            .run(Delete {
                                path,
                                is_directory: dir,
                            })
                            .await?;
                    }
                    FileCommand::Mv { from, to } => {
                        client.run(Rename { from, to }).await?;
                    }
                    FileCommand::Get {
                        remote,
                        output,
                        recursive,
                        offset,
                        size,
                    } => {
                        let attrs = client
                            .run(GetFileAttributes {
                                path: remote.clone(),
                            })
                            .await
                            .ok();
                        let is_directory = attrs.as_ref().map(|a| a.is_directory).unwrap_or(false);

                        if is_directory {
                            if !recursive {
                                return Err(rootcause::Report::new(Error::from(
                                    xeedee::error::ArgumentError::EmptyFilename,
                                ))
                                .attach(format!(
                                    "{remote:?} is a directory; pass -r for recursive download"
                                )));
                            }
                            if offset.is_some() || size.is_some() {
                                return Err(rootcause::Report::new(Error::from(
                                    xeedee::error::ArgumentError::EmptyFilename,
                                ))
                                .attach(
                                    "--offset / --size are file-mode only, not valid with -r",
                                ));
                            }
                            let root = resolve_get_dir_output(&remote, output.as_deref())?;
                            tokio::fs::create_dir_all(&root)
                                .await
                                .map_err(Error::from)
                                .into_report()
                                .attach_with(|| {
                                    format!("creating local directory {}", root.display())
                                })?;
                            let mut stats = RecursiveGetStats::default();
                            download_dir_recursive(client, &remote, &root, ui, &mut stats).await?;
                            eprintln!(
                                "{} {} file{} ({} total) under {}",
                                ok_tag("downloaded"),
                                stats.files,
                                if stats.files == 1 { "" } else { "s" },
                                ui.fmt_bytes(stats.bytes),
                                root.display()
                            );
                        } else {
                            let range = match (offset, size) {
                                (Some(offset), Some(size)) => GetFileRange::Range { offset, size },
                                (None, None) => GetFileRange::WholeFile,
                                _ => {
                                    return Err(rootcause::Report::new(Error::from(
                                        xeedee::error::ArgumentError::EmptyFilename,
                                    ))
                                    .attach("--offset and --size must be provided together"));
                                }
                            };
                            let output_path = resolve_get_output(&remote, output.as_deref())?;
                            let DownloadResult { copied, total } =
                                download_single_file(client, &remote, &output_path, range, ui)
                                    .await?;
                            eprintln!(
                                "{} {copied} bytes ({total} declared) to {}",
                                ok_tag("downloaded"),
                                output_path.display()
                            );
                        }
                    }
                    FileCommand::Put { local, remote } => {
                        let metadata = std::fs::metadata(&local)
                            .map_err(Error::from)
                            .into_report()
                            .attach_with(|| format!("stat local file {local:?}"))?;
                        let size = metadata.len();
                        let mut file = tokio::fs::File::open(&local)
                            .await
                            .map_err(Error::from)
                            .into_report()
                            .attach_with(|| format!("opening local file {local:?}"))?;
                        let upload = client
                            .send_file(&remote, FileUploadKind::Create { size })
                            .await?;
                        let bar = ui.progress(size, "upload");
                        let compat = tokio_util::compat::TokioAsyncReadCompatExt::compat(&mut file);
                        let mut tracked = ProgressRead::new(compat, bar.clone());
                        upload.copy_from(&mut tracked).await?;
                        bar.finish_and_clear();
                        eprintln!("{} {size} bytes to {remote}", ok_tag("uploaded"));
                    }
                    FileCommand::Writeto {
                        local,
                        remote,
                        offset,
                        length,
                    } => {
                        let mut file = tokio::fs::File::open(&local)
                            .await
                            .map_err(Error::from)
                            .into_report()
                            .attach_with(|| format!("opening local file {local:?}"))?;
                        let upload = client
                            .send_file(
                                &remote,
                                FileUploadKind::WriteAt {
                                    offset,
                                    size: length,
                                },
                            )
                            .await?;
                        let bar = ui.progress(length, "write");
                        let compat = tokio_util::compat::TokioAsyncReadCompatExt::compat(&mut file);
                        let mut tracked = ProgressRead::new(compat, bar.clone());
                        upload.copy_from(&mut tracked).await?;
                        bar.finish_and_clear();
                        eprintln!(
                            "{} {length} bytes at offset {offset} in {remote}",
                            ok_tag("wrote")
                        );
                    }
                    FileCommand::Fileeof { path, size, create } => {
                        client
                            .run(FileEof {
                                path,
                                size,
                                create_if_missing: create,
                            })
                            .await?;
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Altaddr => {
            let client = &mut client;
            Box::pin(async move {
                let addr = client.run(AltAddr).await?;
                println!("{addr}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Getpid => {
            let client = &mut client;
            Box::pin(async move {
                let pid = client.run(GetPid).await?;
                println!("{pid:#010x}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Consolemem => {
            let client = &mut client;
            Box::pin(async move {
                let mem = client.run(GetConsoleMem).await?;
                println!("class={:#04x}", mem.class);
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Netaddrs => {
            let client = &mut client;
            Box::pin(async move {
                let na = client.run(GetNetAddrs).await?;
                println!("name={}", na.name);
                println!("debug={}", hex_dump(&na.debug));
                println!("title={}", hex_dump(&na.title));
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Modules => {
            let client = &mut client;
            Box::pin(async move {
                let mods = client.run(Modules).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        name: String,
                        base: String,
                        end: String,
                        size: String,
                        check: String,
                        #[tabled(rename = "dll")]
                        dll: &'static str,
                        osize: String,
                    }
                    let rows: Vec<Row> = mods
                        .iter()
                        .map(|m| Row {
                            name: m.name.clone(),
                            base: format!("{:#010x}", m.base),
                            end: format!("{:#010x}", m.base.wrapping_add(m.size)),
                            size: format!("{:#010x}", m.size),
                            check: format!("{:#010x}", m.checksum),
                            dll: if m.is_dll { "yes" } else { "no" },
                            osize: format!("{:#010x}", m.osize),
                        })
                        .collect();
                    print_colored_table(&heading_label("modules", &ui), rows, &ui);
                } else {
                    for m in mods {
                        println!(
                            "{}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{}\t{:#010x}",
                            m.name,
                            m.base,
                            m.base.wrapping_add(m.size),
                            m.size,
                            m.checksum,
                            m.is_dll,
                            m.osize
                        );
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::DumpModule { module, output } => {
            let client = &mut client;
            Box::pin(async move {
                let modules = client.run(Modules).await?;
                let module_info = modules
                    .into_iter()
                    .find(|candidate| candidate.name.eq_ignore_ascii_case(&module))
                    .ok_or_else(|| {
                        rootcause::Report::new(Error::ModuleNotFound {
                            name: module.clone(),
                        })
                    })?;
                if module_info.size == 0 {
                    return Err(rootcause::Report::new(Error::EmptyModule {
                        name: module_info.name,
                    }));
                }
                module_info
                    .base
                    .checked_add(module_info.size - 1)
                    .ok_or_else(|| {
                        rootcause::Report::new(Error::ModuleRangeOverflow {
                            base: module_info.base,
                            size: module_info.size,
                        })
                    })?;

                let mut file = tokio::fs::File::create(&output)
                    .await
                    .map_err(Error::from)
                    .into_report()
                    .attach_with(|| format!("creating module dump {output:?}"))?;
                let bar = ui.progress(module_info.size as u64, "read");
                let mut offset = 0u32;
                while offset < module_info.size {
                    let length = (module_info.size - offset).min(0x1000);
                    let address = module_info
                        .base
                        .checked_add(offset)
                        .expect("module range was validated");
                    let snapshot = client.run(GetMem { address, length }).await?;
                    if let Some(relative) = snapshot.unmapped_offsets.first() {
                        return Err(rootcause::Report::new(Error::UnmappedModuleMemory {
                            address: address + relative,
                        }));
                    }
                    file.write_all(&snapshot.data)
                        .await
                        .map_err(Error::from)
                        .into_report()
                        .attach_with(|| format!("writing module dump {output:?}"))?;
                    offset += length;
                    bar.set_position(offset as u64);
                }
                file.flush()
                    .await
                    .map_err(Error::from)
                    .into_report()
                    .attach_with(|| format!("flushing module dump {output:?}"))?;
                bar.finish_and_clear();
                eprintln!(
                    "{} {} bytes from {} at {:#010x}",
                    ok_tag("dumped"),
                    module_info.size,
                    module_info.name,
                    module_info.base
                );
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Modsections { module } => {
            let client = &mut client;
            Box::pin(async move {
                let sections = client
                    .run(ModuleSections {
                        module: module.clone(),
                    })
                    .await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        name: String,
                        base: String,
                        size: String,
                        idx: u32,
                        flags: String,
                        #[tabled(rename = "rwxu")]
                        perms: String,
                    }
                    let rows: Vec<Row> = sections
                        .iter()
                        .map(|s| Row {
                            name: s.name.clone(),
                            base: format!("{:#010x}", s.base),
                            size: format!("{:#010x}", s.size),
                            idx: s.index,
                            flags: format!("{:#x}", s.flags.0),
                            perms: format!(
                                "{}{}{}{}",
                                if s.flags.readable() { 'r' } else { '-' },
                                if s.flags.writable() { 'w' } else { '-' },
                                if s.flags.executable() { 'x' } else { '-' },
                                if s.flags.uninitialized() { 'u' } else { '-' },
                            ),
                        })
                        .collect();
                    print_colored_table(
                        &heading_label(&format!("modsections {module}"), &ui),
                        rows,
                        &ui,
                    );
                } else {
                    for s in sections {
                        println!(
                            "{}\t{:#010x}\t{:#010x}\t{}\t{:#x}\t{}{}{}{}",
                            s.name,
                            s.base,
                            s.size,
                            s.index,
                            s.flags.0,
                            if s.flags.readable() { 'r' } else { '-' },
                            if s.flags.writable() { 'w' } else { '-' },
                            if s.flags.executable() { 'x' } else { '-' },
                            if s.flags.uninitialized() { 'u' } else { '-' },
                        );
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Threads => {
            let client = &mut client;
            Box::pin(async move {
                let tids = client.run(Threads).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        #[tabled(rename = "thread id")]
                        id: String,
                    }
                    let rows: Vec<Row> = tids.iter().map(|t| Row { id: format!("{t}") }).collect();
                    print_colored_table(&heading_label("threads", &ui), rows, &ui);
                } else {
                    for t in tids {
                        println!("{t}");
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Threadinfo { thread } => {
            let client = &mut client;
            Box::pin(async move {
                let id = parse_thread_id(&thread)?;
                let info = client.run(ThreadInfo { thread: id }).await?;
                println!("{info:#?}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Xbeinfo { name } => {
            let client = &mut client;
            Box::pin(async move {
                let cmd = match name {
                    Some(path) => XbeInfo::Named(path),
                    None => XbeInfo::Running,
                };
                let info = client.run(cmd).await?;
                println!("name={}", info.name);
                println!("timestamp={:#010x}", info.timestamp);
                println!("checksum={:#010x}", info.checksum);
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Walkmem => {
            let client = &mut client;
            Box::pin(async move {
                let regions = client.run(WalkMem).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        base: String,
                        size: String,
                        protect: String,
                    }
                    let rows: Vec<Row> = regions
                        .iter()
                        .map(|r| Row {
                            base: format!("{:#010x}", r.base),
                            size: format!("{:#010x}", r.size),
                            protect: format!("{:#010x}", r.protect),
                        })
                        .collect();
                    print_colored_table(&heading_label("walkmem", &ui), rows, &ui);
                } else {
                    for region in regions {
                        println!(
                            "base={:#010x} size={:#010x} protect={:#010x}",
                            region.base, region.size, region.protect
                        );
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Getmem { address, length } => {
            let client = &mut client;
            Box::pin(async move {
                let addr = parse_u32(&address).map_err(|e| attach_hint(e, "--address"))?;
                let len = parse_u32(&length).map_err(|e| attach_hint(e, "--length"))?;
                let snap = client
                    .run(GetMem {
                        address: addr,
                        length: len,
                    })
                    .await?;
                print_hex_dump(snap.address, &snap.data, &snap.unmapped_offsets);
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Pclist => {
            let client = &mut client;
            Box::pin(async move {
                let counters = client.run(PerfCounterList).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        #[tabled(rename = "type")]
                        kind: String,
                        name: String,
                    }
                    let rows: Vec<Row> = counters
                        .iter()
                        .map(|c| Row {
                            kind: format!("{:#010x}", c.kind),
                            name: c.name.clone(),
                        })
                        .collect();
                    print_colored_table(&heading_label("pclist", &ui), rows, &ui);
                } else {
                    for c in counters {
                        println!("{:#010x}\t{}", c.kind, c.name);
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Querypc { name, kind } => {
            let client = &mut client;
            Box::pin(async move {
                let sample = client.run(QueryPerfCounter { name, kind }).await?;
                println!(
                    "type={:#010x} value={} rate={}",
                    sample.kind, sample.value, sample.rate
                );
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Sockets => {
            let client = &mut client;
            Box::pin(async move {
                let sockets = client.run(GetSocketInfo).await?;
                if ui.pretty() {
                    #[derive(Tabled)]
                    struct Row {
                        handle: String,
                        af: u32,
                        #[tabled(rename = "type")]
                        sock_type: u32,
                        proto: u32,
                        local: String,
                        remote: String,
                        tcpstate: u32,
                        flags: String,
                    }
                    let rows: Vec<Row> = sockets
                        .iter()
                        .map(|s| Row {
                            handle: format!("{:#010x}", s.handle),
                            af: s.addr_family,
                            sock_type: s.socket_type,
                            proto: s.protocol,
                            local: format!("{:#010x}:{:#06x}", s.local_addr, s.local_port),
                            remote: format!("{:#010x}:{:#06x}", s.remote_addr, s.remote_port),
                            tcpstate: s.tcp_state,
                            flags: format!("{:#010x}", s.flags),
                        })
                        .collect();
                    print_colored_table(&heading_label("sockets", &ui), rows, &ui);
                } else {
                    for s in sockets {
                        println!(
                            "handle={:#010x} af={} type={} proto={} local={:#010x}:{:#06x} remote={:#010x}:{:#06x} tcpstate={} flags={:#010x}",
                            s.handle,
                            s.addr_family,
                            s.socket_type,
                            s.protocol,
                            s.local_addr,
                            s.local_port,
                            s.remote_addr,
                            s.remote_port,
                            s.tcp_state,
                            s.flags
                        );
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Isstopped { thread } => {
            let client = &mut client;
            Box::pin(async move {
                let id = parse_thread_id(&thread)?;
                let state = client.run(IsStopped { thread: id }).await?;
                println!("{state:?}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Reboot {
            warm,
            stop_on_start,
            no_debug,
            wait,
            title,
        } => {
            let client = &mut client;
            Box::pin(async move {
                client
                    .run(Reboot {
                        flags: RebootFlags {
                            warm,
                            stop_on_start,
                            no_debug,
                            wait,
                        },
                        title,
                        directory: None,
                        cmd_line: None,
                    })
                    .await?;
                println!("reboot issued");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::SetTitle { nopersist, name } => {
            let client = &mut client;
            Box::pin(async move {
                let cmd = if nopersist {
                    Title::NoPersist
                } else {
                    Title::Set {
                        name: name.unwrap_or_default(),
                    }
                };
                client.run(cmd).await?;
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Setmem { address, hex } => {
            let client = &mut client;
            Box::pin(async move {
                let addr = parse_u32(&address).map_err(rootcause::Report::new)?;
                let data = decode_hex(&hex)
                    .map_err(rootcause::Report::new)
                    .attach_with(|| format!("decoding --data {hex:?}"))?;
                let result = client
                    .run(SetMem {
                        address: addr,
                        data,
                    })
                    .await?;
                println!("requested={} written={}", result.requested, result.written);
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Bp { address, clear } => {
            let client = &mut client;
            Box::pin(async move {
                let addr = parse_u32(&address).map_err(rootcause::Report::new)?;
                client
                    .run(Breakpoint {
                        address: addr,
                        clear,
                    })
                    .await?;
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Databp {
            address,
            size,
            kind,
            clear,
        } => {
            let client = &mut client;
            Box::pin(async move {
                let addr = parse_u32(&address).map_err(rootcause::Report::new)?;
                let kind = match kind.to_ascii_lowercase().as_str() {
                    "read" => DataBreakKind::Read,
                    "write" => DataBreakKind::Write,
                    "readwrite" | "rw" => DataBreakKind::ReadWrite,
                    "execute" | "exec" => DataBreakKind::Execute,
                    _ => {
                        return Err(rootcause::Report::new(Error::from(
                            xeedee::error::ArgumentError::EmptyFilename,
                        ))
                        .attach("kind must be one of read/write/readwrite/execute"));
                    }
                };
                client
                    .run(DataBreakpoint {
                        address: addr,
                        size,
                        kind,
                        clear,
                    })
                    .await?;
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        Command::Screenshot { output, raw } => {
            let client = &mut client;
            Box::pin(async move {
                let shot = client.screenshot().await?;
                let meta = shot.metadata;
                eprintln!(
                    "{} {}x{} pitch={} bytes={} format={:?}",
                    ok_tag("captured"),
                    meta.width,
                    meta.height,
                    meta.pitch,
                    meta.framebuffer_size,
                    meta.format
                );
                if raw {
                    std::fs::write(&output, &shot.data)
                        .map_err(Error::from)
                        .into_report()
                        .attach_with(|| format!("writing raw framebuffer to {output}"))?;
                    let sidecar = format!("{output}.meta");
                    let meta_text = format!(
                        "pitch={}\nwidth={}\nheight={}\nformat={:?}\nframebuffer_size={}\npitch_hex={:#010x}\nformat_raw={:#010x}\n",
                        meta.pitch,
                        meta.width,
                        meta.height,
                        meta.format,
                        meta.framebuffer_size,
                        meta.pitch,
                        meta.format.raw()
                    );
                    std::fs::write(&sidecar, meta_text)
                        .map_err(Error::from)
                        .into_report()
                        .attach("writing metadata sidecar")?;
                    eprintln!(
                        "{} raw framebuffer + metadata to {output} (+ {sidecar})",
                        ok_tag("wrote"),
                    );
                } else {
                    let rgba = shot.to_rgba8().ok_or_else(|| {
                        rootcause::Report::new(Error::from(
                            xeedee::error::ArgumentError::EmptyFilename,
                        ))
                        .attach(format!(
                            "cannot convert format {:?} to PNG without de-tiling; re-run with --raw",
                            meta.format
                        ))
                    })?;
                    let buffer = image::RgbaImage::from_raw(meta.width, meta.height, rgba)
                        .ok_or_else(|| {
                            rootcause::Report::new(Error::from(
                                xeedee::error::ArgumentError::EmptyFilename,
                            ))
                            .attach("RgbaImage::from_raw rejected the buffer dimensions")
                        })?;
                    let png_msg = format!("encoding PNG to {output}");
                    buffer
                        .save_with_format(&output, image::ImageFormat::Png)
                        .map_err(|e| {
                            rootcause::Report::new(Error::from(std::io::Error::other(
                                e.to_string(),
                            )))
                            .attach(png_msg)
                        })?;
                    eprintln!("{} PNG to {output}", ok_tag("wrote"));
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        #[cfg(feature = "capture")]
        Command::Capture { .. } => {
            unreachable!("Capture is handled by run_capture before drive_connected")
        }
        #[cfg(feature = "capture")]
        Command::PixcmdProbe { subcommand } => {
            let client = &mut client;
            Box::pin(async move {
                run_pixcmd_probe(client, &subcommand).await?;
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        #[cfg(feature = "capture")]
        Command::PixNotify { .. } => {
            unreachable!("PixNotify is handled by run_pix_notify before drive_connected")
        }
        #[cfg(feature = "capture")]
        Command::Xbm(_) => {
            unreachable!("Xbm is handled by run_xbm before drive_connected")
        }
        Command::Raw { line } => {
            let client = &mut client;
            Box::pin(async move {
                let resp = client.send_raw(&line).await?;
                println!("{resp:#?}");
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
        #[cfg(feature = "dangerous")]
        Command::Dangerous(cmd) => {
            let client = &mut client;
            Box::pin(async move {
                match cmd {
                    DangerousCommand::DrivemapStatus => {
                        let status = dm::status(client).await?;
                        println!(
                            "xbdm @ {:#010x}, drivemap_fn @ {:#010x}, flag @ {:#010x} = {:#010x}, altaddr entry @ {:#010x}",
                            status.layout.module.base,
                            status.layout.drivemap_fn,
                            status.layout.flag_global,
                            status.flag_value,
                            status.layout.altaddr_entry.name_ptr_addr
                        );
                        println!("visible drives: {:?}", status.visible_drives);
                    }
                    DangerousCommand::DrivemapEnable => unreachable!(
                        "DrivemapEnable is handled by run_drivemap_enable before drive_connected"
                    ),
                    DangerousCommand::NandDump { .. } => {
                        unreachable!(
                            "NandDump is handled by run_nand_dump before drive_connected"
                        )
                    }
                    DangerousCommand::DrivemapPersist => {
                        let report = dm::persist(client).await?;
                        eprintln!(
                            "{} wrote {} bytes to {}",
                            ok_tag("persisted"),
                            report.bytes_written,
                            report.path
                        );
                    }
                }
                Ok::<(), rootcause::Report<Error>>(())
            })
            .await?;
        }
    }

    let _ = client.bye().await;
    Ok(())
}

#[derive(Default)]
struct RecursiveGetStats {
    files: u64,
    bytes: u64,
}

struct DownloadResult {
    /// Bytes actually streamed onto disk.
    copied: u64,
    /// Total length declared by the remote in the `getfile` prefix header.
    total: u64,
}

async fn download_single_file<T>(
    client: &mut Client<T, xeedee::Connected>,
    remote: &str,
    output_path: &std::path::Path,
    range: GetFileRange,
    ui: UiCtx,
) -> Result<DownloadResult, rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    let download = client.get_file(remote, range).await?;
    let total = download.total();
    let bar = ui.progress(total, "download");
    let file = tokio::fs::File::create(output_path)
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating local file {}", output_path.display()))?;
    let compat = tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(file);
    let mut tracked = ProgressWrite::new(compat, bar.clone());
    let copied = download.copy_into(&mut tracked).await?;
    bar.finish_and_clear();
    Ok(DownloadResult { copied, total })
}

async fn download_dir_recursive<T>(
    client: &mut Client<T, xeedee::Connected>,
    remote_dir: &str,
    local_root: &std::path::Path,
    ui: UiCtx,
    stats: &mut RecursiveGetStats,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    let dir = normalize_dir_path(remote_dir);
    let entries = client.run(DirList { path: dir.clone() }).await?;
    for entry in entries {
        let child_remote = join_path(&dir, &entry.name);
        let child_local = local_root.join(&entry.name);
        if entry.is_directory {
            tokio::fs::create_dir_all(&child_local)
                .await
                .map_err(Error::from)
                .into_report()
                .attach_with(|| format!("creating local directory {}", child_local.display()))?;
            Box::pin(download_dir_recursive(
                client,
                &child_remote,
                &child_local,
                ui,
                stats,
            ))
            .await?;
        } else {
            let DownloadResult { copied, .. } = download_single_file(
                client,
                &child_remote,
                &child_local,
                GetFileRange::WholeFile,
                ui,
            )
            .await?;
            stats.files += 1;
            stats.bytes += copied;
        }
    }
    Ok(())
}

fn resolve_get_dir_output(
    remote: &str,
    output: Option<&str>,
) -> Result<PathBuf, rootcause::Report<Error>> {
    let basename = remote_basename(remote).unwrap_or_else(|| "download".to_owned());
    match output {
        None => Ok(PathBuf::from(basename)),
        Some(explicit) => {
            let p = PathBuf::from(explicit);
            // If the user gave us an existing directory, drop the tree
            // inside it (rather than overwriting). Otherwise use the
            // path verbatim as the root.
            if p.is_dir() {
                Ok(p.join(basename))
            } else {
                Ok(p)
            }
        }
    }
}

fn remote_basename(remote: &str) -> Option<String> {
    // Strip drive prefix like `FLASH:` if present so the local path
    // doesn't end up with a literal colon.
    let after_drive = remote.split_once(':').map(|x| x.1).unwrap_or(remote);
    after_drive
        .rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .map(|s| s.to_owned())
}

fn resolve_get_output(
    remote: &str,
    output: Option<&str>,
) -> Result<PathBuf, rootcause::Report<Error>> {
    let basename = remote_basename(remote).ok_or_else(|| {
        rootcause::Report::new(Error::from(xeedee::error::ArgumentError::EmptyFilename))
            .attach(format!("cannot derive local filename from {remote:?}"))
    })?;
    match output {
        None => Ok(PathBuf::from(basename)),
        Some(explicit) => {
            let p = PathBuf::from(explicit);
            if p.is_dir() {
                Ok(p.join(basename))
            } else {
                Ok(p)
            }
        }
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Error> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(Error::from(xeedee::ParseError::InvalidHexDigits {
            key: "hex-bytes",
        }));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks(2) {
        let s = core::str::from_utf8(pair)
            .map_err(|_| Error::from(xeedee::ParseError::InvalidHexDigits { key: "hex-bytes" }))?;
        out.push(
            u8::from_str_radix(s, 16).map_err(|_| {
                Error::from(xeedee::ParseError::InvalidHexDigits { key: "hex-bytes" })
            })?,
        );
    }
    Ok(out)
}

fn parse_u32(input: &str) -> Result<u32, Error> {
    let trimmed = input.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
            .map_err(|_| Error::from(xeedee::ParseError::InvalidHexDigits { key: "cli" }))
    } else {
        trimmed
            .parse::<u32>()
            .map_err(|_| Error::from(xeedee::ParseError::InvalidDecimalU32 { key: "cli" }))
    }
}

fn parse_thread_id(input: &str) -> Result<ThreadId, rootcause::Report<Error>> {
    parse_u32(input)
        .map(ThreadId)
        .map_err(rootcause::Report::new)
        .attach_with(|| format!("invalid thread id {input:?}"))
}

fn attach_hint(err: Error, hint: &'static str) -> rootcause::Report<Error> {
    rootcause::Report::new(err).attach(hint)
}

fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

fn print_hex_dump(base: u32, data: &[u8], unmapped: &[u32]) {
    let unmapped: std::collections::HashSet<u32> = unmapped.iter().copied().collect();
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let addr = base.wrapping_add((chunk_idx * 16) as u32);
        print!("{addr:#010x}  ");
        for (i, b) in chunk.iter().enumerate() {
            let offset = (chunk_idx * 16 + i) as u32;
            if unmapped.contains(&offset) {
                print!("?? ");
            } else {
                print!("{:02x} ", b);
            }
            if i == 7 {
                print!(" ");
            }
        }
        for _ in chunk.len()..16 {
            print!("   ");
        }
        print!(" |");
        for (i, b) in chunk.iter().enumerate() {
            let offset = (chunk_idx * 16 + i) as u32;
            if unmapped.contains(&offset) || !(0x20..0x7f).contains(b) {
                print!(".");
            } else {
                print!("{}", *b as char);
            }
        }
        println!("|");
    }
}

#[cfg(feature = "capture")]
async fn run_pixcmd_probe<T>(
    client: &mut xeedee::Client<T, xeedee::Connected>,
    subcommand: &str,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    let mut session = PixCmd::new(client);
    let resp = session.raw(subcommand).await?;
    println!("{resp:#?}");
    Ok(())
}

#[cfg(feature = "capture")]
#[allow(clippy::too_many_arguments)]
async fn run_capture(
    target: &Target,
    conn_timeout: Duration,
    remote: String,
    size_limit_mb: u32,
    duration: Option<Duration>,
    output_dir: String,
    no_conversion: bool,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>> {
    use futures_util::io::AsyncBufReadExt as _;
    use futures_util::io::BufReader;
    use tokio::sync::mpsc;

    std::fs::create_dir_all(&output_dir)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating local output dir {output_dir}"))?;

    // Notify channel (2nd connection).
    // Capture file-creation and capture-end are async; the handler
    // only signals completion on the notify channel. Subscribe first
    // so no events are missed.
    let notify_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut notify_client = xeedee::Client::new(notify_transport).read_banner().await?;
    let _ack = notify_client.send_raw("notify reverse").await?;

    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<Notification>();
    let mut notify_raw = notify_client.into_inner();
    let notify_task = tokio::spawn(async move {
        let mut reader = BufReader::new(&mut notify_raw);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if let Some(n) = Notification::parse(trimmed) {
                        if notify_tx.send(n).is_err() {
                            break;
                        }
                    } else {
                        tracing::debug!(target: "xeedee::pix", line = %trimmed, "non-pix notify line");
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Command channel (main connection).
    let cmd_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = xeedee::Client::new(cmd_transport).read_banner().await?;

    let xeedee::commands::pix::ConnectOutcome {
        mut session,
        handler_detected,
    } = CaptureSession::connect(&mut client).await?;
    if handler_detected {
        eprintln!(
            "{} PIX handler responded to {{Connect}}",
            ok_tag("connected")
        );
    } else {
        eprintln!(
            "{} no title has registered as the PIX handler (got plain `OK`). \
             Continuing anyway, but subsequent commands will likely no-op.",
            warn_tag("warning:")
        );
    }

    session.limit_capture_size_mb(size_limit_mb).await?;
    session.begin_capture_file_creation(&remote).await?;
    eprintln!(
        "{} requested capture file -> {remote}, waiting for \
         {{CaptureFileCreationEnded}} on notify channel",
        ok_tag("prepared"),
    );

    // The handler ACKs {BeginCaptureFileCreation} immediately but
    // actual readiness is signalled asynchronously. Block until we
    // see PIX!{CaptureFileCreationEnded} <hresult>. The hresult is
    // on the notification line as a trailing hex; a 0 means success.
    // Give up after 30s and surface a clearer error than the eventual
    // "0 segments".
    const FILE_READY_TIMEOUT: Duration = Duration::from_secs(30);
    match tokio::time::timeout(FILE_READY_TIMEOUT, async {
        loop {
            match notify_rx.recv().await {
                Some(Notification::CaptureFileCreationEnded { index }) => {
                    // The `index` field here is the hresult from the
                    // notification line; a 0 means S_OK.
                    return Ok::<_, rootcause::Report<Error>>(index);
                }
                Some(other) => {
                    tracing::debug!(
                        target: "xeedee::pix",
                        ?other,
                        "notify while waiting for CaptureFileCreationEnded",
                    );
                }
                None => {
                    return Err(rootcause::Report::new(Error::from(
                        xeedee::error::ArgumentError::EmptyFilename,
                    ))
                    .attach("notify channel closed before CaptureFileCreationEnded"));
                }
            }
        }
    })
    .await
    {
        Ok(Ok(0)) => eprintln!("{} capture file ready", ok_tag("ready")),
        Ok(Ok(hr)) => {
            return Err(rootcause::Report::new(Error::from(
                xeedee::error::ArgumentError::EmptyFilename,
            ))
            .attach(format!(
                "capture file creation failed on console, hresult {hr:#010x}"
            )));
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(rootcause::Report::new(Error::from(
                xeedee::error::ArgumentError::EmptyFilename,
            ))
            .attach(format!(
                "no CaptureFileCreationEnded within {}s; is a title actually rendering D3D frames?",
                FILE_READY_TIMEOUT.as_secs()
            )));
        }
    }

    session.begin_capture().await?;
    eprintln!(
        "{} capturing; {}",
        ok_tag("recording"),
        match duration {
            Some(d) => format!("stopping in {}s", d.as_secs()),
            None => "press Enter to stop".to_owned(),
        }
    );

    match duration {
        Some(d) => tokio::time::sleep(d).await,
        None => {
            use tokio::io::AsyncBufReadExt as _;
            let stdin = tokio::io::BufReader::new(tokio::io::stdin());
            let mut lines = stdin.lines();
            let _ = lines.next_line().await;
        }
    };

    session.end_capture().await?;
    session.end_capture_file_creation().await?;
    eprintln!(
        "{} capture closed, waiting for {{CaptureEnded}}",
        ok_tag("stopping")
    );

    // Wait for the handler to signal the whole session is done so we
    // know all segments have been flushed to disk.
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match notify_rx.recv().await {
                Some(Notification::CaptureEnded) => break,
                Some(_) => continue,
                None => break,
            }
        }
    })
    .await;

    session.disconnect().await?;
    // Stop the notify task; we're about to do file I/O and don't
    // need the notification reader anymore.
    notify_task.abort();
    // The PIX command socket is "dedicated" -- xbdm rejects normal
    // file-ops on it (`dirlist` / `getfile` returns "dedicated
    // connection required"). Drop it and open a fresh connection for
    // the segment download phase.
    drop(client);
    let files_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = xeedee::Client::new(files_transport).read_banner().await?;
    eprintln!("{} capture finalised, downloading segments", ok_tag("done"));

    // Find segment files. xbmovie's file naming is
    // `<stem><N>.<ext>` where the remote path was `<stem>.<ext>`,
    // starting at N=0. Rather than polling GetFileAttributes with
    // the NT device path form (which doesn't always resolve back),
    // list the parent directory in DOS form and match by basename
    // stem -- this works regardless of how we sent the path to the
    // PIX handler.
    let CaptureRemotePath {
        parent: parent_dir_dos,
        stem,
        ext,
    } = split_capture_remote(&remote);
    eprintln!(
        "{} scanning {parent_dir_dos} for segments (stem={stem:?}, ext={ext:?})",
        ok_tag("looking"),
    );
    let entries = match client
        .run(DirList {
            path: parent_dir_dos.clone(),
        })
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "{} dirlist failed on {parent_dir_dos}: {:?}",
                warn_tag("warn:"),
                e.current_context()
            );
            vec![]
        }
    };
    tracing::debug!(target: "xeedee::pix", entry_count = entries.len(), "dirlist returned");

    let prefix = stem.clone();
    let mut segments: Vec<(u32, String, u64)> = entries
        .into_iter()
        .filter(|e| !e.is_directory && e.name.starts_with(&prefix) && e.name.ends_with(&ext))
        .filter_map(|e| {
            // Extract the numeric index between stem and ext.
            let mid = &e.name[prefix.len()..e.name.len() - ext.len()];
            mid.parse::<u32>().ok().map(|idx| (idx, e.name, e.size))
        })
        .collect();
    segments.sort_by_key(|(idx, _, _)| *idx);
    if segments.is_empty() {
        eprintln!(
            "{} no files matching {stem}<N>{ext} in {parent_dir_dos}. \
             Either the handler produced no output this run, or the \
             previous segments have already been deleted.",
            warn_tag("warn:"),
        );
    }

    let total_segments = segments.len();
    let mut segments_downloaded = 0u32;
    let mut bytes_downloaded = 0u64;
    let mut downloaded_local_paths: Vec<String> = Vec::new();
    for (index, name, _size_hint) in segments {
        let remote_path = format!("{parent_dir_dos}{name}");
        let local_path = format!("{output_dir}/{name}");
        let download = client
            .get_file(&remote_path, GetFileRange::WholeFile)
            .await?;
        let total = download.total();
        if total == 0 {
            // Release the streaming borrow before reusing `client`.
            drop(download);
            eprintln!("{} segment {index}: empty, skipping", warn_tag("skip:"));
            let _ = client
                .run(xeedee::commands::Delete {
                    path: remote_path,
                    is_directory: false,
                })
                .await;
            continue;
        }
        let bar = ui.progress(total, &format!("segment {index}"));
        let file = tokio::fs::File::create(&local_path)
            .await
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("creating {local_path}"))?;
        let compat = tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(file);
        let mut tracked = ProgressWrite::new(compat, bar.clone());
        let copied = download.copy_into(&mut tracked).await?;
        bar.finish_and_clear();
        eprintln!(
            "{} segment {index}: {copied} bytes -> {local_path}",
            ok_tag("saved")
        );
        let _ = client
            .run(xeedee::commands::Delete {
                path: remote_path,
                is_directory: false,
            })
            .await;
        segments_downloaded += 1;
        bytes_downloaded += copied;
        downloaded_local_paths.push(local_path);
    }

    eprintln!(
        "{} downloaded {segments_downloaded}/{total_segments} segment{s} ({})",
        ok_tag("finished"),
        ui.fmt_bytes(bytes_downloaded),
        s = if total_segments == 1 { "" } else { "s" },
    );

    if no_conversion || downloaded_local_paths.is_empty() {
        return Ok(());
    }
    match which_ffmpeg() {
        Ok(()) => {}
        Err(e) => {
            eprintln!(
                "{} skipping conversion: {}. Pass --no-conversion to silence.",
                warn_tag("warn:"),
                e.current_context()
            );
            return Ok(());
        }
    }

    for xbm_path in &downloaded_local_paths {
        let mp4_path = match xbm_path.strip_suffix(".xbm") {
            Some(stem) => format!("{stem}.mp4"),
            None => format!("{xbm_path}.mp4"),
        };
        eprintln!("{} encoding {xbm_path} -> {mp4_path}", ok_tag("converting"),);
        match encode_xbm_to_mp4(xbm_path, &mp4_path, "frame", 0.0, 20, &[]).await {
            Ok(()) => {
                if let Err(e) = std::fs::remove_file(xbm_path) {
                    eprintln!(
                        "{} could not delete {xbm_path} after encode: {e}",
                        warn_tag("warn:")
                    );
                } else {
                    eprintln!("{} removed {xbm_path}", ok_tag("cleaned"));
                }
            }
            Err(e) => {
                eprintln!(
                    "{} conversion of {xbm_path} failed: {:?}; raw file retained",
                    warn_tag("warn:"),
                    e.current_context()
                );
            }
        }
    }
    Ok(())
}

/// Split a capture remote path into (parent directory in DOS form
/// ending in `\\`, stem, extension-with-dot).
///
/// Accepts both the NT device form
/// (`\\Device\\Harddisk0\\Partition1\\DEVKIT\\foo.xbm`) and the DOS
/// form (`DEVKIT:\\foo.xbm`), translating the former back to the
/// latter for use with xbdm's file-ops. Assumes the path is under
/// the `DEVKIT` drive on partition 1 when in NT form; any other
/// layout should supply a DOS-form path directly.
#[cfg(feature = "capture")]
#[derive(Debug)]
struct CaptureRemotePath {
    /// DOS-form directory, always ending in `\` (e.g. `DEVKIT:\`).
    parent: String,
    /// Filename stem, without extension.
    stem: String,
    /// Extension with leading `.` (e.g. `.xbm`), or empty if no dot.
    ext: String,
}

#[cfg(feature = "capture")]
fn split_capture_remote(remote: &str) -> CaptureRemotePath {
    let nt_prefix = r"\Device\Harddisk0\Partition1\";
    let dos_form = if let Some(rest) = remote.strip_prefix(nt_prefix) {
        // Rest looks like `DEVKIT\foo.xbm`; first `\` becomes `:\`.
        match rest.find('\\') {
            Some(slash) => format!("{}:\\{}", &rest[..slash], &rest[slash + 1..]),
            None => format!("{rest}:\\"),
        }
    } else {
        remote.to_owned()
    };

    let last_sep = dos_form.rfind('\\').unwrap_or(0);
    let (parent, name) = dos_form.split_at(last_sep + 1);
    let (stem, ext) = match name.rfind('.') {
        Some(dot) => (&name[..dot], &name[dot..]),
        None => (name, ""),
    };
    CaptureRemotePath {
        parent: parent.to_owned(),
        stem: stem.to_owned(),
        ext: ext.to_owned(),
    }
}

#[cfg(feature = "capture")]
async fn run_xbm(cmd: &XbmCommand) -> Result<(), rootcause::Report<Error>> {
    use xeedee::commands::pix::FrameCursor;
    use xeedee::commands::pix::XbmHeader;

    match cmd {
        XbmCommand::Info { file } => {
            let mut f = std::fs::File::open(file)
                .map_err(Error::from)
                .into_report()
                .attach_with(|| format!("opening xbm file {file}"))?;
            let header = XbmHeader::read(&mut f)?;
            println!(
                "magic        {:?} ({:#010x})  version {:#010x}  header_size {:#x}",
                header.variant,
                header.variant.as_u32(),
                header.version,
                header.header_size
            );
            println!(
                "frame        {}x{}  aligned {}x{}  (this drives pixel stride)",
                header.frame_width,
                header.frame_height,
                header.aligned_frame_width(),
                header.aligned_frame_height(),
            );
            println!(
                "source       {}x{}  display {}x{}",
                header.source_width,
                header.source_height,
                header.display_width,
                header.display_height,
            );
            println!(
                "tick rate    {} ticks/s  yuv bytes/frame {}",
                header.timestamp_rate,
                header.frame_pixel_bytes(),
            );

            let mut cursor = FrameCursor::new(&mut f)?;
            let mut frame_count = 0u64;
            let mut audio_bytes = 0u64;
            let mut first_ts: Option<u32> = None;
            let mut last_ts: Option<u32> = None;
            let mut first_record_size: Option<u64> = None;
            let mut frame_magic: Option<u32> = None;
            while let Some(fr) = cursor.next_frame(&header)? {
                frame_count += 1;
                audio_bytes += fr.header.audio_bytes() as u64;
                first_ts.get_or_insert(fr.header.timestamp);
                last_ts = Some(fr.header.timestamp);
                first_record_size.get_or_insert(fr.record_size);
                frame_magic.get_or_insert(fr.header.frame_magic);
            }
            println!("frames       {frame_count}");
            if let Some(m) = frame_magic {
                println!("frame magic  {m:#010x}");
            }
            if let (Some(a), Some(b)) = (first_ts, last_ts) {
                let span = b.wrapping_sub(a);
                let seconds = span as f64 / header.timestamp_rate as f64;
                let fps = if seconds > 0.0 {
                    (frame_count.saturating_sub(1)) as f64 / seconds
                } else {
                    0.0
                };
                println!("timestamps   {a} -> {b} (span {span}, {seconds:.3}s, {fps:.2} fps)");
            }
            println!("audio bytes  {audio_bytes}");
            if let Some(sz) = first_record_size {
                println!("first record {sz} bytes");
            }
            Ok(())
        }
        XbmCommand::Extract {
            file,
            output_dir,
            concat,
            raw,
        } => run_xbm_extract(file, output_dir, *concat, *raw).await,
        XbmCommand::Encode {
            file,
            output,
            crop,
            fps,
            crf,
            ffmpeg_args,
        } => run_xbm_encode(file, output, crop, *fps, *crf, ffmpeg_args).await,
    }
}

#[cfg(feature = "capture")]
async fn run_xbm_extract(
    file: &str,
    output_dir: &str,
    concat: bool,
    raw: bool,
) -> Result<(), rootcause::Report<Error>> {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use xeedee::commands::pix::FrameCursor;
    use xeedee::commands::pix::XbmHeader;
    use xeedee::commands::pix::detile_frame;

    std::fs::create_dir_all(output_dir)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating {output_dir}"))?;
    let mut f = std::fs::File::open(file)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("opening xbm file {file}"))?;
    let header = XbmHeader::read(&mut f)?;
    let pixel_bytes = header.frame_pixel_bytes() as usize;

    let ext = if raw { "tiled" } else { "nv12" };
    let mut concat_writer = if concat {
        let path = format!("{output_dir}/frames.{ext}");
        Some((
            std::fs::File::create(&path)
                .map_err(Error::from)
                .into_report()
                .attach_with(|| format!("creating {path}"))?,
            path,
        ))
    } else {
        None
    };

    let mut cursor = FrameCursor::new(&mut f)?;
    let mut records: Vec<_> = Vec::new();
    while let Some(fr) = cursor.next_frame(&header)? {
        records.push(fr);
    }

    let mut tiled = vec![0u8; pixel_bytes];
    let mut nv12 = vec![0u8; pixel_bytes];
    let mut index = 0u32;
    let mut timestamps: Vec<u32> = Vec::with_capacity(records.len());
    for fr in &records {
        f.seek(SeekFrom::Start(fr.pixels_offset))
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("seek to pixels at {:#x}", fr.pixels_offset))?;
        f.read_exact(&mut tiled)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("reading pixel bytes at {:#x}", fr.pixels_offset))?;
        timestamps.push(fr.header.timestamp);

        let payload: &[u8] = if raw {
            &tiled
        } else {
            detile_frame(&tiled, &mut nv12, &header);
            &nv12
        };

        let out_path = format!("{output_dir}/frame-{:05}.{ext}", index);
        std::fs::write(&out_path, payload)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("writing {out_path}"))?;
        if let Some((w, _)) = concat_writer.as_mut() {
            w.write_all(payload)
                .map_err(Error::from)
                .into_report()
                .attach("appending to concat")?;
        }
        index += 1;
    }

    let meta_path = format!("{output_dir}/metadata.txt");
    let fps = if timestamps.len() >= 2 {
        let span = timestamps
            .last()
            .unwrap()
            .wrapping_sub(*timestamps.first().unwrap());
        if span > 0 {
            (timestamps.len() - 1) as f64 * header.timestamp_rate as f64 / span as f64
        } else {
            0.0
        }
    } else {
        0.0
    };
    let layout = if raw {
        "tiled Xbox 360 16-wide-column NV12 (raw on-device layout)"
    } else {
        "nv12 (Y plane, then interleaved UV plane; detiled from on-device layout)"
    };
    let ffmpeg_pixfmt = if raw {
        "nv12  # WILL NOT RENDER -- re-run without --raw"
    } else {
        "nv12"
    };
    let meta = format!(
        "# xbmovie .xbm frame dump\n\
         source: {file}\n\
         magic: {:?}\n\
         frame_width: {}\n\
         frame_height: {}\n\
         aligned_width: {}\n\
         aligned_height: {}\n\
         visible_crop: {}x{}\n\
         pixel_format: {layout}\n\
         frame_count: {}\n\
         approx_fps: {fps:.3}\n\
         \n\
         # Reconstruct (crops off the 32-alignment padding):\n\
         # ffmpeg -f rawvideo -pix_fmt {ffmpeg_pixfmt} -s {}x{} -r {} \\\n\
         #   -i frames.{ext} -vf crop={}:{}:0:0 \\\n\
         #   -c:v libx264 -pix_fmt yuv420p out.mp4\n",
        header.variant,
        header.frame_width,
        header.frame_height,
        header.aligned_frame_width(),
        header.aligned_frame_height(),
        header.source_width,
        header.source_height,
        records.len(),
        header.aligned_frame_width(),
        header.aligned_frame_height(),
        fps.round() as u32,
        header.frame_width,
        header.frame_height,
    );
    std::fs::write(&meta_path, meta)
        .map_err(Error::from)
        .into_report()
        .attach("writing metadata")?;

    eprintln!(
        "{} extracted {} frame{s} ({} pixel bytes each) -> {output_dir}",
        ok_tag("done"),
        index,
        humanize_bytes(pixel_bytes as u64),
        s = if index == 1 { "" } else { "s" },
    );
    if let Some((_, p)) = concat_writer {
        eprintln!("{} concatenated stream -> {p}", ok_tag("done"));
    }
    eprintln!("{} metadata -> {meta_path}", ok_tag("done"));
    Ok(())
}

#[cfg(feature = "capture")]
async fn run_xbm_encode(
    file: &str,
    output: &str,
    crop_mode: &str,
    fps_override: f64,
    crf: u32,
    extra_args: &[String],
) -> Result<(), rootcause::Report<Error>> {
    // Probe ffmpeg before we do any work so the user gets an
    // immediate, typed failure rather than something mid-pipeline.
    which_ffmpeg()?;
    encode_xbm_to_mp4(file, output, crop_mode, fps_override, crf, extra_args).await
}

/// Shared implementation used by both the `xbm encode` subcommand
/// and the auto-conversion tail of `capture`. Assumes `ffmpeg` is on
/// `$PATH`; callers should invoke [`which_ffmpeg`] first.
#[cfg(feature = "capture")]
async fn encode_xbm_to_mp4(
    file: &str,
    output: &str,
    crop_mode: &str,
    fps_override: f64,
    crf: u32,
    extra_args: &[String],
) -> Result<(), rootcause::Report<Error>> {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;
    use xeedee::commands::pix::FrameCursor;
    use xeedee::commands::pix::XbmHeader;
    use xeedee::commands::pix::detile_frame;

    let mut f = std::fs::File::open(file)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("opening xbm file {file}"))?;
    let header = XbmHeader::read(&mut f)?;
    let aligned_w = header.aligned_frame_width();
    let aligned_h = header.aligned_frame_height();
    let pixel_bytes = header.frame_pixel_bytes() as usize;

    let (crop_w, crop_h) = match crop_mode {
        "frame" => (header.frame_width, header.frame_height),
        "source" => (header.source_width, header.source_height),
        "none" => (aligned_w, aligned_h),
        other => {
            return Err(rootcause::Report::new(Error::from(
                xeedee::error::ArgumentError::EmptyFilename,
            ))
            .attach(format!(
                "--crop must be one of `frame`, `source`, `none`; got {other:?}"
            )));
        }
    };

    // Walk the frame table once to derive timestamps + fps, then
    // rewind for the streaming pass.
    let mut cursor = FrameCursor::new(&mut f)?;
    let mut records = Vec::new();
    while let Some(fr) = cursor.next_frame(&header)? {
        records.push(fr);
    }
    if records.is_empty() {
        return Err(rootcause::Report::new(Error::from(
            xeedee::error::ArgumentError::EmptyFilename,
        ))
        .attach("xbm contains no frame records"));
    }
    let derived_fps = if records.len() >= 2 {
        let span = records
            .last()
            .unwrap()
            .header
            .timestamp
            .wrapping_sub(records.first().unwrap().header.timestamp);
        if span > 0 {
            (records.len() - 1) as f64 * header.timestamp_rate as f64 / span as f64
        } else {
            0.0
        }
    } else {
        0.0
    };
    let fps = if fps_override > 0.0 {
        fps_override
    } else if derived_fps > 0.0 {
        derived_fps
    } else {
        30.0
    };

    // Build the ffmpeg command. Input is rawvideo NV12 over stdin.
    let size = format!("{aligned_w}x{aligned_h}");
    let framerate = format!("{fps:.3}");
    let crop_filter = format!("crop={crop_w}:{crop_h}:0:0");
    let crf_str = crf.to_string();

    let mut cmd = Command::new("ffmpeg");
    cmd.arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-stats")
        .arg("-f")
        .arg("rawvideo")
        .arg("-pix_fmt")
        .arg("nv12")
        .arg("-s")
        .arg(&size)
        .arg("-framerate")
        .arg(&framerate)
        .arg("-i")
        .arg("-")
        .arg("-vf")
        .arg(&crop_filter)
        .arg("-c:v")
        .arg("libx264")
        .arg("-crf")
        .arg(&crf_str)
        .arg("-pix_fmt")
        .arg("yuv420p");
    for extra in extra_args {
        cmd.arg(extra);
    }
    cmd.arg("-y").arg(output).stdin(Stdio::piped());

    eprintln!(
        "{} encoding {} frames at {aligned_w}x{aligned_h} -> {crop_w}x{crop_h} @ {fps:.2} fps -> {output}",
        ok_tag("encoding"),
        records.len()
    );

    let mut child = cmd
        .spawn()
        .map_err(Error::from)
        .into_report()
        .attach("spawning ffmpeg")?;
    let mut stdin = child.stdin.take().expect("stdin configured as piped");

    let mut tiled = vec![0u8; pixel_bytes];
    let mut nv12 = vec![0u8; pixel_bytes];
    for fr in &records {
        f.seek(SeekFrom::Start(fr.pixels_offset))
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("seek to pixels at {:#x}", fr.pixels_offset))?;
        f.read_exact(&mut tiled)
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("reading pixels at {:#x}", fr.pixels_offset))?;
        detile_frame(&tiled, &mut nv12, &header);
        if stdin.write_all(&nv12).is_err() {
            // ffmpeg died; break out and let the exit-status branch
            // explain why.
            break;
        }
    }
    drop(stdin);
    let status = child
        .wait()
        .map_err(Error::from)
        .into_report()
        .attach("waiting on ffmpeg")?;
    if !status.success() {
        return Err(rootcause::Report::new(Error::from(
            xeedee::error::ArgumentError::EmptyFilename,
        ))
        .attach(format!("ffmpeg exited with {status}")));
    }
    eprintln!("{} wrote {output}", ok_tag("done"));
    Ok(())
}

/// Error out cleanly if `ffmpeg` isn't on $PATH. Used by
/// `xbm encode` as an early precondition check.
#[cfg(feature = "capture")]
fn which_ffmpeg() -> Result<(), rootcause::Report<Error>> {
    use std::process::Command;
    use std::process::Stdio;
    let ok = Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if ok {
        Ok(())
    } else {
        Err(
            rootcause::Report::new(Error::from(xeedee::error::ArgumentError::EmptyFilename))
                .attach(
                    "ffmpeg not found on $PATH. Install it (`nix-shell -p ffmpeg`, \
             `brew install ffmpeg`, etc.) and retry. The `xbm encode` \
             subcommand streams decoded NV12 frames to ffmpeg's stdin.",
                ),
        )
    }
}

#[cfg(feature = "capture")]
async fn run_pix_notify(
    target: &Target,
    conn_timeout: Duration,
    duration_secs: u64,
    log_path: Option<String>,
) -> Result<(), rootcause::Report<Error>> {
    use futures_util::io::AsyncBufReadExt as _;
    use futures_util::io::BufReader;
    use std::io::Write as _;

    let transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = xeedee::Client::new(transport).read_banner().await?;

    // `notify` turns the current connection into a pure notification
    // channel after xbdm acknowledges with a single response line;
    // subsequent reads get async events at the server's discretion.
    let ack = client.send_raw("notify").await?;
    eprintln!(
        "{} {ack:?}; {}",
        ok_tag("subscribed"),
        if duration_secs == 0 {
            "Ctrl-C to stop".to_owned()
        } else {
            format!("stopping in {duration_secs}s")
        }
    );

    let mut log_file = match log_path.as_deref() {
        Some(p) => Some(
            std::fs::File::create(p)
                .map_err(Error::from)
                .into_report()
                .attach_with(|| format!("creating notify log {p}"))?,
        ),
        None => None,
    };

    let mut transport = client.into_inner();
    let mut reader = BufReader::new(&mut transport);
    let mut line = String::new();

    let deadline = if duration_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(duration_secs))
    };

    let start = std::time::Instant::now();
    loop {
        line.clear();
        let read = async { reader.read_line(&mut line).await };
        let remaining = deadline.map(|d| d.saturating_sub(start.elapsed()));
        let result = match remaining {
            Some(Duration::ZERO) => break,
            Some(r) => match tokio::time::timeout(r, read).await {
                Ok(r) => r,
                Err(_) => break,
            },
            None => read.await,
        };
        match result {
            Ok(0) => {
                eprintln!("{} notification channel closed", warn_tag("eof:"));
                break;
            }
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    continue;
                }
                let ts = start.elapsed().as_millis();
                let tag = match Notification::parse(trimmed) {
                    Some(Notification::CaptureFileCreationEnded { .. }) => "cap-seg",
                    Some(Notification::CaptureEnded) => "cap-end",
                    Some(Notification::MovieData(_)) => "movie",
                    Some(Notification::Resource(_)) => "rsrc",
                    Some(Notification::VideoOp { error: true, .. }) => "verr",
                    Some(Notification::VideoOp { error: false, .. }) => "vop",
                    Some(Notification::Status(_)) => "stat",
                    Some(Notification::Other(_)) => "pix?",
                    None => "line",
                };
                let rendered = format!("{ts:>6}ms [{tag}] {trimmed}");
                eprintln!("{rendered}");
                if let Some(f) = log_file.as_mut() {
                    let _ = writeln!(f, "{rendered}");
                }
            }
            Err(e) => {
                return Err(rootcause::Report::new(Error::from(e)));
            }
        }
    }
    Ok(())
}

async fn run_discover(
    listen_ms: u64,
    broadcast: Option<&str>,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>> {
    let mut config = DiscoveryConfig::broadcast();
    config.listen_for = Duration::from_millis(listen_ms);
    if let Some(raw) = broadcast {
        let parsed: SocketAddr = raw
            .parse()
            .or_else(|_| format!("{raw}:{NAP_PORT}").parse::<SocketAddr>())
            .map_err(|_| {
                rootcause::Report::new(Error::from(
                    xeedee::error::ArgumentError::QuotedContainsCrlf,
                ))
                .attach(format!("invalid --broadcast value {raw:?}"))
            })?;
        config.destination = parsed;
    }
    tracing::info!(destination = %config.destination, "broadcasting nap identify");
    let results = discover_all(config).await?;
    if results.is_empty() {
        eprintln!("{} no consoles responded", warn_tag("warning:"));
        return Ok(());
    }
    if ui.pretty() {
        #[derive(Tabled)]
        struct Row {
            name: String,
            address: String,
        }
        let rows: Vec<Row> = results
            .iter()
            .map(|c| Row {
                name: c.name.clone(),
                address: c.addr.to_string(),
            })
            .collect();
        print_colored_table(&heading_label("discover", &ui), rows, &ui);
    } else {
        for console in results {
            println!("{}\t{}", console.name, console.addr);
        }
    }
    Ok(())
}

async fn run_resolve(name: &str, listen_ms: u64) -> Result<(), rootcause::Report<Error>> {
    let mut config = DiscoveryConfig::broadcast();
    config.listen_for = Duration::from_millis(listen_ms);
    config.destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), NAP_PORT);
    match find_by_name(name, config).await? {
        Some(console) => {
            println!("{}\t{}", console.name, console.addr);
            Ok(())
        }
        None => Err(rootcause::Report::new(Error::from(
            xeedee::error::TransportError::ConnectTimeout,
        ))
        .attach(format!("no reply from console named {name:?}"))),
    }
}

fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// Emit a line on **stdout** alongside an active progress bar/spinner
/// without the two clobbering each other. `ProgressBar::println` would
/// route through the bar's draw target (stderr); we want tree output
/// to be pipeable, so we use `suspend` to temporarily clear the bar,
/// `println!` to real stdout, then let the bar redraw itself.
fn tree_println(bar: Option<&ProgressBar>, line: impl AsRef<str>) {
    let line = line.as_ref();
    match bar {
        Some(bar) if !bar.is_hidden() => bar.suspend(|| println!("{line}")),
        _ => println!("{line}"),
    }
}

fn tree_dir_style(name: &str, is_dir: bool) -> String {
    if !colors_enabled() || !is_dir {
        return name.to_owned();
    }
    format!("{}", name.blue().bold())
}

async fn run_tree<T>(
    client: &mut Client<T, xeedee::Connected>,
    path: Option<String>,
    max_depth: u32,
    include_files: bool,
    ui: UiCtx,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    let spinner = if !ui.no_progress && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        let bar = ProgressBar::new_spinner();
        bar.set_draw_target(indicatif::ProgressDrawTarget::stderr());
        bar.set_style(
            indicatif::ProgressStyle::with_template("{spinner:.cyan} {prefix:.bold} dirs={msg}")
                .expect("valid spinner template"),
        );
        bar.enable_steady_tick(Duration::from_millis(120));
        bar.set_prefix("walking");
        Some(bar)
    } else {
        None
    };

    let roots: Vec<String> = match path {
        Some(p) => vec![normalize_dir_path(&p)],
        None => client
            .run(DriveList)
            .await?
            .into_iter()
            .map(|d| format!("{d}:\\"))
            .collect(),
    };

    let mut dir_count: u64 = 0;
    for root in &roots {
        walk(
            client,
            root,
            0,
            max_depth,
            include_files,
            ui,
            spinner.as_ref(),
            &mut dir_count,
            &[],
            true,
        )
        .await?;
    }

    if let Some(bar) = spinner {
        bar.finish_and_clear();
    }
    eprintln!(
        "{} {} dir{}",
        ok_tag("walked"),
        dir_count,
        if dir_count == 1 { "" } else { "s" }
    );
    Ok(())
}

fn normalize_dir_path(input: &str) -> String {
    if input.ends_with('\\') || input.is_empty() {
        input.to_owned()
    } else {
        format!("{input}\\")
    }
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{child}")
    } else {
        format!("{parent}\\{child}")
    }
}

#[allow(clippy::too_many_arguments)]
async fn walk<T>(
    client: &mut Client<T, xeedee::Connected>,
    dir: &str,
    depth: u32,
    max_depth: u32,
    include_files: bool,
    ui: UiCtx,
    spinner: Option<&ProgressBar>,
    dir_count: &mut u64,
    ancestor_is_last: &[bool],
    is_root: bool,
) -> Result<(), rootcause::Report<Error>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    *dir_count += 1;
    if let Some(bar) = spinner {
        bar.inc(1);
        bar.set_message(format!("{}", *dir_count));
    }
    if is_root {
        tree_println(spinner, tree_dir_style(dir.trim_end_matches('\\'), true));
    }

    let entries = match client
        .run(DirList {
            path: dir.to_owned(),
        })
        .await
    {
        Ok(entries) => entries,
        Err(err) => {
            let indent = tree_indent(ancestor_is_last, ui);
            let reason = format!("{:?}", err.current_context());
            let line = format!(
                "{indent}(unreadable) {}",
                if colors_enabled() {
                    format!("{}", reason.red())
                } else {
                    reason
                }
            );
            tree_println(spinner, line);
            return Ok(());
        }
    };

    let mut filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| include_files || e.is_directory)
        .collect();
    filtered.sort_by(|a, b| {
        b.is_directory.cmp(&a.is_directory).then_with(|| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        })
    });

    for (idx, entry) in filtered.iter().enumerate() {
        let last = idx == filtered.len() - 1;
        let indent = tree_indent(ancestor_is_last, ui);
        let branch = if ui.pretty() {
            if last { "└── " } else { "├── " }
        } else if last {
            "`-- "
        } else {
            "|-- "
        };
        let label = tree_dir_style(&entry.name, entry.is_directory);
        let line = if entry.is_directory {
            format!("{indent}{branch}{label}")
        } else {
            let size_text = format!("({})", ui.fmt_bytes(entry.size));
            let size_tag = if colors_enabled() {
                format!("  {}", size_text.dimmed())
            } else {
                format!("  {size_text}")
            };
            format!("{indent}{branch}{label}{size_tag}")
        };
        tree_println(spinner, line);

        if entry.is_directory && (max_depth == 0 || depth + 1 < max_depth) {
            let mut next_ancestors = ancestor_is_last.to_vec();
            next_ancestors.push(last);
            let child_dir = join_path(dir, &entry.name);
            let child_dir = normalize_dir_path(&child_dir);
            Box::pin(walk(
                client,
                &child_dir,
                depth + 1,
                max_depth,
                include_files,
                ui,
                spinner,
                dir_count,
                &next_ancestors,
                false,
            ))
            .await?;
        }
    }

    let _ = depth;
    Ok(())
}

fn tree_indent(ancestor_is_last: &[bool], ui: UiCtx) -> String {
    let mut out = String::new();
    for &last in ancestor_is_last {
        if ui.pretty() {
            out.push_str(if last { "    " } else { "│   " });
        } else {
            out.push_str(if last { "    " } else { "|   " });
        }
    }
    out
}

fn heading_label(label: &str, ui: &UiCtx) -> String {
    if ui.pretty() && colors_enabled() {
        format!("{}", label.cyan().bold())
    } else {
        label.to_owned()
    }
}

fn ok_tag(label: &str) -> String {
    if colors_enabled() {
        format!("{}", label.green().bold())
    } else {
        label.to_owned()
    }
}

fn warn_tag(label: &str) -> String {
    if colors_enabled() {
        format!("{}", label.yellow().bold())
    } else {
        label.to_owned()
    }
}

fn print_colored_table<I, T>(heading: &str, rows: I, ui: &UiCtx)
where
    I: IntoIterator<Item = T>,
    T: Tabled,
{
    if !heading.is_empty() {
        println!("{heading}");
    }
    let _ = ui;
    println!("{}", ui::styled_table(rows));
}

use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;

/// Wrap an `AsyncWrite`, ticking an [`indicatif::ProgressBar`] as bytes
/// flow through.
struct ProgressWrite<W> {
    inner: W,
    bar: ProgressBar,
}

impl<W> ProgressWrite<W> {
    fn new(inner: W, bar: ProgressBar) -> Self {
        Self { inner, bar }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                this.bar.inc(n as u64);
                Poll::Ready(Ok(n))
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Wrap an `AsyncRead`, ticking an [`indicatif::ProgressBar`] as bytes
/// flow out.
struct ProgressRead<R> {
    inner: R,
    bar: ProgressBar,
}

impl<R> ProgressRead<R> {
    fn new(inner: R, bar: ProgressBar) -> Self {
        Self { inner, bar }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                this.bar.inc(n as u64);
                Poll::Ready(Ok(n))
            }
        }
    }
}

fn write_capture(
    path: &PathBuf,
    handle: &Arc<Mutex<CaptureLog>>,
) -> Result<(), rootcause::Report<Error>> {
    let snapshot = handle.lock().expect("capture log poisoned").clone();
    std::fs::write(path, snapshot.to_text())
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("writing capture to {}", path.display()))?;
    eprintln!("capture written to {}", path.display());
    Ok(())
}

#[cfg(all(test, feature = "capture"))]
mod capture_tests {
    use super::CaptureRemotePath;
    use super::split_capture_remote;

    #[test]
    fn splits_nt_device_path() {
        let CaptureRemotePath { parent, stem, ext } =
            split_capture_remote(r"\Device\Harddisk0\Partition1\DEVKIT\foo.xbm");
        assert_eq!(parent, r"DEVKIT:\");
        assert_eq!(stem, "foo");
        assert_eq!(ext, ".xbm");
    }

    #[test]
    fn splits_dos_path_unchanged() {
        let CaptureRemotePath { parent, stem, ext } = split_capture_remote(r"DEVKIT:\bar.xbm");
        assert_eq!(parent, r"DEVKIT:\");
        assert_eq!(stem, "bar");
        assert_eq!(ext, ".xbm");
    }

    #[test]
    fn splits_nt_nested() {
        let CaptureRemotePath { parent, stem, ext } =
            split_capture_remote(r"\Device\Harddisk0\Partition1\DEVKIT\sub\baz.xbm");
        assert_eq!(parent, r"DEVKIT:\sub\");
        assert_eq!(stem, "baz");
        assert_eq!(ext, ".xbm");
    }
}
