//! C/C++ FFI for the `openxbdm-client` crate via [diplomat].
//!
//! Exposes a synchronous XBDM client plus the wire-protocol helpers. The
//! async runtime is embedded; callers need not know tokio exists.
//!
//! The C++ wrappers are generated (not committed) into `bindings/cpp/`
//! with:
//!
//! ```text
//! diplomat-tool cpp crates/openxbdm-ffi/bindings/cpp \
//!     --entry crates/openxbdm-ffi/src/lib.rs
//! ```
//!
//! CI runs this on every build; the release workflow packages the output
//! alongside the static / dynamic libraries.

mod inner;

#[allow(clippy::needless_lifetimes, clippy::too_many_arguments)]
#[diplomat::bridge]
mod ffi {
    use diplomat_runtime::DiplomatWrite;
    use std::fmt::Write;

    /// Error returned by any fallible FFI entry point. Carries a
    /// human-readable message accessible via [`OpenxbdmError::message`].
    #[diplomat::opaque]
    pub struct OpenxbdmError(pub(crate) String);

    impl OpenxbdmError {
        pub fn message(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.0);
        }
    }

    /// Owned byte buffer. Size via `.len()` then `.copy_into(dst)`.
    #[diplomat::opaque]
    pub struct OpenxbdmBytes(pub(crate) Vec<u8>);

    impl OpenxbdmBytes {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn copy_into(&self, dst: &mut [u8]) -> usize {
            let n = self.0.len().min(dst.len());
            dst[..n].copy_from_slice(&self.0[..n]);
            n
        }
    }

    /// Owned list of strings. `get(idx, out)` writes one entry, errors on OOB.
    #[diplomat::opaque]
    pub struct OpenxbdmStringList(pub(crate) Vec<String>);

    impl OpenxbdmStringList {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn get(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let s = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", s);
            Ok(())
        }
    }

    /// Builder for an XBDM command line. Wraps [`openxbdm_client::ArgBuilder`].
    ///
    /// `ArgBuilder` consumes `self` on every append; we hold it in a
    /// `RefCell<Option<_>>` so diplomat's `&self` methods can take/replace.
    #[diplomat::opaque]
    pub struct OpenxbdmCommand(pub(crate) std::cell::RefCell<Option<openxbdm_client::ArgBuilder>>);

    impl OpenxbdmCommand {
        #[diplomat::attr(auto, constructor)]
        pub fn new(mnemonic: &str) -> Box<OpenxbdmCommand> {
            Box::new(OpenxbdmCommand(std::cell::RefCell::new(Some(openxbdm_client::ArgBuilder::new(mnemonic)))))
        }

        pub fn flag(&self, token: &str) {
            self.mutate(|b| b.flag(token));
        }
        pub fn dec(&self, key: &str, value: u64) {
            self.mutate(|b| b.dec(key, value));
        }
        pub fn int(&self, key: &str, value: i64) {
            self.mutate(|b| b.int(key, value));
        }
        pub fn hex32(&self, key: &str, value: u32) {
            self.mutate(|b| b.hex32(key, value));
        }
        pub fn hex(&self, key: &str, value: u64) {
            self.mutate(|b| b.hex(key, value));
        }
        pub fn qword(&self, key: &str, value: u64) {
            self.mutate(|b| b.qword(key, openxbdm_client::Qword(value)));
        }
        pub fn qword_pair(&self, key: &str, hi: u64, lo: u64) {
            self.mutate(|b| b.qword_pair(key, openxbdm_client::QwordPair { hi, lo }));
        }

        pub fn quoted(&self, key: &str, value: &str) -> Result<(), Box<OpenxbdmError>> {
            let mut slot = self.0.borrow_mut();
            let b = slot.take().ok_or_else(|| Box::new(OpenxbdmError("command already consumed".into())))?;
            match b.quoted(key, value) {
                Ok(next) => {
                    *slot = Some(next);
                    Ok(())
                }
                Err(e) => Err(Box::new(OpenxbdmError(e.to_string()))),
            }
        }

        pub fn finish(&self) -> Result<Box<OpenxbdmBytes>, Box<OpenxbdmError>> {
            let mut slot = self.0.borrow_mut();
            let b = slot.take().ok_or_else(|| Box::new(OpenxbdmError("command already consumed".into())))?;
            Ok(Box::new(OpenxbdmBytes(b.finish().into_bytes())))
        }
    }

    impl OpenxbdmCommand {
        fn mutate(&self, f: impl FnOnce(openxbdm_client::ArgBuilder) -> openxbdm_client::ArgBuilder) {
            let mut slot = self.0.borrow_mut();
            if let Some(b) = slot.take() {
                *slot = Some(f(b));
            }
        }
    }

    #[diplomat::opaque]
    pub struct OpenxbdmResponseHead(pub(crate) openxbdm_client::protocol::ResponseHead);

    impl OpenxbdmResponseHead {
        #[diplomat::attr(auto, named_constructor = "parse")]
        pub fn parse(line: &str) -> Result<Box<OpenxbdmResponseHead>, Box<OpenxbdmError>> {
            openxbdm_client::protocol::parse_response_head(line)
                .map(|h| Box::new(OpenxbdmResponseHead(h)))
                .map_err(|e| Box::new(OpenxbdmError(e.to_string())))
        }

        pub fn status_code(&self) -> u16 {
            self.0.code.raw()
        }
        pub fn is_success(&self) -> bool {
            self.0.code.is_success()
        }
        pub fn is_error(&self) -> bool {
            self.0.code.is_error()
        }
        pub fn rest(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.0.rest);
        }
    }

    #[diplomat::opaque]
    pub struct OpenxbdmFileTime(pub(crate) openxbdm_client::FileTime);

    impl OpenxbdmFileTime {
        #[diplomat::attr(auto, named_constructor = "from_raw")]
        pub fn from_raw(ticks: u64) -> Box<OpenxbdmFileTime> {
            Box::new(OpenxbdmFileTime(openxbdm_client::FileTime::from_raw(ticks)))
        }

        #[diplomat::attr(auto, named_constructor = "from_halves")]
        pub fn from_halves(high: u32, low: u32) -> Box<OpenxbdmFileTime> {
            Box::new(OpenxbdmFileTime(openxbdm_client::FileTime::from_halves(high, low)))
        }

        pub fn as_raw(&self) -> u64 {
            self.0.as_raw()
        }
        pub fn high(&self) -> u32 {
            self.0.high()
        }
        pub fn low(&self) -> u32 {
            self.0.low()
        }

        pub fn unix_seconds(&self) -> u64 {
            self.0.into_system_time().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        }
        pub fn unix_nanos(&self) -> u32 {
            self.0.into_system_time().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0)
        }
    }

    /// Connected XBDM client. Internally owns a tokio runtime and a
    /// borrowed `openxbdm_client::Client`; all methods block the calling thread
    /// while the I/O completes.
    #[diplomat::opaque]
    pub struct OpenxbdmClient(pub(crate) crate::inner::Inner);

    impl OpenxbdmClient {
        /// Connect to `address` (e.g. `"192.168.1.26:730"`, `"deanxbox:730"`)
        /// with a connect timeout in seconds.
        #[diplomat::attr(auto, named_constructor = "connect")]
        pub fn connect(address: &str, timeout_secs: u32) -> Result<Box<OpenxbdmClient>, Box<OpenxbdmError>> {
            crate::inner::Inner::connect(address, timeout_secs)
                .map(|i| Box::new(OpenxbdmClient(i)))
                .map_err(|e| Box::new(OpenxbdmError(e)))
        }

        /// `dbgname`: read the console's debuggable name into `out`.
        pub fn dbgname(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let name = self.0.run(openxbdm_client::commands::DbgName::Get).map_err(err_box)?;
            let _ = write!(out, "{}", name);
            Ok(())
        }

        /// `dbgname name=<name>`: set the console's debuggable name.
        pub fn set_dbgname(&self, name: &str) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::DbgName::Set(name.to_owned())).map(|_| ()).map_err(err_box)
        }

        /// `systime`: console clock as a `FileTime`.
        pub fn systime(&self) -> Result<Box<OpenxbdmFileTime>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::SysTime)
                .map(|r| Box::new(OpenxbdmFileTime(r.file_time)))
                .map_err(err_box)
        }

        /// `dmversion`: opaque build identifier.
        pub fn dmversion(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let v = self.0.run(openxbdm_client::commands::DmVersion).map_err(err_box)?;
            let _ = write!(out, "{}", v);
            Ok(())
        }

        /// `consoletype`: returns one of "retail", "devkit", "testkit",
        /// "reviewerkit", or a raw string for anything else.
        pub fn consoletype(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let t = self.0.run(openxbdm_client::commands::GetConsoleType).map_err(err_box)?;
            let s = match t {
                openxbdm_client::commands::ConsoleType::Retail => "retail",
                openxbdm_client::commands::ConsoleType::DevKit => "devkit",
                openxbdm_client::commands::ConsoleType::TestKit => "testkit",
                openxbdm_client::commands::ConsoleType::ReviewerKit => "reviewerkit",
                openxbdm_client::commands::ConsoleType::Other(ref raw) => raw.as_str(),
            };
            let _ = write!(out, "{}", s);
            Ok(())
        }

        /// `consolefeatures`: list of feature flags the kernel advertises.
        pub fn consolefeatures(&self) -> Result<Box<OpenxbdmStringList>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::GetConsoleFeatures)
                .map(|r| Box::new(OpenxbdmStringList(r.flags)))
                .map_err(err_box)
        }

        /// `altaddr`: alternate (debug) IPv4 address as a host-order `u32`.
        pub fn altaddr(&self) -> Result<u32, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::AltAddr).map(u32::from).map_err(err_box)
        }

        /// `getpid`: pid of the currently running title process.
        pub fn getpid(&self) -> Result<u32, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::GetPid).map_err(err_box)
        }

        /// `consolemem`: memory-class byte.
        pub fn consolemem(&self) -> Result<u8, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::GetConsoleMem).map(|m| m.class).map_err(err_box)
        }

        /// `getnetaddrs`: console name + debug/title `sockaddr`-ish blobs.
        pub fn getnetaddrs(&self) -> Result<Box<OpenxbdmNetAddrs>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::GetNetAddrs)
                .map(|a| Box::new(OpenxbdmNetAddrs { name: a.name, debug: a.debug, title: a.title }))
                .map_err(err_box)
        }

        /// `drivelist`: drive labels (e.g. "D", "DEVKIT", "HDD").
        pub fn drivelist(&self) -> Result<Box<OpenxbdmStringList>, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::DriveList).map(|v| Box::new(OpenxbdmStringList(v))).map_err(err_box)
        }

        /// `drivefreespace`: free and total byte counters for a drive.
        pub fn drivefreespace(&self, drive: &str) -> Result<Box<OpenxbdmDriveSpace>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::DriveFreeSpace { drive: drive.to_owned() })
                .map(|s| {
                    Box::new(OpenxbdmDriveSpace {
                        free_to_caller: s.free_to_caller_bytes,
                        total: s.total_bytes,
                        total_free: s.total_free_bytes,
                    })
                })
                .map_err(err_box)
        }

        /// `dirlist`: directory entries.
        pub fn dirlist(&self, path: &str) -> Result<Box<OpenxbdmDirEntries>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::DirList { path: path.to_owned() })
                .map(|v| Box::new(OpenxbdmDirEntries(v)))
                .map_err(err_box)
        }

        /// `getfileattributes`: size + timestamps for a single path.
        pub fn getfileattributes(&self, path: &str) -> Result<Box<OpenxbdmFileAttributes>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::GetFileAttributes { path: path.to_owned() })
                .map(|a| {
                    Box::new(OpenxbdmFileAttributes {
                        size: a.size,
                        create_time: a.create_time.as_raw(),
                        change_time: a.change_time.as_raw(),
                        is_directory: a.is_directory,
                    })
                })
                .map_err(err_box)
        }

        pub fn mkdir(&self, path: &str) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::MakeDirectory { path: path.to_owned() }).map_err(err_box)
        }

        pub fn delete(&self, path: &str, is_directory: bool) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Delete { path: path.to_owned(), is_directory }).map_err(err_box)
        }

        pub fn rename(&self, from: &str, to: &str) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Rename { from: from.to_owned(), to: to.to_owned() }).map_err(err_box)
        }

        pub fn fileeof(&self, path: &str, size: u64, create_if_missing: bool) -> Result<(), Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::FileEof { path: path.to_owned(), size, create_if_missing })
                .map_err(err_box)
        }

        pub fn stop(&self) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Stop).map_err(err_box)
        }

        pub fn go(&self) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Go).map_err(err_box)
        }

        pub fn halt(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Halt { thread: openxbdm_client::commands::ThreadId(thread) })
                .map_err(err_box)
        }

        pub fn continue_thread(&self, thread: u32, single_step: bool) -> Result<(), Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Continue {
                    thread: openxbdm_client::commands::ThreadId(thread),
                    single_step,
                })
                .map_err(err_box)
        }

        pub fn suspend(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Suspend { thread: openxbdm_client::commands::ThreadId(thread) })
                .map_err(err_box)
        }

        pub fn resume(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Resume { thread: openxbdm_client::commands::ThreadId(thread) })
                .map_err(err_box)
        }

        pub fn isstopped(&self, thread: u32) -> Result<Box<OpenxbdmStopState>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::IsStopped { thread: openxbdm_client::commands::ThreadId(thread) })
                .map(|s| Box::new(OpenxbdmStopState::from(s)))
                .map_err(err_box)
        }

        /// `isbreak`: returns the breakpoint kind as a `u32` (0=None,
        /// 1=Execution, 2=DataRead, 3=DataWrite, 4=DataReadWrite,
        /// 5=DataExecute, or the raw value for anything else).
        pub fn isbreak(&self, address: u32) -> Result<u32, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::IsBreak { address })
                .map(|k| match k {
                    openxbdm_client::commands::BreakpointKind::None => 0,
                    openxbdm_client::commands::BreakpointKind::Execution => 1,
                    openxbdm_client::commands::BreakpointKind::DataRead => 2,
                    openxbdm_client::commands::BreakpointKind::DataWrite => 3,
                    openxbdm_client::commands::BreakpointKind::DataReadWrite => 4,
                    openxbdm_client::commands::BreakpointKind::DataExecute => 5,
                    openxbdm_client::commands::BreakpointKind::Unknown(raw) => raw,
                })
                .map_err(err_box)
        }

        pub fn set_breakpoint(&self, address: u32, clear: bool) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Breakpoint { address, clear }).map_err(err_box)
        }

        pub fn set_initial_breakpoint(&self) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::SetInitialBreakpoint).map_err(err_box)
        }

        /// `break` with READ/WRITE/READWRITE/EXECUTE kind. `kind` is the
        /// same encoding used by [`OpenxbdmClient::isbreak`]: 2=Read,
        /// 3=Write, 4=ReadWrite, 5=Execute. Other values are rejected.
        pub fn set_data_breakpoint(
            &self,
            address: u32,
            size: u32,
            kind: u32,
            clear: bool,
        ) -> Result<(), Box<OpenxbdmError>> {
            let kind = match kind {
                2 => openxbdm_client::commands::DataBreakKind::Read,
                3 => openxbdm_client::commands::DataBreakKind::Write,
                4 => openxbdm_client::commands::DataBreakKind::ReadWrite,
                5 => openxbdm_client::commands::DataBreakKind::Execute,
                other => {
                    return Err(Box::new(OpenxbdmError(format!("invalid data breakpoint kind {other}"))));
                }
            };
            self.0.run(openxbdm_client::commands::DataBreakpoint { address, size, kind, clear }).map_err(err_box)
        }

        pub fn clear_all_breakpoints(&self) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::ClearAllBreakpoints).map_err(err_box)
        }

        /// `reboot`: reboot the console. Pass empty strings for `title`/
        /// `directory`/`cmd_line` to omit them.
        pub fn reboot(
            &self,
            warm: bool,
            stop_on_start: bool,
            no_debug: bool,
            wait: bool,
            title: &str,
            directory: &str,
            cmd_line: &str,
        ) -> Result<(), Box<OpenxbdmError>> {
            let opt = |s: &str| {
                if s.is_empty() { None } else { Some(s.to_owned()) }
            };
            self.0
                .run(openxbdm_client::commands::Reboot {
                    flags: openxbdm_client::commands::RebootFlags { warm, stop_on_start, no_debug, wait },
                    title: opt(title),
                    directory: opt(directory),
                    cmd_line: opt(cmd_line),
                })
                .map_err(err_box)
        }

        pub fn set_title(&self, name: &str) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Title::Set { name: name.to_owned() }).map_err(err_box)
        }

        pub fn clear_title(&self) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Title::NoPersist).map_err(err_box)
        }

        pub fn stopon(&self, flags: &OpenxbdmStopOnFlags) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::StopOn(flags.to_client())).map_err(err_box)
        }

        pub fn nostopon(&self, flags: &OpenxbdmStopOnFlags) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::NoStopOn(flags.to_client())).map_err(err_box)
        }

        pub fn notify(
            &self,
            port: u16,
            reverse: bool,
            drop_on_reconnect: bool,
        ) -> Result<Box<OpenxbdmNotifyReply>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Notify { reconnect_port: port, reverse, drop_on_reconnect })
                .map(|r| Box::new(OpenxbdmNotifyReply::from(r)))
                .map_err(err_box)
        }

        pub fn modules(&self) -> Result<Box<OpenxbdmModules>, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::Modules).map(|v| Box::new(OpenxbdmModules(v))).map_err(err_box)
        }

        pub fn module_sections(&self, module: &str) -> Result<Box<OpenxbdmModuleSections>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::ModuleSections { module: module.to_owned() })
                .map(|v| Box::new(OpenxbdmModuleSections(v)))
                .map_err(err_box)
        }

        pub fn threads(&self) -> Result<Box<OpenxbdmThreadIds>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::Threads)
                .map(|v| Box::new(OpenxbdmThreadIds(v.into_iter().map(|t| t.as_u32()).collect())))
                .map_err(err_box)
        }

        pub fn thread_info(&self, thread: u32) -> Result<Box<OpenxbdmThreadDetail>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::ThreadInfo { thread: openxbdm_client::commands::ThreadId(thread) })
                .map(|d| Box::new(OpenxbdmThreadDetail::from(d)))
                .map_err(err_box)
        }

        /// `xbeinfo RUNNING`: metadata for the currently loaded title.
        pub fn xbeinfo_running(&self) -> Result<Box<OpenxbdmXbeInfo>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::XbeInfo::Running)
                .map(|r| Box::new(OpenxbdmXbeInfo::from(r)))
                .map_err(err_box)
        }

        /// `xbeinfo NAME="..."`: metadata for a specific `.xex` / `.xbe` on disk.
        pub fn xbeinfo_named(&self, path: &str) -> Result<Box<OpenxbdmXbeInfo>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::XbeInfo::Named(path.to_owned()))
                .map(|r| Box::new(OpenxbdmXbeInfo::from(r)))
                .map_err(err_box)
        }

        pub fn perf_counter_list(&self) -> Result<Box<OpenxbdmPerfCounters>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::PerfCounterList)
                .map(|v| Box::new(OpenxbdmPerfCounters(v)))
                .map_err(err_box)
        }

        pub fn query_perf_counter(
            &self,
            name: &str,
            kind: u32,
        ) -> Result<Box<OpenxbdmPerfCounterSample>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::QueryPerfCounter { name: name.to_owned(), kind })
                .map(|s| Box::new(OpenxbdmPerfCounterSample { kind: s.kind, value: s.value, rate: s.rate }))
                .map_err(err_box)
        }

        pub fn get_socket_info(&self) -> Result<Box<OpenxbdmSockets>, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::GetSocketInfo).map(|v| Box::new(OpenxbdmSockets(v))).map_err(err_box)
        }

        pub fn getmem(&self, address: u32, length: u32) -> Result<Box<OpenxbdmMemorySnapshot>, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::GetMem { address, length })
                .map(|s| Box::new(OpenxbdmMemorySnapshot::from(s)))
                .map_err(err_box)
        }

        /// `setmem`: write `data` starting at `address`. Returns the number
        /// of bytes the kernel actually accepted (may be shorter than
        /// `data.len()` if an unmapped page aborted the write).
        pub fn setmem(&self, address: u32, data: &[u8]) -> Result<u32, Box<OpenxbdmError>> {
            self.0
                .run(openxbdm_client::commands::SetMem { address, data: data.to_vec() })
                .map(|w| w.written)
                .map_err(err_box)
        }

        pub fn walkmem(&self) -> Result<Box<OpenxbdmVirtualRegions>, Box<OpenxbdmError>> {
            self.0.run(openxbdm_client::commands::WalkMem).map(|v| Box::new(OpenxbdmVirtualRegions(v))).map_err(err_box)
        }

        /// `screenshot`: capture the current HDMI scanout.
        pub fn screenshot(&self) -> Result<Box<OpenxbdmScreenshot>, Box<OpenxbdmError>> {
            self.0.screenshot().map(|s| Box::new(OpenxbdmScreenshot::from(s))).map_err(err_box)
        }
    }

    /// `getnetaddrs` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmNetAddrs {
        pub(crate) name: String,
        pub(crate) debug: Vec<u8>,
        pub(crate) title: Vec<u8>,
    }

    impl OpenxbdmNetAddrs {
        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }
        pub fn debug_len(&self) -> usize {
            self.debug.len()
        }
        pub fn copy_debug(&self, dst: &mut [u8]) -> usize {
            let n = self.debug.len().min(dst.len());
            dst[..n].copy_from_slice(&self.debug[..n]);
            n
        }
        pub fn title_len(&self) -> usize {
            self.title.len()
        }
        pub fn copy_title(&self, dst: &mut [u8]) -> usize {
            let n = self.title.len().min(dst.len());
            dst[..n].copy_from_slice(&self.title[..n]);
            n
        }
    }

    /// `drivefreespace` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmDriveSpace {
        pub(crate) free_to_caller: u64,
        pub(crate) total: u64,
        pub(crate) total_free: u64,
    }

    impl OpenxbdmDriveSpace {
        pub fn free_to_caller_bytes(&self) -> u64 {
            self.free_to_caller
        }
        pub fn total_bytes(&self) -> u64 {
            self.total
        }
        pub fn total_free_bytes(&self) -> u64 {
            self.total_free
        }
    }

    /// `dirlist` reply: list of entries.
    #[diplomat::opaque]
    pub struct OpenxbdmDirEntries(pub(crate) Vec<openxbdm_client::commands::DirEntry>);

    impl OpenxbdmDirEntries {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let e = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", e.name);
            Ok(())
        }
        pub fn size(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            self.0.get(idx).map(|e| e.size).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
        pub fn create_time(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .map(|e| e.create_time.as_raw())
                .ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
        pub fn change_time(&self, idx: usize) -> Result<u64, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .map(|e| e.change_time.as_raw())
                .ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
        pub fn is_directory(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .map(|e| e.is_directory)
                .ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `getfileattributes` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmFileAttributes {
        pub(crate) size: u64,
        pub(crate) create_time: u64,
        pub(crate) change_time: u64,
        pub(crate) is_directory: bool,
    }

    impl OpenxbdmFileAttributes {
        pub fn size(&self) -> u64 {
            self.size
        }
        pub fn create_time(&self) -> u64 {
            self.create_time
        }
        pub fn change_time(&self) -> u64 {
            self.change_time
        }
        pub fn is_directory(&self) -> bool {
            self.is_directory
        }
    }

    /// `isstopped` reply. Flattened: `kind()` returns a discriminant;
    /// field accessors are valid only for the matching kind.
    ///
    /// Kinds: 0=Running, 1=Breakpoint, 2=DataBreakpoint, 3=SingleStep,
    /// 4=Exception, 5=HardwareDebug, 6=Assertion, 7=Other.
    #[diplomat::opaque]
    pub struct OpenxbdmStopState {
        pub(crate) kind: u32,
        pub(crate) address: u32,
        pub(crate) access: u32,
        pub(crate) code: u32,
        pub(crate) other: String,
    }

    impl From<openxbdm_client::commands::StopState> for OpenxbdmStopState {
        fn from(s: openxbdm_client::commands::StopState) -> Self {
            match s {
                openxbdm_client::commands::StopState::Running => {
                    Self { kind: 0, address: 0, access: 0, code: 0, other: String::new() }
                }
                openxbdm_client::commands::StopState::Halted(reason) => match reason {
                    openxbdm_client::commands::StopReason::Breakpoint { address } => {
                        Self { kind: 1, address, access: 0, code: 0, other: String::new() }
                    }
                    openxbdm_client::commands::StopReason::DataBreakpoint { address, access } => Self {
                        kind: 2,
                        address,
                        access: match access {
                            openxbdm_client::commands::DataAccess::Read => 2,
                            openxbdm_client::commands::DataAccess::Write => 3,
                            openxbdm_client::commands::DataAccess::ReadWrite => 4,
                            openxbdm_client::commands::DataAccess::Execute => 5,
                            openxbdm_client::commands::DataAccess::Unknown(raw) => raw,
                        },
                        code: 0,
                        other: String::new(),
                    },
                    openxbdm_client::commands::StopReason::SingleStep => {
                        Self { kind: 3, address: 0, access: 0, code: 0, other: String::new() }
                    }
                    openxbdm_client::commands::StopReason::Exception { code } => {
                        Self { kind: 4, address: 0, access: 0, code, other: String::new() }
                    }
                    openxbdm_client::commands::StopReason::HardwareDebug => {
                        Self { kind: 5, address: 0, access: 0, code: 0, other: String::new() }
                    }
                    openxbdm_client::commands::StopReason::Assertion => {
                        Self { kind: 6, address: 0, access: 0, code: 0, other: String::new() }
                    }
                    openxbdm_client::commands::StopReason::Other(s) => {
                        Self { kind: 7, address: 0, access: 0, code: 0, other: s }
                    }
                },
            }
        }
    }

    impl OpenxbdmStopState {
        pub fn kind(&self) -> u32 {
            self.kind
        }
        /// Valid when kind is 1 (Breakpoint) or 2 (DataBreakpoint).
        pub fn address(&self) -> u32 {
            self.address
        }
        /// Valid when kind is 2 (DataBreakpoint): 2=Read, 3=Write,
        /// 4=ReadWrite, 5=Execute, other=raw `access` value.
        pub fn access(&self) -> u32 {
            self.access
        }
        /// Valid when kind is 4 (Exception): the exception code.
        pub fn exception_code(&self) -> u32 {
            self.code
        }
        /// Valid when kind is 7 (Other): the raw response head text.
        pub fn other(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.other);
        }
    }

    /// Stop-on / nostopon flag set.
    #[diplomat::opaque]
    pub struct OpenxbdmStopOnFlags {
        pub(crate) inner: std::cell::Cell<openxbdm_client::commands::StopOnFlags>,
    }

    impl OpenxbdmStopOnFlags {
        #[diplomat::attr(auto, constructor)]
        pub fn new() -> Box<OpenxbdmStopOnFlags> {
            Box::new(OpenxbdmStopOnFlags {
                inner: std::cell::Cell::new(openxbdm_client::commands::StopOnFlags::default()),
            })
        }
        pub fn set_create_thread(&self, v: bool) {
            let mut f = self.inner.get();
            f.create_thread = v;
            self.inner.set(f);
        }
        pub fn set_first_chance_exception(&self, v: bool) {
            let mut f = self.inner.get();
            f.first_chance_exception = v;
            self.inner.set(f);
        }
        pub fn set_debugstr(&self, v: bool) {
            let mut f = self.inner.get();
            f.debugstr = v;
            self.inner.set(f);
        }
        pub fn set_stacktrace(&self, v: bool) {
            let mut f = self.inner.get();
            f.stacktrace = v;
            self.inner.set(f);
        }
        pub fn set_title_init(&self, v: bool) {
            let mut f = self.inner.get();
            f.title_init = v;
            self.inner.set(f);
        }
        pub fn set_title_exit(&self, v: bool) {
            let mut f = self.inner.get();
            f.title_exit = v;
            self.inner.set(f);
        }
        pub fn set_debugger(&self, v: bool) {
            let mut f = self.inner.get();
            f.debugger = v;
            self.inner.set(f);
        }
        pub fn set_all(&self, v: bool) {
            let mut f = self.inner.get();
            f.all = v;
            self.inner.set(f);
        }
    }

    impl OpenxbdmStopOnFlags {
        fn to_client(&self) -> openxbdm_client::commands::StopOnFlags {
            self.inner.get()
        }
    }

    /// `notify` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmNotifyReply {
        pub(crate) port_present: bool,
        pub(crate) port: u16,
        pub(crate) raw: String,
    }

    impl From<openxbdm_client::commands::NotifyReply> for OpenxbdmNotifyReply {
        fn from(r: openxbdm_client::commands::NotifyReply) -> Self {
            Self { port_present: r.reconnect_port.is_some(), port: r.reconnect_port.unwrap_or(0), raw: r.raw }
        }
    }

    impl OpenxbdmNotifyReply {
        pub fn has_reconnect_port(&self) -> bool {
            self.port_present
        }
        pub fn reconnect_port(&self) -> u16 {
            self.port
        }
        pub fn raw(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.raw);
        }
    }

    /// `modules` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmModules(pub(crate) Vec<openxbdm_client::commands::ModuleInfo>);

    impl OpenxbdmModules {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let m = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", m.name);
            Ok(())
        }
        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.base)
        }
        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.size)
        }
        pub fn checksum(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.checksum)
        }
        pub fn timestamp(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.timestamp)
        }
        pub fn pdata(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.pdata)
        }
        pub fn psize(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.psize)
        }
        pub fn thread(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.thread)
        }
        pub fn osize(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |m| m.osize)
        }
        pub fn is_dll(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            self.field(idx, |m| m.is_dll)
        }
        pub fn is_tls(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            self.field(idx, |m| m.is_tls)
        }
        pub fn is_xbe(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            self.field(idx, |m| m.is_xbe)
        }
    }

    impl OpenxbdmModules {
        fn field<T>(
            &self,
            idx: usize,
            f: impl FnOnce(&openxbdm_client::commands::ModuleInfo) -> T,
        ) -> Result<T, Box<OpenxbdmError>> {
            self.0.get(idx).map(f).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `modsections` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmModuleSections(pub(crate) Vec<openxbdm_client::commands::ModuleSection>);

    impl OpenxbdmModuleSections {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let s = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", s.name);
            Ok(())
        }
        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.base)
        }
        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.size)
        }
        pub fn index(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.index)
        }
        pub fn flags(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.flags.0)
        }
    }

    impl OpenxbdmModuleSections {
        fn field<T>(
            &self,
            idx: usize,
            f: impl FnOnce(&openxbdm_client::commands::ModuleSection) -> T,
        ) -> Result<T, Box<OpenxbdmError>> {
            self.0.get(idx).map(f).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `threads` reply: list of thread ids.
    #[diplomat::opaque]
    pub struct OpenxbdmThreadIds(pub(crate) Vec<u32>);

    impl OpenxbdmThreadIds {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn get(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.0.get(idx).copied().ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `threadinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmThreadDetail {
        pub(crate) thread: u32,
        pub(crate) suspend: u32,
        pub(crate) priority: i32,
        pub(crate) tls_base: u32,
        pub(crate) start: u32,
        pub(crate) base: u32,
        pub(crate) limit: u32,
        pub(crate) slack: u32,
        pub(crate) create_time: u64,
        pub(crate) name_address: u32,
        pub(crate) name_length: u32,
        pub(crate) processor: u32,
        pub(crate) last_error: u32,
    }

    impl From<openxbdm_client::commands::ThreadDetail> for OpenxbdmThreadDetail {
        fn from(d: openxbdm_client::commands::ThreadDetail) -> Self {
            Self {
                thread: d.thread.as_u32(),
                suspend: d.suspend,
                priority: d.priority,
                tls_base: d.tls_base,
                start: d.start,
                base: d.base,
                limit: d.limit,
                slack: d.slack,
                create_time: d.create_time.as_raw(),
                name_address: d.name_address,
                name_length: d.name_length,
                processor: d.processor,
                last_error: d.last_error,
            }
        }
    }

    impl OpenxbdmThreadDetail {
        pub fn thread(&self) -> u32 {
            self.thread
        }
        pub fn suspend(&self) -> u32 {
            self.suspend
        }
        pub fn priority(&self) -> i32 {
            self.priority
        }
        pub fn tls_base(&self) -> u32 {
            self.tls_base
        }
        pub fn start(&self) -> u32 {
            self.start
        }
        pub fn base(&self) -> u32 {
            self.base
        }
        pub fn limit(&self) -> u32 {
            self.limit
        }
        pub fn slack(&self) -> u32 {
            self.slack
        }
        pub fn create_time(&self) -> u64 {
            self.create_time
        }
        pub fn name_address(&self) -> u32 {
            self.name_address
        }
        pub fn name_length(&self) -> u32 {
            self.name_length
        }
        pub fn processor(&self) -> u32 {
            self.processor
        }
        pub fn last_error(&self) -> u32 {
            self.last_error
        }
    }

    /// `xbeinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmXbeInfo {
        pub(crate) timestamp: u32,
        pub(crate) checksum: u32,
        pub(crate) name: String,
    }

    impl From<openxbdm_client::commands::XbeInfoResult> for OpenxbdmXbeInfo {
        fn from(r: openxbdm_client::commands::XbeInfoResult) -> Self {
            Self { timestamp: r.timestamp, checksum: r.checksum, name: r.name }
        }
    }

    impl OpenxbdmXbeInfo {
        pub fn timestamp(&self) -> u32 {
            self.timestamp
        }
        pub fn checksum(&self) -> u32 {
            self.checksum
        }
        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }
    }

    /// `pclist` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmPerfCounters(pub(crate) Vec<openxbdm_client::commands::PerfCounterEntry>);

    impl OpenxbdmPerfCounters {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let e = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", e.name);
            Ok(())
        }
        pub fn kind(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.0.get(idx).map(|e| e.kind).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `querypc` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmPerfCounterSample {
        pub(crate) kind: u32,
        pub(crate) value: u64,
        pub(crate) rate: u64,
    }

    impl OpenxbdmPerfCounterSample {
        pub fn kind(&self) -> u32 {
            self.kind
        }
        pub fn value(&self) -> u64 {
            self.value
        }
        pub fn rate(&self) -> u64 {
            self.rate
        }
    }

    /// `getsockinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmSockets(pub(crate) Vec<openxbdm_client::commands::SocketEntry>);

    impl OpenxbdmSockets {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn handle(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.handle)
        }
        pub fn owner_type(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.owner_type)
        }
        pub fn flags(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.flags)
        }
        pub fn addr_family(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.addr_family)
        }
        pub fn socket_type(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.socket_type)
        }
        pub fn protocol(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.protocol)
        }
        pub fn local_addr(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.local_addr)
        }
        pub fn remote_addr(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.remote_addr)
        }
        pub fn local_port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            self.field(idx, |s| s.local_port)
        }
        pub fn remote_port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            self.field(idx, |s| s.remote_port)
        }
        pub fn tcp_state(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |s| s.tcp_state)
        }
    }

    impl OpenxbdmSockets {
        fn field<T>(
            &self,
            idx: usize,
            f: impl FnOnce(&openxbdm_client::commands::SocketEntry) -> T,
        ) -> Result<T, Box<OpenxbdmError>> {
            self.0.get(idx).map(f).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `getmem` reply: raw bytes plus the offsets the kernel flagged as
    /// unmapped (`??`).
    #[diplomat::opaque]
    pub struct OpenxbdmMemorySnapshot {
        pub(crate) address: u32,
        pub(crate) data: Vec<u8>,
        pub(crate) unmapped: Vec<u32>,
    }

    impl From<openxbdm_client::commands::MemorySnapshot> for OpenxbdmMemorySnapshot {
        fn from(s: openxbdm_client::commands::MemorySnapshot) -> Self {
            Self { address: s.address, data: s.data, unmapped: s.unmapped_offsets }
        }
    }

    impl OpenxbdmMemorySnapshot {
        pub fn address(&self) -> u32 {
            self.address
        }
        pub fn data_len(&self) -> usize {
            self.data.len()
        }
        pub fn copy_data(&self, dst: &mut [u8]) -> usize {
            let n = self.data.len().min(dst.len());
            dst[..n].copy_from_slice(&self.data[..n]);
            n
        }
        pub fn unmapped_len(&self) -> usize {
            self.unmapped.len()
        }
        pub fn unmapped_at(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.unmapped.get(idx).copied().ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `walkmem` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmVirtualRegions(pub(crate) Vec<openxbdm_client::commands::VirtualRegion>);

    impl OpenxbdmVirtualRegions {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |r| r.base)
        }
        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |r| r.size)
        }
        pub fn protect(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.field(idx, |r| r.protect)
        }
    }

    impl OpenxbdmVirtualRegions {
        fn field<T>(
            &self,
            idx: usize,
            f: impl FnOnce(&openxbdm_client::commands::VirtualRegion) -> T,
        ) -> Result<T, Box<OpenxbdmError>> {
            self.0.get(idx).map(f).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
    }

    /// `screenshot` reply: the raw framebuffer plus its metadata.
    #[diplomat::opaque]
    pub struct OpenxbdmScreenshot {
        pub(crate) pitch: u32,
        pub(crate) width: u32,
        pub(crate) height: u32,
        pub(crate) format_raw: u32,
        pub(crate) is_linear_xrgb8888: bool,
        pub(crate) offset_x: u32,
        pub(crate) offset_y: u32,
        pub(crate) framebuffer_size: u32,
        pub(crate) shown_width: u32,
        pub(crate) shown_height: u32,
        pub(crate) colorspace: u32,
        pub(crate) data: Vec<u8>,
    }

    impl From<openxbdm_client::commands::Screenshot> for OpenxbdmScreenshot {
        fn from(s: openxbdm_client::commands::Screenshot) -> Self {
            let meta = s.metadata;
            Self {
                pitch: meta.pitch,
                width: meta.width,
                height: meta.height,
                format_raw: meta.format.raw(),
                is_linear_xrgb8888: meta.format.is_linear_xrgb8888(),
                offset_x: meta.offset_x,
                offset_y: meta.offset_y,
                framebuffer_size: meta.framebuffer_size,
                shown_width: meta.shown_width,
                shown_height: meta.shown_height,
                colorspace: meta.colorspace,
                data: s.data,
            }
        }
    }

    impl OpenxbdmScreenshot {
        pub fn pitch(&self) -> u32 {
            self.pitch
        }
        pub fn width(&self) -> u32 {
            self.width
        }
        pub fn height(&self) -> u32 {
            self.height
        }
        /// Raw XBDM pixel-format value with the `0x80000000` ready-marker
        /// stripped.
        pub fn format_raw(&self) -> u32 {
            self.format_raw
        }
        /// True when the format is a known linear 32-bit XRGB layout that
        /// the built-in RGBA8 decoder understands.
        pub fn is_linear_xrgb8888(&self) -> bool {
            self.is_linear_xrgb8888
        }
        pub fn offset_x(&self) -> u32 {
            self.offset_x
        }
        pub fn offset_y(&self) -> u32 {
            self.offset_y
        }
        pub fn framebuffer_size(&self) -> u32 {
            self.framebuffer_size
        }
        pub fn shown_width(&self) -> u32 {
            self.shown_width
        }
        pub fn shown_height(&self) -> u32 {
            self.shown_height
        }
        pub fn colorspace(&self) -> u32 {
            self.colorspace
        }

        pub fn data_len(&self) -> usize {
            self.data.len()
        }
        pub fn copy_data(&self, dst: &mut [u8]) -> usize {
            let n = self.data.len().min(dst.len());
            dst[..n].copy_from_slice(&self.data[..n]);
            n
        }

        /// Decode the raw framebuffer into a `width * height * 4` RGBA
        /// byte buffer. Returns a zero-length handle when the pixel
        /// format isn't a known linear XRGB layout.
        pub fn to_rgba8(&self) -> Box<OpenxbdmBytes> {
            // We lost the typed metadata when we flattened; rebuild just
            // enough to reuse the upstream detiler.
            if !self.is_linear_xrgb8888 {
                return Box::new(OpenxbdmBytes(Vec::new()));
            }
            let w = self.width as usize;
            let h = self.height as usize;
            if w * h * 4 > self.data.len() {
                return Box::new(OpenxbdmBytes(Vec::new()));
            }
            let linear = openxbdm_client::commands::screenshot::detile_2d_32bpp(&self.data, self.width, self.height);
            let mut rgba = Vec::with_capacity(linear.len());
            for chunk in linear.as_chunks::<4>().0 {
                let (b, g, r, _x) = (chunk[0], chunk[1], chunk[2], chunk[3]);
                rgba.extend_from_slice(&[r, g, b, 0xFF]);
            }
            Box::new(OpenxbdmBytes(rgba))
        }
    }

    /// NAP-discovery helpers. These are free functions that open a fresh
    /// UDP socket per call; no persistent client is involved.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscovery;

    impl OpenxbdmDiscovery {
        /// Broadcast a `whatisyourname` request and collect replies for
        /// up to `timeout_ms` milliseconds.
        pub fn discover_all(timeout_ms: u32) -> Result<Box<OpenxbdmDiscoveredConsoles>, Box<OpenxbdmError>> {
            crate::inner::discover_all_blocking(timeout_ms)
                .map(|v| Box::new(OpenxbdmDiscoveredConsoles::from_vec(v)))
                .map_err(|e| Box::new(OpenxbdmError(e)))
        }

        /// Broadcast a targeted `lookup name` request; returns the first
        /// matching reply or an error if none arrive within `timeout_ms`.
        pub fn find_by_name(name: &str, timeout_ms: u32) -> Result<Box<OpenxbdmDiscoveredConsole>, Box<OpenxbdmError>> {
            match crate::inner::find_by_name_blocking(name, timeout_ms) {
                Ok(Some(c)) => Ok(Box::new(OpenxbdmDiscoveredConsole::from(c))),
                Ok(None) => Err(Box::new(OpenxbdmError(format!("no reply from {name:?} within {timeout_ms}ms")))),
                Err(e) => Err(Box::new(OpenxbdmError(e))),
            }
        }
    }

    /// One console reply from NAP discovery.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscoveredConsole {
        pub(crate) name: String,
        pub(crate) ip_octets: [u8; 16],
        pub(crate) is_ipv6: bool,
        pub(crate) port: u16,
    }

    impl From<openxbdm_client::discovery::DiscoveredConsole> for OpenxbdmDiscoveredConsole {
        fn from(c: openxbdm_client::discovery::DiscoveredConsole) -> Self {
            let mut octets = [0u8; 16];
            let is_ipv6 = match c.addr {
                std::net::SocketAddr::V4(v4) => {
                    octets[..4].copy_from_slice(&v4.ip().octets());
                    false
                }
                std::net::SocketAddr::V6(v6) => {
                    octets.copy_from_slice(&v6.ip().octets());
                    true
                }
            };
            Self { name: c.name, ip_octets: octets, is_ipv6, port: c.addr.port() }
        }
    }

    impl OpenxbdmDiscoveredConsole {
        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }
        pub fn is_ipv6(&self) -> bool {
            self.is_ipv6
        }
        pub fn port(&self) -> u16 {
            self.port
        }
        /// Copy the socket address octets: first 4 bytes are valid when
        /// `is_ipv6()` is false; all 16 are valid when it is true.
        /// Returns the number of meaningful bytes (4 or 16).
        pub fn copy_ip(&self, dst: &mut [u8]) -> usize {
            let n = if self.is_ipv6 { 16 } else { 4 };
            let n = n.min(dst.len());
            dst[..n].copy_from_slice(&self.ip_octets[..n]);
            n
        }
    }

    /// Collection of discovery replies.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscoveredConsoles(pub(crate) Vec<OpenxbdmDiscoveredConsole>);

    impl OpenxbdmDiscoveredConsoles {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let c = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let _ = write!(out, "{}", c.name);
            Ok(())
        }
        pub fn port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            self.0.get(idx).map(|c| c.port).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
        pub fn is_ipv6(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .map(|c| c.is_ipv6)
                .ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))
        }
        pub fn copy_ip(&self, idx: usize, dst: &mut [u8]) -> Result<usize, Box<OpenxbdmError>> {
            let c = self.0.get(idx).ok_or_else(|| Box::new(OpenxbdmError(format!("index {idx} out of range"))))?;
            let n = if c.is_ipv6 { 16 } else { 4 };
            let n = n.min(dst.len());
            dst[..n].copy_from_slice(&c.ip_octets[..n]);
            Ok(n)
        }
    }

    impl OpenxbdmDiscoveredConsoles {
        fn from_vec(v: Vec<openxbdm_client::discovery::DiscoveredConsole>) -> Self {
            Self(v.into_iter().map(OpenxbdmDiscoveredConsole::from).collect())
        }
    }

    fn err_box(msg: String) -> Box<OpenxbdmError> {
        Box::new(OpenxbdmError(msg))
    }
}
