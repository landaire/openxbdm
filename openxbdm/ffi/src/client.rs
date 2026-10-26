#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands;

    use crate::blocking::BlockingClient;
    use crate::buffers::ffi::OpenxbdmStringList;
    use crate::debugger::ffi::OpenxbdmStopOnFlags;
    use crate::debugger::ffi::OpenxbdmStopState;
    use crate::error::ffi::OpenxbdmError;
    use crate::filesystem::ffi::FileEofDisposition;
    use crate::filesystem::ffi::OpenxbdmDirEntries;
    use crate::filesystem::ffi::OpenxbdmDriveSpace;
    use crate::filesystem::ffi::OpenxbdmFileAttributes;
    use crate::memory::ffi::OpenxbdmMemorySnapshot;
    use crate::memory::ffi::OpenxbdmVirtualRegions;
    use crate::network::ffi::OpenxbdmNetAddrs;
    use crate::network::ffi::OpenxbdmSockets;
    use crate::performance::ffi::OpenxbdmPerfCounterSample;
    use crate::performance::ffi::OpenxbdmPerfCounters;
    use crate::process::ffi::OpenxbdmModuleSections;
    use crate::process::ffi::OpenxbdmModules;
    use crate::process::ffi::OpenxbdmThreadDetail;
    use crate::process::ffi::OpenxbdmThreadIds;
    use crate::process::ffi::OpenxbdmXbeInfo;
    use crate::screenshot::ffi::OpenxbdmScreenshot;
    use crate::time::ffi::OpenxbdmFileTime;

    /// Connected XBDM client. Internally owns a tokio runtime and a
    /// borrowed `openxbdm_client::Client`; all methods block the calling thread
    /// while the I/O completes.
    #[diplomat::opaque]
    pub struct OpenxbdmClient(BlockingClient);

    impl OpenxbdmClient {
        /// Connect to `address` (e.g. `"192.168.1.26:730"`, `"deanxbox:730"`)
        /// with a connect timeout in seconds.
        #[diplomat::attr(auto, named_constructor = "connect")]
        pub fn connect(
            address: &str,
            timeout_secs: u32,
        ) -> Result<Box<OpenxbdmClient>, Box<OpenxbdmError>> {
            let client = BlockingClient::connect(address, timeout_secs)?;

            Ok(Box::new(OpenxbdmClient(client)))
        }

        /// `dbgname`: read the console's debuggable name into `out`.
        pub fn dbgname(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let name = self.0.run(commands::DbgName::Get)?;
            let _ = write!(out, "{name}");

            Ok(())
        }

        /// `dbgname name=<name>`: set the console's debuggable name.
        pub fn set_dbgname(&self, name: &str) -> Result<(), Box<OpenxbdmError>> {
            self.0.run(commands::DbgName::Set(name.to_owned()))?;

            Ok(())
        }

        /// `systime`: console clock as a `FileTime`.
        pub fn systime(&self) -> Result<Box<OpenxbdmFileTime>, Box<OpenxbdmError>> {
            let time = self.0.run(commands::SysTime)?;

            Ok(Box::new(OpenxbdmFileTime(time.file_time)))
        }

        /// `dmversion`: opaque build identifier.
        pub fn dmversion(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let version = self.0.run(commands::DmVersion)?;
            let _ = write!(out, "{version}");

            Ok(())
        }

        /// `consoletype`: returns "devkit" or "testkit".
        pub fn consoletype(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let console_type = match self.0.run(commands::GetConsoleType)? {
                commands::ConsoleType::DevKit => "devkit",
                commands::ConsoleType::TestKit => "testkit",
            };
            let _ = write!(out, "{console_type}");

            Ok(())
        }

        /// `consolefeatures`: list of feature flags the kernel advertises.
        pub fn consolefeatures(&self) -> Result<Box<OpenxbdmStringList>, Box<OpenxbdmError>> {
            let features = self.0.run(commands::GetConsoleFeatures)?;

            Ok(Box::new(OpenxbdmStringList(features.flags)))
        }

        /// `altaddr`: title IPv4 address as a host-order `u32`.
        pub fn altaddr(&self) -> Result<u32, Box<OpenxbdmError>> {
            Ok(u32::from(self.0.run(commands::AltAddr)?))
        }

        /// `getpid`: pid of the currently running title process.
        pub fn getpid(&self) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.0.run(commands::GetPid)?)
        }

        /// `consolemem`: memory configuration class (0, 1 or 2).
        pub fn consolemem(&self) -> Result<u8, Box<OpenxbdmError>> {
            let class = match self.0.run(commands::GetConsoleMem)? {
                commands::ConsoleMem::Standard => 0,
                commands::ConsoleMem::ExtraMemoryUnused => 1,
                commands::ConsoleMem::ExtraMemoryInUse => 2,
            };

            Ok(class)
        }

        /// `getnetaddrs`: console name + debug/title `sockaddr`-ish blobs.
        pub fn getnetaddrs(&self) -> Result<Box<OpenxbdmNetAddrs>, Box<OpenxbdmError>> {
            let addrs = self.0.run(commands::GetNetAddrs)?;

            Ok(Box::new(OpenxbdmNetAddrs::from(addrs)))
        }

        /// `drivelist`: drive labels (e.g. "D", "DEVKIT", "HDD").
        pub fn drivelist(&self) -> Result<Box<OpenxbdmStringList>, Box<OpenxbdmError>> {
            let drives = self.0.run(commands::DriveList)?;

            Ok(Box::new(OpenxbdmStringList(drives)))
        }

        /// `drivefreespace`: free and total byte counters for a drive.
        pub fn drivefreespace(
            &self,
            drive: &str,
        ) -> Result<Box<OpenxbdmDriveSpace>, Box<OpenxbdmError>> {
            let space = self.0.run(commands::DriveFreeSpace {
                drive: drive.to_owned(),
            })?;

            Ok(Box::new(OpenxbdmDriveSpace::from(space)))
        }

        /// `dirlist`: directory entries.
        pub fn dirlist(&self, path: &str) -> Result<Box<OpenxbdmDirEntries>, Box<OpenxbdmError>> {
            let entries = self.0.run(commands::DirList {
                path: path.to_owned(),
            })?;

            Ok(Box::new(OpenxbdmDirEntries(entries)))
        }

        /// `getfileattributes`: size + timestamps for a single path.
        pub fn getfileattributes(
            &self,
            path: &str,
        ) -> Result<Box<OpenxbdmFileAttributes>, Box<OpenxbdmError>> {
            let attributes = self.0.run(commands::GetFileAttributes {
                path: path.to_owned(),
            })?;

            Ok(Box::new(OpenxbdmFileAttributes::from(attributes)))
        }

        pub fn mkdir(&self, path: &str) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::MakeDirectory {
                path: path.to_owned(),
            })?)
        }

        pub fn delete(&self, path: &str, is_directory: bool) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Delete {
                path: path.to_owned(),
                is_directory,
            })?)
        }

        pub fn rename(&self, from: &str, to: &str) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Rename {
                from: from.to_owned(),
                to: to.to_owned(),
            })?)
        }

        pub fn fileeof(
            &self,
            path: &str,
            size: u32,
            disposition: FileEofDisposition,
        ) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::FileEof {
                path: path.to_owned(),
                size,
                disposition: disposition.into(),
            })?)
        }

        pub fn stop(&self) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Stop)?)
        }

        pub fn go(&self) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Go)?)
        }

        /// `halt`: stock XBDM always rejects it (`400- ` on development
        /// kits, `407- unknown command` on test kits).
        pub fn halt(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Halt {
                thread: commands::ThreadId(thread),
            })?)
        }

        /// `continue`: release a stopped thread. `pass_exception` marks the
        /// pending exception as not handled by the debugger.
        pub fn continue_thread(
            &self,
            thread: u32,
            pass_exception: bool,
        ) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Continue {
                thread: commands::ThreadId(thread),
                pass_exception,
            })?)
        }

        pub fn suspend(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Suspend {
                thread: commands::ThreadId(thread),
            })?)
        }

        pub fn resume(&self, thread: u32) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Resume {
                thread: commands::ThreadId(thread),
            })?)
        }

        pub fn isstopped(&self, thread: u32) -> Result<Box<OpenxbdmStopState>, Box<OpenxbdmError>> {
            let state = self.0.run(commands::IsStopped {
                thread: commands::ThreadId(thread),
            })?;

            Ok(Box::new(OpenxbdmStopState::from(state)))
        }

        /// `isbreak`: returns the stock `type=` value: 0 none, 4 execution,
        /// 1 data write, 2 data read/write, 5 data read.
        pub fn isbreak(&self, address: u32) -> Result<u32, Box<OpenxbdmError>> {
            let kind = self.0.run(commands::IsBreak { address })?;

            Ok(kind.code())
        }

        pub fn set_breakpoint(&self, address: u32, clear: bool) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Breakpoint { address, clear })?)
        }

        pub fn set_initial_breakpoint(&self) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::SetInitialBreakpoint)?)
        }

        /// `break` with a READ/WRITE/READWRITE kind. `kind` uses the
        /// [`OpenxbdmClient::isbreak`] data codes: 1=Write, 2=ReadWrite,
        /// 5=Read. Other values are rejected.
        pub fn set_data_breakpoint(
            &self,
            address: u32,
            size: u32,
            kind: u32,
            clear: bool,
        ) -> Result<(), Box<OpenxbdmError>> {
            let Some(commands::BreakpointKind::Data(data_kind)) =
                commands::BreakpointKind::from_code(kind)
            else {
                return Err(OpenxbdmError::new(format!(
                    "invalid data breakpoint kind {kind}"
                )));
            };

            Ok(self.0.run(commands::DataBreakpoint {
                address,
                size,
                kind: data_kind,
                clear,
            })?)
        }

        pub fn clear_all_breakpoints(&self) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::ClearAllBreakpoints)?)
        }

        /// `reboot`: reboot the console.
        pub fn reboot(
            &self,
            stop: bool,
            wait: bool,
            smc_reset: bool,
        ) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Reboot {
                stop,
                wait,
                smc_reset,
            })?)
        }

        /// `magicboot`: launch a title. Pass empty strings for `title`/
        /// `directory`/`cmd_line` to omit them.
        pub fn magic_boot(
            &self,
            cold: bool,
            wait: bool,
            stop: bool,
            title: &str,
            directory: &str,
            cmd_line: &str,
        ) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::MagicBoot {
                cold,
                wait,
                stop,
                title: non_empty(title),
                directory: non_empty(directory),
                cmd_line: non_empty(cmd_line),
            })?)
        }

        pub fn set_title(&self, name: &str) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Title::Set {
                name: name.to_owned(),
            })?)
        }

        pub fn clear_title(&self) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::Title::NoPersist)?)
        }

        pub fn stopon(&self, flags: &OpenxbdmStopOnFlags) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::StopOn(flags.flags()))?)
        }

        pub fn nostopon(&self, flags: &OpenxbdmStopOnFlags) -> Result<(), Box<OpenxbdmError>> {
            Ok(self.0.run(commands::NoStopOn(flags.flags()))?)
        }

        pub fn modules(&self) -> Result<Box<OpenxbdmModules>, Box<OpenxbdmError>> {
            let modules = self.0.run(commands::Modules)?;

            Ok(Box::new(OpenxbdmModules(modules)))
        }

        pub fn module_sections(
            &self,
            module: &str,
        ) -> Result<Box<OpenxbdmModuleSections>, Box<OpenxbdmError>> {
            let sections = self.0.run(commands::ModuleSections {
                module: module.to_owned(),
            })?;

            Ok(Box::new(OpenxbdmModuleSections(sections)))
        }

        pub fn threads(&self) -> Result<Box<OpenxbdmThreadIds>, Box<OpenxbdmError>> {
            let threads = self.0.run(commands::Threads)?;
            let ids = threads.into_iter().map(|thread| thread.as_u32()).collect();

            Ok(Box::new(OpenxbdmThreadIds(ids)))
        }

        pub fn thread_info(
            &self,
            thread: u32,
        ) -> Result<Box<OpenxbdmThreadDetail>, Box<OpenxbdmError>> {
            let detail = self.0.run(commands::ThreadInfo {
                thread: commands::ThreadId(thread),
            })?;

            Ok(Box::new(OpenxbdmThreadDetail::from(detail)))
        }

        /// `xbeinfo RUNNING`: metadata for the currently loaded title.
        pub fn xbeinfo_running(&self) -> Result<Box<OpenxbdmXbeInfo>, Box<OpenxbdmError>> {
            let info = self.0.run(commands::XbeInfo::Running)?;

            Ok(Box::new(OpenxbdmXbeInfo::from(info)))
        }

        /// `xbeinfo NAME="..."`: the console reports the running executable for
        /// any name.
        pub fn xbeinfo_named(
            &self,
            path: &str,
        ) -> Result<Box<OpenxbdmXbeInfo>, Box<OpenxbdmError>> {
            let info = self.0.run(commands::XbeInfo::Named(path.to_owned()))?;

            Ok(Box::new(OpenxbdmXbeInfo::from(info)))
        }

        pub fn perf_counter_list(&self) -> Result<Box<OpenxbdmPerfCounters>, Box<OpenxbdmError>> {
            let counters = self.0.run(commands::PerfCounterList)?;

            Ok(Box::new(OpenxbdmPerfCounters(counters)))
        }

        pub fn query_perf_counter(
            &self,
            name: &str,
            kind: u32,
        ) -> Result<Box<OpenxbdmPerfCounterSample>, Box<OpenxbdmError>> {
            let sample = self.0.run(commands::QueryPerfCounter {
                name: name.to_owned(),
                kind,
            })?;

            Ok(Box::new(OpenxbdmPerfCounterSample::from(sample)))
        }

        pub fn get_socket_info(&self) -> Result<Box<OpenxbdmSockets>, Box<OpenxbdmError>> {
            let sockets = self.0.run(commands::GetSocketInfo)?;

            Ok(Box::new(OpenxbdmSockets(sockets)))
        }

        pub fn getmem(
            &self,
            address: u32,
            length: u32,
        ) -> Result<Box<OpenxbdmMemorySnapshot>, Box<OpenxbdmError>> {
            let snapshot = self.0.run(commands::GetMem { address, length })?;

            Ok(Box::new(OpenxbdmMemorySnapshot::from(snapshot)))
        }

        /// `setmem`: write `data` starting at `address`. Returns the number
        /// of bytes the kernel actually accepted (may be shorter than
        /// `data.len()` if an unmapped page aborted the write).
        pub fn setmem(&self, address: u32, data: &[u8]) -> Result<u32, Box<OpenxbdmError>> {
            let written = self.0.run(commands::SetMem {
                address,
                data: data.to_vec(),
            })?;

            Ok(written.written)
        }

        pub fn walkmem(&self) -> Result<Box<OpenxbdmVirtualRegions>, Box<OpenxbdmError>> {
            let regions = self.0.run(commands::WalkMem)?;

            Ok(Box::new(OpenxbdmVirtualRegions(regions)))
        }

        /// `screenshot`: capture the current HDMI scanout.
        pub fn screenshot(&self) -> Result<Box<OpenxbdmScreenshot>, Box<OpenxbdmError>> {
            let screenshot = self.0.screenshot()?;

            Ok(Box::new(OpenxbdmScreenshot::from(screenshot)))
        }
    }

    /// Empty strings stand for an omitted `magicboot` argument.
    fn non_empty(value: &str) -> Option<String> {
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    }
}
