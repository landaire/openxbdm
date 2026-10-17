# Changelog

## Unreleased

### Server engine

- Add `openxbdm-server`, a `no_std`, allocation-free command engine with the stock dispatch rules (access masks, development-kit-only and own-thread flags, dedicated connections), continuations for 202/203/204 transfers, notification channels, command processors, and the settings file.
- Implement all 177 stock XBDM 2.0.21256.0 commands in eleven domains (session, security, console, system, file system, memory, debugger, network, performance, hardware, services) over per-domain backend traits.
- Move the protocol grammar, status codes, and authentication function shared by client and server into `openxbdm-core`.
- `openxbdm-core` takes `NtStatus`, `KernelError`, `Win32Error` and `Hresult` from `xbox360-sys`; the monitor's result codes and default reply texts are the `XbdmHresult` trait, `xbdm_success`, `xbdm_error` and `ErrorCode::hresult`.
- Keep status integers at the wire and the kernel/title ABI: handlers and continuations return `Result<Reply, CommandError>`, converted to the reply line's result in `send_status`; backend traits fail with `KernelError` (a kernel status with named variants and exact passthrough of others) or per-domain error enums; exports, control codes, and reply texts that print a code convert typed errors at that point. `ErrorCode` is an enum of the result-table codes, and `Win32Error` carries Win32 codes.
- Add the `smb` feature (default): every drive whose device exists, from the drive table and the internal drive mapping, is an SMB share served through `smb2-server`, with share identifiers common to all connections; logons need no password while security is off; while the console is locked, logons, opens, renames, and deletes fail. Optical drives and read-only volumes are read-only shares, and volume information comes from FileFsAttributeInformation. Change notifications report changes made by titles and XBDM through a scan of the watched directory every 2 seconds. Connections close without a logon after 30 seconds, when stalled for 30 seconds, and when idle without open files for 15 minutes; a full table replaces the oldest connection without a session, or else the one silent longest if silent for 5 minutes; a logon naming a previous session ends that session. File reads take a byte slice or a pool range (`ReadTarget`).

### SMB server

- Add `smb2-server`, a `no_std`, allocation-free, sans-io SMB 2 and SMB 3 file server: dialects 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1 (also from an SMB 1 multi-protocol negotiate) with 3.1.1 negotiate contexts, preauthentication integrity, and FSCTL_VALIDATE_NEGOTIATE_INFO; compound requests; NTLMv2 logons in SPNEGO or raw NTLMSSP; HMAC-SHA256, AES-CMAC, and AES-GMAC signing; AES-128-CCM and AES-128-GCM encryption; byte-range locks and change notification kept across a server's connections, with asynchronous replies and CANCEL; NT wildcard directory queries; file, file system and security information; and share enumeration through the `srvsvc` pipe. Failures are typed (`FsError` from backends, `AuthError`, `PipeError`, `PathError`) and become NT statuses only in replies.

### Host server

- Add `openxbdm-server-host`: the engine over std TCP sockets with one simulated console shared by all connections, and UDP name discovery.
- Add integration tests per domain that send every command to the host server over TCP.
- Run on Windows (writability through `WSAPoll`) and macOS, where a socket is reported writable only with a full transfer block of send space free, so a stalled reader does not block other connections.
- Serve SMB on `--smb-listen` (default `127.0.0.1:1445`) over the simulated volumes.

### Xbox 360 module

- Add console backends for every domain, the debug monitor control dispatcher (102 of 103 stock handler codes), and all 253 stock exports through `export!`/`export_raw!` and xex-link.
- Run server services inline under a startup lock until the command loop starts, so exports called during boot do not wait for the server thread.
- Threads wait for the server thread only while it runs its pass loop: debug events, thread notifications, and queued services take their default disposition before the first pass and after the loop stops, and thread notifications are posted without waiting unless the thread may stop.
- Enter the module entry point, the kernel debug routine, the thread notification, the control dispatcher, and the remaining kernel callbacks through the export bridge, and call console routines through frames that reserve the console argument area.
- Create the server thread with stock's flags, which make it not debuggable, and stock's 0x8000-byte stack: the server state is a static built at compile time, and the service loop keeps socket event handlers, continuations, and startup work in frames of their own.
- Build with `-Cpanic=immediate-abort`, and write text replies of every capacity through one non-generic writer.
- Add the `boot-guard` feature: a boot without `DEVKIT:\FlashEx\openxbdm.arm` removes the `DEVKIT:\FlashEx\xbdm.xex` override and restarts into the flash monitor.
- Deploy the module as `DEVKIT:\FlashEx\xbdm.xex` with a matching bounding path; it removes that file at startup.
- Pack the image on 4 KB pages (`.text` at `0x91f01000`; xex-link derives section alignment from the small-pages flag), so the image ends below xshell at `0x92000000`.
- Replace inline callee-saved register saves and restores with shared helpers (`xbox360-asm-rewrite` of rust-xbox360 on the module's LTO assembly; `//xbox360:openxbdm-no-rewrite` builds without it), and fail the build on reservation instructions the kernel loader reports as unprotected.
- Shrink static data to stock's layouts: 0x298-class connection slots, one static 0x488 breakpoint block with pool blocks after it, a static transfer block with pool fallback for `threads`, `getcontext`, and similar replies, and detour records from the pool at the first `detour start`.
- Loaded footprint: image 0xbb000 bytes (stock 0xaf000); with xshell idle the console reports 22 more free pages than with stock XBDM.
- Place the export table in an executable section (`.xexp`); the loader hypercall reads it only from protected code pages.
- `threads` reads the process objects at debug monitor data +0x50 and +0x54; the listener sets SO_REUSEADDR before bind; `getmemex` missing texts are `missing ADDR` and `missing LENGTH`.
- Boots on a devkit in place of stock XBDM; xshell loads against its exports.
- Declare kernel and XAM imports through `xbox360-sys`, and use the `xbox360` crate for spin locks, module and export lookup, the time base, system time, tick count, sleeps, last-error values, the kernel version and the hardware flags. Import records and data import slots are in per-import `.xthunks.*` and `.xvars.*` sections, so the XEX imports only what the module calls.
- The counter sampler timer (stock 0x91f2b110) and the network simulator timer (stock 0x91f8ed88 region) are initialized with `KeInitializeTimerEx` process type 2 (`ProcessType::SYSTEM`), the `li r5,2` of both stock call sites.
- Kernel BOOLEAN results (`MmIsAddressValid`, `HalIsExecutingPowerDownDpc`, `RtlTryEnterCriticalSection`) are tested on their low byte.
- `xconfig` writes fail with `InvalidParameter` for values above 0xffff bytes, the largest size `ExSetXConfigSetting` takes.
- Data breakpoints write DABR with a zero upper word.
- Serve SMB on TCP port 445 from the server thread's select loop, with two connections of two 0x10400-byte pool buffers each; without the port the monitor runs without SMB.
- Flash updates fail with `InvalidParameter` when the image header points outside the uploaded image, where stock reads past the buffer.

### Kernel debugger

- Add `openxbdm-kd host`: acts as the console's debugger host, serves the kernel's host file requests from `--file` mappings (for example XBDM from a local image), and keeps an image's load-symbols stop (`--stop-on-load`) so memory can be patched before its entry point runs.
- The host file service fails with `HostFileError`, converted to the FILE_IO reply status.
- Serving `DEVKIT\FlashEx\xbdm.xex` from the host boots openxbdm without writing the console disk; stopping the host and rebooting returns to stock XBDM.

### Client

- Match stock replies in the client: debugger commands (`isbreak`, `isstopped`, `stopon`/`nostopon`, `continue`, `dbgextld`; no `execute` data breakpoint), `consoletype`, `consolemem`, `getnetaddrs`, `setmem` partial writes, `getmem` lengths, file transfer ranges and `fileeof` dispositions, `screenshot` detiling, and discovery name matching.
- Add client commands for `getcontext`, `setcontext`, `isdebugger`, `debugger`, `kd`, `kdlite`, `kdnet`, `threadstat`, `crashdump`, `break now`, lock mode, users, privileges, `authuser`, `adminpw`, and `keyxchg`.
- Add `xeedee parity record` and `xeedee parity compare`: record the replies to a command list and compare two recordings outside listed varying fields.
- Report 4xx replies outside the result table as remote errors with their code (`RemoteStatus`); parse stop exception codes as `NtStatus`, thread last errors as `Win32Error`, and the PIX capture file result as a hexadecimal HRESULT, failing on malformed text.
- The command-line client is `xeedee`.

### Build

- Build, test and lint with Buck2. `build_defs/update_buck_files.py` generates `crates/<name>/BUCK` for each workspace crate from Cargo's resolution, including test targets and `-all-features` variants, and `third-party/rust/BUCK` through Reindeer.
- Buck2 downloads each crates.io dependency and checks it against the SHA-256 in `Cargo.lock`; nothing is vendored. Cargo fetches from crates.io.
- Build the Xbox 360 module with Buck2 (`//xbox360:openxbdm`, `//xbox360:openxbdm-boot-guard`) on every host, with the toolchain, standard library overlay, build rules, xex-link and xbox360-asm-rewrite of rust-xbox360 as the `xbox360` external cell pinned to a commit. rustc assembles the rewritten module, and llvm-objdump comes from the Rust release; no LLVM installation, overlay step or `build_xbox360.sh` is needed.
- Buck2 uses the Rust release that the `xbox360` cell pins (1.98.0); `rust-toolchain.toml` names the same release for Cargo and rust-analyzer, and `//:rust-toolchain-test` checks that they match. On Linux the host C driver links with the lld bundled in `rustc`.
- Generate the C++ headers of `openxbdm-ffi` with Buck2 (`//bindings:cpp`, through `openxbdm-ffi-bindgen`), and build its shared and static libraries as subtargets of its library.
- Format with a pinned nightly rustfmt (`.rustfmt.toml`); `build_defs/lint.py` checks formatting and clippy diagnostics through Buck2.
- `-c rust.profile=release` builds with the optimization, stripping and thin LTO of Cargo's release profile.
- Report each libtest case as its own Buck2 test through the internal test runner.
- `devenv.nix` provides the Buck2 release that `toolchains/buck2_release.json` pins, and no C compiler or LLVM tools.
- CI builds and tests everything, including the console module and the C++ headers, with Buck2 on Linux x86_64, macOS arm64 and Windows x86_64, with a bazel-remote action cache on Linux and macOS, and checks formatting, clippy diagnostics and the generated files on Linux x86_64.

### Releases

- A `vX.Y.Z` tag that names the workspace version publishes the console module (`openxbdm-<version>.xex` and `openxbdm-boot-guard-<version>.xex`), and for Linux x86_64, macOS arm64 and Windows x86_64 the `xeedee` and `openxbdm-kd` executables and the FFI libraries with C++ headers, all built by Buck2.
- The `nightly` pre-release is rebuilt each day the default branch has changed. The notes of each release give the build date, the commit, and the steps to install the module in `DEVKIT:\FlashEx`.

### Documentation

- Add command specifications, the export table, the control dispatcher, the PGO runtime, per-domain parity records, and the parity summary under `docs/re-notes`.
- Add the hardware differential results (`parity/hardware-commands.txt`, `parity/hardware-variances.txt`): 399 exchanges, 378 equal, 21 equal outside varying fields, 0 differ.
- Document the kd host deployment loop, kdnet setup, and differential testing in `DEVELOPING.md`.
