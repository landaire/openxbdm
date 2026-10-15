# Changelog

## Unreleased

### Server engine

- Add `openxbdm-server`, a `no_std`, allocation-free command engine with the stock dispatch rules (access masks, development-kit-only and own-thread flags, dedicated connections), continuations for 202/203/204 transfers, notification channels, command processors, and the settings file.
- Implement all 177 stock XBDM 2.0.21256.0 commands in eleven domains (session, security, console, system, file system, memory, debugger, network, performance, hardware, services) over per-domain backend traits.
- Move the protocol grammar, status codes, and authentication function shared by client and server into `openxbdm-core`.

### Host server

- Add `openxbdm-server-host`: the engine over std TCP sockets with one simulated console shared by all connections, and UDP name discovery.
- Add integration tests per domain that send every command to the host server over TCP.

### Xbox 360 module

- Add console backends for every domain, the debug monitor control dispatcher (102 of 103 stock handler codes), and all 253 stock exports through `export!`/`export_raw!` and xex-link.
- Run server services inline under a startup lock until the command loop starts, so exports called during boot do not wait for the server thread.
- Threads wait for the server thread only while it runs its pass loop: debug events, thread notifications, and queued services take their default disposition before the first pass and after the loop stops, and thread notifications are posted without waiting unless the thread may stop.
- Enter the module entry point, the kernel debug routine, the thread notification, the control dispatcher, and the remaining kernel callbacks through the export bridge, and call console routines through frames that reserve the console argument area.
- Create the server thread with stock's flags, which make it not debuggable.
- Add the `boot-guard` feature: a boot without `DEVKIT:\FlashEx\openxbdm.arm` removes the `DEVKIT:\FlashEx\xbdm.xex` override and restarts into the flash monitor.
- Deploy the module as `DEVKIT:\FlashEx\xbdm.xex` with a matching bounding path; it removes that file at startup.
- Pack the image on 4 KB pages (`.text` at `0x91f01000`; xex-link derives section alignment from the small-pages flag), so the image ends at `0x91fe5000`, below xshell.
- Place the export table in an executable section (`.xexp`); the loader hypercall reads it only from protected code pages.
- `threads` reads the process objects at debug monitor data +0x50 and +0x54; the listener sets SO_REUSEADDR before bind; `getmemex` missing texts are `missing ADDR` and `missing LENGTH`.
- Boots on a devkit in place of stock XBDM; xshell loads against its exports.

### Kernel debugger

- Add `openxbdm-kd host`: acts as the console's debugger host, serves the kernel's host file requests from `--file` mappings (for example XBDM from a local image), and keeps an image's load-symbols stop (`--stop-on-load`) so memory can be patched before its entry point runs.
- Serving `DEVKIT\FlashEx\xbdm.xex` from the host boots openxbdm without writing the console disk; stopping the host and rebooting returns to stock XBDM.

### Client

- Match stock replies in the client: debugger commands (`isbreak`, `isstopped`, `stopon`/`nostopon`, `continue`, `dbgextld`; no `execute` data breakpoint), `consoletype`, `consolemem`, `getnetaddrs`, `setmem` partial writes, `getmem` lengths, file transfer ranges and `fileeof` dispositions, `screenshot` detiling, and discovery name matching.
- Add client commands for `getcontext`, `setcontext`, `isdebugger`, `debugger`, `kd`, `kdlite`, `kdnet`, `threadstat`, `crashdump`, `break now`, lock mode, users, privileges, `authuser`, `adminpw`, and `keyxchg`.
- Add `openxbdm parity record` and `openxbdm parity compare`: record the replies to a command list and compare two recordings outside listed varying fields.

### Build

- Build with Buck2; Reindeer generates the rules from the workspace and the vendored dependencies, and `build_defs/rust_tests.bzl` declares the test targets.
- Pin Rust 1.98.0 in `rust-toolchain.toml`; Buck2 downloads the same release from the hashes in `toolchains/rust_release.bzl` instead of using the system Rust. On Linux the host C driver links with the lld bundled in `rustc`.
- Vendor all dependencies, including the standard library sources for the console build.

### Documentation

- Add command specifications, the export table, the control dispatcher, the PGO runtime, per-domain parity records, and the parity summary under `docs/re-notes`.
- Add the hardware differential results (`parity/hardware-commands.txt`, `parity/hardware-variances.txt`): 399 exchanges, 378 equal, 21 equal outside varying fields, 0 differ.
- Document the kd host deployment loop, kdnet setup, and differential testing in `DEVELOPING.md`.
