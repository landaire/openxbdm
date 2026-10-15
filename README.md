# openxbdm

Clean-room Rust reimplementation of the Xbox 360 [XBDM][xbdm] (Xbox Debug
Monitor): a client library and CLI, and a server that replaces the
monitor on the console.

[xbdm]: https://xboxdevwiki.net/Xbox_Debug_Monitor

Xbox 360 development kits serve a text-line protocol on TCP port 730, with
multi-line and binary bodies, and answer name discovery on UDP port 730.

## Crates

| Crate | Contents |
| --- | --- |
| `openxbdm-core` | `no_std` protocol grammar, status codes, value encodings, and the authentication response function shared by client and server |
| `openxbdm-client` | Async client: transports (including `MockTransport`), response parsers, typed commands, discovery |
| `openxbdm-cli` | The `xeedee` command-line client, including `parity record` and `parity compare` for differential testing |
| `openxbdm-ffi` | C/C++ bindings for the client (`cdylib`, `staticlib`) |
| `openxbdm-ffi-bindgen` | Generates the C++ headers of `openxbdm-ffi` with diplomat |
| `openxbdm-server` | `no_std`, allocation-free command engine: all 177 stock commands in `src/commands/<domain>` over per-domain backend traits |
| `openxbdm-server-host` | The engine over std TCP sockets with a simulated console (`openxbdm-server` binary), and the integration tests |
| `openxbdm-server-xbox360` | The Xbox 360 system-debugger module: console backends, control dispatcher, and the 253 exports |
| `openxbdm-kd-core` | `no_std` kdnet packet codec and session |
| `openxbdm-kd` | Kernel debugger client over kdnet: the `openxbdm-kd` binary, GDB server, and debugger host |
| `openxbdm-asm-rewrite` | Assembly rewrite and the rewrite and reservation audits of the console module build |

## Build

Buck2 builds, tests and lints the workspace on Linux x86_64, macOS arm64
and Windows x86_64, including the console module. It downloads the Rust
release, a pinned nightly rustfmt, a Python interpreter, each crates.io
dependency, and the Xbox 360 toolchain, and checks every download against
a pinned SHA-256 (crates and Rust archives) or commit (the toolchain). The
host provides the C++ compiler driver, which links host executables: `c++`
on Linux, Xcode's `clang++` on macOS, and the Visual Studio build tools on
Windows.

The Xbox 360 toolchain is the `xbox360` cell, the
[rust-xbox360](https://github.com/landaire/rust-xbox360) repository at the
commit that `.buckconfig` pins: the target specification, the standard
library overlay that Buck2 builds the console's `core`, `alloc` and
`compiler_builtins` from, and `xex-link`. The Rust release is the one that
cell pins; `rust-toolchain.toml` names the same release for Cargo and
rust-analyzer.

Each workspace crate has a generated `crates/<name>/BUCK`; the crates.io
dependencies are in the generated `third-party/rust/BUCK`. Cargo.toml stays
the description of every crate. A crate with optional features also has
`-all-features` variants of its library and binaries, so that builds and
lints cover the optional code. Cargo builds the host crates from the same
sources (`cargo build --workspace`, `cargo test --workspace`).

With [devenv](https://devenv.sh), `devenv shell` provides Buck2, reindeer,
Python, and the same Rust release for Cargo and rust-analyzer; the C
compiler stays the host's. Without devenv, install:

- Buck2, the release that `toolchains/buck2_release.json` names. The test
  rules require that release or a later one.
- git, which Buck2 runs to fetch the `xbox360` cell.
- Python 3.11 or later.
- rustup, which installs the release that `rust-toolchain.toml` names, and
  [reindeer](https://github.com/facebookincubator/reindeer), to regenerate
  the build files.

| Command | Purpose |
| --- | --- |
| `buck2 build //: //bindings/... //crates/... //xbox360/...` | Build everything: host crates, C++ headers, and the console module. |
| `buck2 test //: //bindings/... //crates/... //xbox360/...` | Run the unit, integration and documentation tests, and check the Rust release pin. |
| `buck2 build //xbox360:openxbdm --show-output` | Build the console module, `openxbdm.xex`. |
| `buck2 run //crates/openxbdm-cli:xeedee-bin -- ARGS` | Run a tool; each binary is `//crates/<crate>:<binary>-bin`. |
| `buck2 build -c rust.profile=release //crates/...` | Build the host crates with the optimizations of Cargo's release profile. |
| `build_defs/lint.py` | Check formatting and clippy diagnostics. |
| `build_defs/lint.py --format` | Format the workspace crates. |
| `build_defs/package_release.py --version V --target T` | Archive the host tools and the FFI libraries. |
| `build_defs/package_module.py --version V` | Copy out the console module builds under release names. |
| `build_defs/update_buck_files.py` | Regenerate the build files after a change to a `Cargo.toml` or `Cargo.lock`. |
| `toolchains/update_rustfmt_release.py` | Regenerate `toolchains/rustfmt_release.bzl` after a change to `RUSTFMT_NIGHTLY` in the script. |

`mise.toml` defines the same commands as tasks. See `DEVELOPING.md` for
the console module build, local changes to rust-xbox360, the Buck rules,
and console deployment.

## Releases

A `vX.Y.Z` tag that names the workspace version publishes a GitHub release.
Every day the `nightly` pre-release is rebuilt from the default branch when
the branch has changed since the last one. The notes of each release give
its build date and commit and the console installation steps. Each release
has:

- `openxbdm-boot-guard-<version>.xex`: the console module for
  `DEVKIT:\FlashEx\xbdm.xex` on a development kit.
- `openxbdm-<version>.xex`: the console module for the kernel debugger
  host.
- For Linux x86_64, macOS arm64 and Windows x86_64:
  - `xeedee-<version>-<target>`: the `xeedee` and `openxbdm-kd`
    executables.
  - `xeedee-ffi-<version>-<target>`: the `openxbdm-ffi` shared and static
    libraries and their C++ headers.

Buck2 builds every file. `<version>` is `nightly` for the nightly
pre-release.

## Host server

```text
buck2 run //crates/openxbdm-server-host:openxbdm-server-bin -- --listen 127.0.0.1:1730
xeedee -H 127.0.0.1:1730 dmversion
```

The default listen address is `127.0.0.1:1730`; name discovery is served
on the UDP port with the same number. All connections share one simulated
console, which starts by executing its settings file as the console
monitor does.

## Tests

- `crates/openxbdm-server-host/tests/<domain>.rs`: integration tests that
  start the host server and send every command over TCP, through
  `openxbdm-client` where it has the command and as raw lines otherwise.
  `framework.rs` covers dispatch and access rules, `trace.rs` the
  `verbose` trace texts, `network/` the `ipproxy`, `netcap`, and `netsim`
  engines; `common/` holds the shared harness.
- `crates/openxbdm-client/tests/`: Insta snapshot tests of command
  encoding and reply parsing against captured fixtures.
- Unit tests in `openxbdm-core`, `openxbdm-client`, `openxbdm-cli`, and
  `openxbdm-server`.

`build_defs/update_buck_files.py` generates a Buck2 test target for each
unit test and `tests/*.rs` file.

## Client

Every wire verb is a type implementing [`openxbdm_client::Command`]. You hand one
to `Client::run` and get back the decoded `Output` associated type.

```rust,no_run
use openxbdm_client::Client;
use openxbdm_client::commands::{DbgName, DirList};
use openxbdm_client::transport::tokio::connect;

#[tokio::main]
async fn main() -> openxbdm_client::Result<()> {
    // `connect` returns a `Compat<TcpStream>` that implements the
    // `futures_io` traits the client needs.
    let transport = connect("192.168.1.26:730").await?;
    let mut client = Client::new(transport).read_banner().await?;

    // Single-line response -> String.
    let name: String = client.run(DbgName::Get).await?;
    println!("console name: {name}");

    // Multi-line response -> Vec<DirEntry> with typed fields.
    let entries = client.run(DirList { path: r"DEVKIT:\".into() }).await?;
    for entry in entries {
        println!(
            "{:<40} {:>10} {}",
            entry.name,
            entry.size,
            if entry.is_directory { "DIR" } else { "FILE" },
        );
    }
    Ok(())
}
```

If you need a verb that doesn't have a typed wrapper yet, drop down to
`client.send_line("any xbdm verb").await?` for the raw `Response`.

Or use the CLI:

```
cargo install --path crates/openxbdm-cli
xeedee -H 192.168.1.26 systime
xeedee -H 192.168.1.26 file ls 'DEVKIT:\'
xeedee -H 192.168.1.26 file get 'DEVKIT:\my-capture.xbm'
xeedee -H 192.168.1.26 dump-module xboxkrnl.exe /tmp/xboxkrnl.exe
```

### Features

`openxbdm-client`:

| Feature | Enables |
| --- | --- |
| `tokio` (default) | `tokio::net::TcpStream` transport |
| `jiff` | `jiff::Zoned` conversions on time-bearing response types |
| `capture` | Video capture over the PIX! protocol and `.xbm` decoding |
| `dangerous` | In-memory patches to xbdm (drive map enable, code patches) |

`openxbdm-cli` enables `capture` and `dangerous` by default.

The client was exercised against a stock v10888-based development kit
(`xbdm-main-nov11`): directory listing, `getfile`, `sendfile`, `getmem`,
`setmem`, `reboot`, `threadinfo`, notification channels, UDP discovery,
PIX! video capture, and the `dangerous` helpers. MP4 output shells out to
`ffmpeg` for H.264 muxing.

## Xbox 360 module

`buck2 build //xbox360:openxbdm` builds `openxbdm.xex`: load address
`0x91f00000`, system-debugger DLL flags, build 21256 import versions,
small pages, compression, development-key encryption, and the bounding
path `\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex`
(`xbox360/xex.toml`). `//xbox360:openxbdm-boot-guard` is the build for
`DEVKIT:\FlashEx`. The module boots on a devkit in place of stock XBDM;
see `docs/re-notes/status.md`.

Development loop, without writing the console disk: with kdnet enabled,
run the kernel debugger host and reboot the console; the kernel loads
the module from the host.

```text
openxbdm-kd host --file "host:\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex=$(buck2 build //xbox360:openxbdm --show-simple-output)"
```

Stopping the host and rebooting returns to stock XBDM from flash. Placed
at `DEVKIT:\FlashEx\xbdm.xex` the boot-guard build also loads in place of
the flash monitor and removes that file at startup; read the hazards and
recovery in `DEVELOPING.md` before using that method.

## Differential testing

`xeedee parity record` sends a command list to a monitor and records
the replies; `xeedee parity compare` reports differences between two
recordings outside listed varying fields. Against stock XBDM on a devkit,
the 399 lines of `docs/re-notes/parity/hardware-commands.txt` give 0
differences (`docs/re-notes/parity.md`). Usage: `DEVELOPING.md`.

## Documentation

- `DEVELOPING.md`: environment, build, third-party code, deployment, recovery, differential testing.
- `docs/re-notes/status.md`: component status.
- `docs/re-notes/parity.md`: per-command, export, and control code coverage; gaps and deviations.
- `docs/re-notes/xbdm.md`: protocol, command table, and feature map.
- `docs/re-notes/commands/`: command specifications (`framework.md`, `group1.md` to `group8.md`).
- `docs/re-notes/parity/`: per-domain parity records.
- `docs/re-notes/exports.md`: export table.
- `docs/re-notes/dispatcher.md`: debug monitor control dispatcher.
- `docs/re-notes/pgo.md`: PGO instrumentation runtime.
- `docs/re-notes/module-loading.md`: kernel module search and boot-time replacement.
- `docs/re-notes/kd.md`: kdnet protocol and the kernel debugger host.
- `docs/re-notes/nuances.md`: behaviors requiring exact compatibility.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.

## Kernel debugger (openxbdm-kd)

`openxbdm-kd` talks to the kernel debugger over the kdnet UDP transport and
serves GDB. Enable kdnet with stock XBDM (`kdnet set IP=<host> Port=50000`,
`kdnet enable`, reboot). The host must reach the kdnet target address on the
local link; for an APIPA target address (169.254.x.y) add a host route, for
example `nmcli device modify eth0 +ipv4.routes 169.254.59.14/32`.

    openxbdm-kd listen [--passive] [--log-file kd.log]
    openxbdm-kd [--target 169.254.59.14] break
    openxbdm-kd mem 0x80040000 64
    openxbdm-kd gdbserver --listen 127.0.0.1:2159
    openxbdm-kd host [--file CONSOLE_PATH=LOCAL_PATH] [--stop-on-load IMAGE]
    openxbdm-kd reboot

Without `--target` the address is learned from the kernel's beacon. While
the tool is attached the kernel waits for it at every print, module load
and stop.

`host` keeps the console running while attached: it continues every event,
prints debug output and module loads, and answers the kernel's host file
requests. Each module load asks the host first with a path such as
`host:\Device\Flash\xbdm.xex`; every requested path is printed. `--file`
serves a requested path (compared case-insensitively) from a local file;
other paths are answered as not found and the kernel loads from its own
devices. To boot XBDM from a local image:

    openxbdm-kd host --file 'host:\Device\Flash\xbdm.xex=xbdm.xex'

`--stop-on-load xbdm.xex` keeps the console stopped at that image's load,
after it is mapped and before its entry point runs, and reads commands from
standard input: `mem ADDRESS [LENGTH]`, `write ADDRESS HEXBYTES` and
`continue` (end of input also continues). `--log-file` appends every
received datagram in the `listen --log-file` format.

GDB (any build with PowerPC support):

    gdb -ex 'set architecture powerpc:common64' -ex 'set endian big' \
        -ex 'target remote 127.0.0.1:2159'

Registers, memory, software breakpoints, `stepi` (software single step),
interrupt and detach are supported. Detaching removes breakpoints and
resumes the console. Do not set breakpoints in the kernel debugger's own
code paths, such as the kd poll path at `0x801b4990`. Single step through
MSR.SE stops the console with bug check 0x2b.
