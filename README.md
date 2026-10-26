# openxbdm

Clean-room Rust reimplementation of the Xbox 360 [XBDM][xbdm] (Xbox Debug Monitor): a client library and CLI, and a server that replaces the monitor on the console.

[xbdm]: https://xboxdevwiki.net/Xbox_Debug_Monitor

## tl;dr

- `openxbdm.xex` is a drop-in replacement for XBDM.
- SMBv2 and v3 are supported by the server. Connect with username `xbox` and no password. Supports NTLMv2 with AES-128-GCM.
- Client library provides sync/async modes and has a sans-io core that can be used in flexible and weird environments (like [my hex editor](https://github.com/landaire/hxy)).
- Client library has an FFI crate which can be used to generate bindings for any target language supported by [diplomat](https://github.com/rust-diplomat/diplomat).
- `kdnet` supported and a `kdnet` to `gdbstub` bridge is provided, so you can debug your console with `gdb` or `lldb`.
- There is a `xeedee` cli which provides some features wrapping the client library for interacting with the devkit.
- `xeedee-controller` relays a host gamepad or timed controller script to a console.

## Releases

Nightly releases will be built iff there have been changes since last nightly.

Release artifacts:

- `openxbdm-boot-guard-<version>.xex`: the console module for `DEVKIT:\FlashEx\xbdm.xex` on a development kit which has some startup safety checks to avoid accidentally killing xbdm connectivity if something goes wrong.
- `openxbdm-<version>.xex`: the console module if you're deploying using the kernel debugger host (temp). For Linux x86_64, macOS arm64 and Windows x86_64:
- `xeedee-<version>-<target>`: the `xeedee` and `openxbdm-kd` executables.
- `xeedee-ffi-<version>-<target>`: the `openxbdm-ffi` shared and static libraries and their C++ headers.

## Xbox 360 module

`buck2 build //xbox360:openxbdm` builds `openxbdm.xex` which is intended to be the replacement for XBDM.

Its XEX2 header info can be found under [xbox360/xex.toml](xbox360/xex.toml)

Development loop, without writing the console disk: with kdnet enabled, run the kernel debugger host and reboot the console. The kernel then loads the module from the host:

```text
openxbdm-kd host --file "host:\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex=$(buck2 build //xbox360:openxbdm --show-simple-output)"
```

Stopping the host and rebooting returns to stock XBDM from flash. Placed at `DEVKIT:\FlashEx\xbdm.xex` the boot-guard build also loads in place of the flash monitor and removes that file at startup. Read the hazards and recovery in `DEVELOPING.md` before using that method.

## Kernel debugger (openxbdm-kd)

`openxbdm-kd` talks to the kernel debugger over the kdnet UDP transport and serves GDB.

Enable kdnet with stock XBDM (`kdnet set IP=<host> Port=50000`, `kdnet enable`, reboot).

    openxbdm-kd listen [--passive] [--log-file kd.log]
    openxbdm-kd [--target 169.254.59.14] break
    openxbdm-kd mem 0x80040000 64
    openxbdm-kd gdbserver [--listen 127.0.0.1:2159] [--registers 64|32] [--stop-on-load IMAGE]
    openxbdm-kd host [--file CONSOLE_PATH=LOCAL_PATH] [--stop-on-load IMAGE]
    openxbdm-kd reboot

Without `--target` the address is learned from the kernel's beacon. While the tool is attached the kernel waits for it at every print, module load and stop.

The `host` command keeps the console running while attached. It continues every event, prints debug output and module loads, and answers the kernel's host file requests.

Each module load asks the host first with a path such as `host:\Device\Flash\xbdm.xex`. Every requested path is printed, and if something catches your eye you can use `--file` to serve that path (compared case-insensitively) from a local file. Other paths are answered as not found and the kernel loads from its own devices.

To boot XBDM from a local image:

    openxbdm-kd host --file 'host:\Device\Flash\xbdm.xex=xbdm.xex'

`--stop-on-load xbdm.xex` keeps the console stopped at that image's load, after it is mapped and before its entry point runs, and reads commands from standard input: `mem ADDRESS [LENGTH]`, `write ADDRESS HEXBYTES` and `continue` (end of input also continues). `--log-file` appends every received datagram in the `listen --log-file` format.

### GDB and LLDB

`gdbserver` serves one debugger (any GDB or LLDB with PowerPC support), then lets the console run.

- Every processor (hardware thread) is a thread of the debugger. A stop freezes all of them.
- Debug output and module loads appear in the debugger console while the console runs.
- `--stop-on-load debugprobe.xex` stops the console when that image loads, after it is mapped and before its entry point runs, so you can set breakpoints first. Launch the title after `gdbserver` starts.
- The registers are 64-bit, as on the processor. Titles compiled as 32-bit PowerPC, such as those built with [rust-xbox360](rust-xbox360), need `--registers 32`: GDB loads a 32-bit ELF only then, and both debuggers unwind 32-bit stack frames with it. A register write in that mode keeps the high word.

Load the title's ELF before you connect so the debugger has its symbols and source. rust-xbox360 titles have `[gdb]` and `[lldb]` subtargets that do this, including the standard library source. Run the debugger from that project's root, since the source paths are relative to it:

    openxbdm-kd gdbserver --registers 32 --stop-on-load stdhello.xex
    gdb -x "$(buck2 build //examples/stdhello:stdhello[gdb] --show-simple-output)" \
        -ex 'target remote 127.0.0.1:2159'
    lldb -s "$(buck2 build //examples/stdhello:stdhello[lldb] --show-simple-output)" \
        -o 'gdb-remote 127.0.0.1:2159'

Without a symbol file, start GDB with `-ex 'set endian big'`.

- Registers, memory, software breakpoints, single step, `next`, `finish`, interrupt and detach are supported.
- A step runs every processor, as the kernel resumes them all, so another thread can pass a breakpoint the debugger lifted for the step.
- Detaching removes breakpoints and resumes the console.
- Do not set breakpoints in the kernel debugger's own code paths, such as the kd poll path at `0x801b4990`.
- Single step through MSR.SE stops the console with bug check 0x2b.
- LLDB releases (21 and earlier) have three defects with 32-bit PowerPC titles: they cannot unwind out of a function that saves no registers, they show values held in several registers with their bytes reversed, and with `--registers 64` they cannot unwind 32-bit frames. GDB has none of them. An LLDB with fixes for all three works with both register widths.

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

## Controller relay

Run the GPUI controller relay and enter the console IP address or hostname:

```text
buck2 run //crates/xeedee-controller:xeedee-controller-bin
```

Select a connected hardware controller to relay its current state. Select a JSON script to queue timed frames on the console instead:

```json
{
  "frames": [
    {
      "duration_ms": 250,
      "buttons": ["a", "dpad_up"],
      "left_trigger": 0.5,
      "left_stick": { "x": -1.0, "y": 1.0 }
    },
    {
      "duration_ms": 100,
      "buttons": []
    }
  ]
}
```

Stick values range from `-1.0` to `1.0`. Trigger values range from `0.0` to `1.0`. Frame durations range from 1 to 2,147,483,647 milliseconds. Button names use snake case XInput names such as `left_shoulder`, `dpad_up`, and `guide`.

## Building

_For in-depth info see [`DEVELOPING.md`](DEVELOPING.md)_.

[Buck2](https://buck2.build/) builds, tests and lints on every platform. You don't need to install it. Run `bin/buck2` (`bin\buck2.cmd` on Windows) wherever these docs say `buck2`, or add `bin` to your `PATH`. The first run downloads [DotSlash](https://dotslash-cli.com) and the Buck2 release that `toolchains/buck2` pins into `.tools`. Buck2 then downloads Rust, Python and every crate it needs.

You do need a few host tools:

- A C++ linker driver: GCC or Clang on Linux, the Xcode command line tools on macOS, or Visual Studio Build Tools with the C++ workload on Windows.
- `git` and `curl`.
- Python 3.11 or later for the `build_defs` scripts.
- rustup, only to build with Cargo.
- [reindeer](https://github.com/facebookincubator/reindeer), only to regenerate the build files after you change a `Cargo.toml`.

`./bootstrap.sh` (`bootstrap.ps1` on Windows) does the first-run setup by hand and lists any host tools it can't find.

We have a custom [rust-xbox360](https://github.com/landaire/rust-xbox360) toolchain used and creates the `xbox360` buck2 cell. Additionally, tools from [acceleration](https://github.com/landaire/acceleration) are used for translating from ppc64 ELF to ppc64 PE, then wrapping that as an XEX2.

If you are a nix user, a [devenv](https://devenv.sh), is present whcih can provide all necessary tooling. Run `devenv shell` to activate.

| Command                                                                 | Purpose                                                                                        |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `buck2 build //: //bindings/... //crates/... //xbox360/...`             | Build everything: host crates, C++ headers, and the console module.                            |
| `buck2 test //: //bindings/... //crates/... //xbox360/...`              | Run the unit, integration and documentation tests, and check the Rust release pin.             |
| `buck2 build //xbox360:openxbdm --show-output`                          | Build the console module, `openxbdm.xex`.                                                      |
| `buck2 run //crates/openxbdm-cli:xeedee-bin -- ARGS`                    | Run a tool; each binary is `//crates/<crate>:<binary>-bin`.                                    |
| `buck2 build //crates/openxbdm-cli:xeedee-bin?release`                  | Build an optimized host binary with external debug information.                               |
| `buck2 build //crates/openxbdm-cli:xeedee-bin?release_no_symbols`       | Build an optimized host binary without symbols.                                                |
| `build_defs/lint.py`                                                    | Check formatting and clippy diagnostics.                                                       |
| `build_defs/lint.py --format`                                           | Format the workspace crates.                                                                   |
| `build_defs/package_release.py --version V --target T`                  | Archive the host tools and the FFI libraries.                                                  |
| `build_defs/package_module.py --version V`                              | Copy out the console module builds under release names.                                        |
| `build_defs/update_buck_files.py`                                       | Regenerate the build files after a change to a `Cargo.toml` or `Cargo.lock`.                   |
| `toolchains/update_rustfmt_release.py`                                  | Regenerate `toolchains/rustfmt_release.bzl` after a change to `RUSTFMT_NIGHTLY` in the script. |

## Tests

- `crates/openxbdm-server-host/tests/<domain>.rs`: integration tests that start the host server and send every command over TCP, through `openxbdm-client` where it has the command and as raw lines otherwise. `framework.rs` covers dispatch and access rules, `trace.rs` the `verbose` trace texts, `network/` the `ipproxy`, `netcap`, and `netsim` engines; `common/` holds the shared harness.
- `crates/openxbdm-client/tests/`: Insta snapshot tests of command encoding and reply parsing against captured fixtures.
- Unit tests in `openxbdm-core`, `openxbdm-client`, `openxbdm-cli`, and `openxbdm-server`.

`build_defs/update_buck_files.py` generates a Buck2 test target for each
unit test and `tests/*.rs` file.

## Other Documentation

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
