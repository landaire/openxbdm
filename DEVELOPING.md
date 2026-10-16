# Developing

## Overview

This repository builds two kinds of things:

- Host tools that run on your PC: the `xeedee` client, the `openxbdm-kd`
  kernel debugger host, and the FFI libraries.
- The console module, `openxbdm.xex`: our replacement for `xbdm.xex`, the
  debug monitor (XBDM) that a development kit normally loads from its
  flash at boot.

The console module comes in two builds. They hold the same server; they
differ only in how they get onto the console and how they recover from a
bad boot.

| Build | Target | Use it when |
| --- | --- | --- |
| `openxbdm.xex` | `//xbox360:openxbdm` | You run `openxbdm-kd host` on your PC and it hands the module to the console at boot. Nothing is written to the console. |
| `openxbdm-boot-guard.xex` | `//xbox360:openxbdm-boot-guard` | You copy the module to `DEVKIT:\FlashEx\xbdm.xex` on the console's disk, with no PC involved at boot. |

Loading from the kd host is the safer method: if the module breaks, stop
the host and restart the console, and it boots the stock monitor again.

Copying to `DEVKIT:\FlashEx\xbdm.xex` makes the console load that file
instead of the stock monitor at every boot, for as long as the file
exists. If that module hangs or crashes during boot, the console hangs at
every boot, and without a running monitor you cannot delete the file over
the network. The boot guard exists to prevent that:

1. Every build of the module deletes `DEVKIT:\FlashEx\xbdm.xex` once its
   server has started, so a good boot runs openxbdm once and the next boot
   is back to the stock monitor.
2. The boot-guard build also checks for a marker file,
   `DEVKIT:\FlashEx\openxbdm.arm`, as the very first thing it does. You
   create the marker each time you install the module.
   - Marker there: the module deletes the marker and starts normally.
   - Marker gone: the marker was used up by an earlier boot, so that boot
     must have failed before it could delete `xbdm.xex`. The module does
     not start; it deletes `xbdm.xex` and restarts the console, which then
     boots the stock monitor.

So if a boot with openxbdm hangs, turn the console off and on: the second
boot finds no marker and puts the stock monitor back. This only fails if
the module crashes before its first instruction runs (for example, the
loader rejects the file); then use the kd host to serve a working module
for the same path, which deletes the file once it starts. Steps for both
methods: Console deployment, below.

## Environment

`devenv shell` (`devenv.nix`) provides Buck2 (the release that
`toolchains/buck2_release.json` pins), Reindeer, Python, and the Rust
release in `rust-toolchain.toml`. It provides no C compiler.
`devenv --profile ci shell` adds `bazel-remote` for the CI action cache
(`ci/start-action-cache.sh`).

Buck2 takes its Rust toolchain from the `xbox360` cell,
[rust-xbox360](https://github.com/landaire/rust-xbox360) at the commit in
`[external_cell_xbox360]` of `.buckconfig`, which Buck2 fetches with git.
The cell's `buck/rust_release.bzl` records the archives of one Rust
release: `rustc` (rustc, rustdoc, and the bundled lld), `rust-std`,
`clippy-preview` (clippy-driver), `llvm-tools-preview` (llvm-objdump), and
`rust-src`. Buck2 verifies each archive's SHA-256 and assembles the host
toolchain once, so `buck2 build` needs no installed Rust. Host code is
built only for the host Buck2 runs on.

`rust-toolchain.toml` names the same release for rustup and devenv, which
provide Cargo and rust-analyzer. `//:rust-toolchain-test` fails when the
two differ. To move to another release, update the cell (its
`buck/update_rust_release.py` and standard library overlay) and
`rust-toolchain.toml` together.

Formatting uses a nightly rustfmt, since `.rustfmt.toml` sets options that
only a nightly accepts. The `RUSTFMT_NIGHTLY` date in
`toolchains/update_rustfmt_release.py` pins it, and
`toolchains/rustfmt_release.bzl` records its `rustc` and `rustfmt-preview`
archives. After a change to the date, run

    toolchains/update_rustfmt_release.py

which writes `toolchains/rustfmt_release.bzl` from the nightly's channel
manifest on static.rust-lang.org. `--check` verifies, without network
access, that the file matches the date.

`toolchains/BUCK` declares the toolchains through `xbox360_toolchains()`
of the cell, with this project's flags: the release profile for host
crates, separate processes for doctests, and the size settings of the
console module.

Buck2 links host executables with the host's linker driver: `c++` (GCC
or Clang) with the lld bundled in `rustc` on Linux, Xcode command line
tools on macOS, and MSVC build tools on Windows. Console executables are
linked by the bundled rust-lld alone. The prelude's Python tools run on a
CPython that Buck2 downloads.

### Local changes to rust-xbox360

To build against a rust-xbox360 working copy instead of the pinned
commit, place the working copy at `rust-xbox360/` in this repository (the
path of the cell in `.buckconfig`; Git ignores it) and make the cell an
ordinary cell in `.buckconfig.local`:

    [external_cells]
      xbox360 = disabled

Buck2 does not follow a symbolic link out of the repository, so the
working copy must be a directory: a clone, a `git worktree`, or a jj
workspace of an existing checkout, for example

    jj -R ../llvm-xbox-360 workspace add --name xeedee rust-xbox360

Buck2 then builds from the working copy as it changes. To pin a new
commit, push it to GitHub, set `commit_hash` in `.buckconfig`, and remove
the `.buckconfig.local` entry.

## Build and test

Buck2 is the primary build system. Cargo builds the host crates from the
same sources.

    buck2 build //: //bindings/... //crates/... //xbox360/...
    buck2 test //: //bindings/... //crates/... //xbox360/...
    build_defs/lint.py

    cargo build --workspace
    cargo test --workspace

`//third-party/rust` is not built as a whole: its rules for other hosts
are incompatible with this one.

The `smb` feature of `openxbdm-server`, `openxbdm-server-host`, and
`openxbdm-server-xbox360` is on by default; the platform crates depend on
`openxbdm-server` without its default features and enable `smb` through
their own. `cargo build -p openxbdm-server --no-default-features` builds
the engine without `smb2-server`.

`buck2 build -c rust.profile=release` builds host crates like Cargo's
release profile: every crate gets `-Copt-level=3` and `-Cstrip=debuginfo`,
and binaries and tests get the workspace's `lto = "thin"` as `-Clto=thin`.
rustc rejects `-Clto` for proc-macro crates, so libraries do not get it.

`build_defs/package_release.py` builds with that profile and archives the
released executables (`xeedee` and `openxbdm-kd`) as
`xeedee-<version>-<target>`, and the `openxbdm-ffi` shared and static
libraries (the `[cdylib]` and `[staticlib]` subtargets of its library)
with their C++ headers (`//bindings:cpp`, written by
`openxbdm-ffi-bindgen`) as `xeedee-ffi-<version>-<target>`. The profile
gives only binaries and tests `-Clto=thin`, so the FFI libraries are
built without LTO.
`build_defs/package_module.py` copies out the console module builds.
`.github/workflows/release.yml` publishes a release for a `vX.Y.Z` tag
that names the workspace version, and `.github/workflows/nightly.yml`
replaces the `nightly` pre-release each day the default branch has
changed. `build_defs/release_notes.py` writes the notes of both.

## Xbox 360 module

`openxbdm-server-xbox360` targets `powerpc-unknown-xbox360`. Its
`[package.metadata.buck2.xbox360]` table names its linker script, and
`build_defs/update_buck_files.py` makes each of its binaries an
`xbox360_executable` (`build_defs/xbox360_module.bzl`). That rule
configures itself and its dependencies for the console, with the `core`,
`alloc` and `compiler_builtins` crates that the cell builds from the
standard library overlay. `xbox360/BUCK` builds the module from it:

| Target | Module |
| --- | --- |
| `//xbox360:openxbdm` | `openxbdm.xex`, for the kd host |
| `//xbox360:openxbdm-boot-guard` | `openxbdm-boot-guard.xex`, with the `boot-guard` feature, for `DEVKIT:\FlashEx` |
| `//xbox360:openxbdm-no-rewrite` | `openxbdm-no-rewrite.xex`, without the save and restore rewrite |

Console crates are built for size (`toolchains/BUCK`): `-Copt-level=z`,
one code generation unit, `-Cpanic=immediate-abort`, and `-Clto=fat` for
the executable. rustc writes the executable's one LTO code generation
unit as assembly along with the image it links (the `[asm]` subtarget and
the default output of the executable).

`openxbdm-asm-rewrite` replaces the callee-saved register saves and
restores in prologues and epilogues with shared helper routines (rules in
`crates/openxbdm-asm-rewrite/src/analysis.rs`). rustc assembles the
result with the integrated assembler of its LLVM (a crate that holds only
the assembly, in `global_asm!`), and rust-lld links it with
`compiler_builtins`, which LTO leaves out, with the arguments rustc passes
when it links the executable. The same link of the object that rustc
linked (the executable's `[obj]` subtarget) must reproduce rustc's image,
or the build fails. An audit of the `llvm-objdump` disassembly then fails
the build if any rewritable sequence remains. Subtargets of
the module targets hold the intermediate files: `[asm]`, `[elf]`,
`[unstripped]`, `[disassembly]`, `[audit]`, `[rewrite-report]`, and
`[refusals]`, which lists each sequence left unchanged and why.

In every case the build fails if the image holds an `lwarx`, `ldarx`,
`stwcx.`, or `stdcx.` outside the interrupt-protected form the kernel
loader accepts (`crates/openxbdm-asm-rewrite/src/reservation.rs`). LLVM
emits unprotected reservations for `core::sync::atomic` read-modify-write
operations unless `core` carries the atomics overlay of rust-xbox360
(`toolchain/rust-std-xbox360`), as the cell's `core` does.

xex-link (`xbox360//crates/xex-link:xex-link`) converts the image with the
metadata in `xbox360/xex.toml`.

## Console deployment

### Kernel debugger host

The recommended method writes nothing to the console disk. While a kd
host is attached, the kernel requests each module from the host before
its own devices, so `openxbdm-kd host` can supply openxbdm at boot.
Stopping the host and rebooting returns the console to stock XBDM from
flash.

kdnet setup, once, through stock XBDM (the address and port are stored in
flash):

    xeedee -H <console> kdnet set IP=<host> Port=50000
    xeedee -H <console> kdnet enable
    xeedee -H <console> reboot

The host must reach the kdnet target address on the local link. For an
APIPA target address (169.254.x.y) add a host route, for example

    nmcli device modify eth0 +ipv4.routes 169.254.59.14/32

Development loop:

1. `buck2 build //xbox360:openxbdm --show-output` (no `boot-guard`
   needed).
2. Start the host and reboot the console:

       openxbdm-kd host --file "host:\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex=$(buck2 build //xbox360:openxbdm --show-simple-output)"

3. Test against port 730. To return to stock XBDM, stop the host and
   reboot.

Kernel debugger notes: `docs/re-notes/kd.md`. Do not set breakpoints in
the kd poll path (`0x801b4990`); do not single step with MSR.SE on
hardware (bug check 0x2b).

### FlashEx file

Use only the boot-guard build here (Overview, above, explains why):

1. Build `//xbox360:openxbdm-boot-guard`.
2. Copy it to `DEVKIT:\FlashEx\xbdm.xex`.
3. Copy any file to `DEVKIT:\FlashEx\openxbdm.arm` (the marker).
4. Turn the console off and on.

For example:

    xeedee -H <console> file put "$(buck2 build //xbox360:openxbdm-boot-guard --show-simple-output)" 'DEVKIT:\FlashEx\xbdm.xex'
    xeedee -H <console> file put openxbdm.arm 'DEVKIT:\FlashEx\openxbdm.arm'

What happens at boot:

- Marker present: the module deletes the marker and starts. Its server
  thread deletes `DEVKIT:\FlashEx\xbdm.xex` (up to 30 attempts, one
  second apart, while the disk comes up) before it accepts connections,
  so the next boot loads the stock monitor from flash.
- Marker absent: an earlier boot used the marker but never got far enough
  to delete `xbdm.xex`. The module starts nothing, deletes `xbdm.xex`, and
  restarts the console into the stock monitor. If the deletion fails, the
  console runs on without any debug monitor.

If the boot hangs, turn the console off and on; the next boot restores
the stock monitor. If the module never starts at all (it fails before its
entry point), or you installed a build without the boot guard, start
`openxbdm-kd host --file` serving a working module for the same path and
restart the console; that module deletes the file once its server starts.
Each installation covers one boot; repeat steps 2 to 4 for the next one.

## Differential testing

`xeedee parity record` sends each line of a command list to a monitor
and writes every reply (head, body lines, binary length and digest) as
JSON; `xeedee parity compare` compares two recordings and exits with
status 1 when they differ outside the varying fields. Run the list once
against stock XBDM (kd host stopped) and once against openxbdm (served by
the kd host), each starting without `DEVKIT:\oxtest`:

    xeedee -H <console> parity record \
        --commands docs/re-notes/parity/hardware-commands.txt --output stock.json
    xeedee -H <console> parity record \
        --commands docs/re-notes/parity/hardware-commands.txt --output openxbdm.json
    xeedee parity compare \
        --variances docs/re-notes/parity/hardware-variances.txt stock.json openxbdm.json

The list holds only lines that are safe to repeat; excluded commands and
the varying fields are described in `docs/re-notes/parity/hardware.md`.

## Buck rules

The build files of the crates follow the Cargo manifests. Do not edit
them; after a change to a `Cargo.toml` or `Cargo.lock`, run

    build_defs/update_buck_files.py

which writes:

- `third-party/rust/BUCK`, through `reindeer buckify`: the rules for the
  crates.io dependencies, each limited to the hosts that use it
  (`build_defs/third_party.bzl`).
- `crates/*/BUCK`: the rules for each workspace crate. A library becomes
  `:<lib>`, a binary `:<bin>-bin`, their unit tests `:<lib>-lib-test` and
  `:<bin>-bin-test`, the integration test `tests/<name>.rs`
  `:<name>-test`, and an example `:<name>-example`. A crate whose
  resolution changes with `--all-features` also gets its library and
  binaries with `-all-features` after the target name. A library with the
  `cdylib` crate type gets Cargo's shared library name.

A crate built for the Xbox 360 has a `[package.metadata.buck2.xbox360]`
table that names its linker script (`link_script`). It may have only
binaries, which become `xbox360_executable` rules without tests. Build
scripts of workspace crates are not supported.

The other build files are written by hand: `BUCK` (the Rust release
check), `bindings/BUCK` (the C++ headers), `xbox360/BUCK` (the console
module), `build_defs/BUCK`, `platforms/BUCK` and `toolchains/BUCK`.

Test-only and optional third-party dependencies, and third-party features
that only `--all-features` enables, are normal dependencies of
`third-party/rust/Cargo.toml`; the script names any that are missing.

Tests run from the project root with `CARGO_MANIFEST_DIR` set to the
crate directory, relative to that root. Read fixtures through
`std::env::var_os("CARGO_MANIFEST_DIR")` at run time, not `env!`.

`build_defs/rust_test.bzl` adds `InternalRunnerTestInfo` to the prelude's
`ExternalRunnerTestInfo`. `buck2 test` lists each binary's libtest cases
(`--list --format terse`), runs every case in its own process
(`--exact <name>`), and reports pass, failure (with the case's output),
or skip (`#[ignore]`) per case. That needs buck2 2026-10-01 or later.

`build_defs/lint.py` checks formatting with the pinned nightly rustfmt
(`.rustfmt.toml`) and the clippy diagnostics of every host target;
`build_defs/lint.py --format` formats the sources. Console executables
have no clippy subtarget.

The test harness layout follows the rarchive repository (`../rarchive`).

## Third-party code

Dependencies are not vendored. Cargo fetches them from crates.io, and
Buck2 downloads each crate from crates.io and checks it against the
SHA-256 in `Cargo.lock`. The xbox360 cell builds the console's standard
library crates from the Rust release's `rust-src` archive with its
overlay; it pins their crates.io dependencies by SHA-256 the same way.

To add or update a dependency:

1. Edit the workspace `Cargo.toml` and the crate manifests.
2. Run `build_defs/update_buck_files.py`.
3. Add fixups under `third-party/rust/fixups/<crate>/fixups.toml` for
   build scripts and files that sources include at compile time.

## Kernel debugger crates

`openxbdm-kd-core` is the `no_std` codec and packet session for kdnet;
`openxbdm-kd` holds the UDP transport, client, GDB target and the
`openxbdm-kd` binary. Protocol notes are in `docs/re-notes/kd.md`. The codec
snapshot tests decode `crates/openxbdm-kd-core/tests/fixtures/kd.log`
(`time peer length hex` lines, the format written by
`openxbdm-kd listen --log-file`). Append new captures there and review the
snapshots with `cargo insta review`. `tests/fixtures/file_io.log` holds the
host file requests of one `xbdm.xex` load, captured with
`openxbdm-kd host --file ... --log-file`.

`xeedee kdnet show` prints the kdnet record in flash;
`xeedee kdnet set --ip <host> --port 50000 [--mac AA-BB-CC-DD-EE-FF]`,
`kdnet enable` and `kdnet disable` write it.

Live checks need kdnet enabled and nothing else bound to UDP 50000. Boot
with XBDM served from the host, then check XBDM on port 730 and the
`file close ...: 258048 bytes served` line:

    openxbdm-kd host --file 'host:\Device\Flash\xbdm.xex=xbdm.xex'

GDB:

    openxbdm-kd break
    gdb -batch -ex 'set architecture powerpc:common64' -ex 'set endian big' \
        -ex 'target remote 127.0.0.1:2159' -ex 'info registers pc' \
        -ex 'x/2c 0x80040000' -ex detach
