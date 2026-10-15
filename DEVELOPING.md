# Developing

## Environment

`devenv shell` (`devenv.nix`) provides Buck2, Reindeer, and the Rust
release in `rust-toolchain.toml`.

The Rust release is pinned in two places that must name the same version:

- `rust-toolchain.toml`, which rustup and devenv read for Cargo,
  rust-analyzer and `build_xbox360.sh`. It adds `clippy`, `rustfmt`,
  `rust-analyzer`, and `rust-src`, the library source that the console
  module builds with `-Zbuild-std`.
- `toolchains/rust_release.bzl`, the archives that Buck2 downloads itself:
  `rustc` (rustc, rustdoc, and the bundled lld), `rust-std`, and
  `clippy-preview` (clippy-driver). Buck2 verifies each archive's SHA-256
  and assembles them once into a sysroot for the host, so `buck2 build`
  needs no installed Rust. Buck2 builds only for the host it runs on.

The channel must be an exact release. To change it, edit
`rust-toolchain.toml` and run

    toolchains/update_rust_release.py

which writes `toolchains/rust_release.bzl` from the release's channel
manifest on static.rust-lang.org. `toolchains/update_rust_release.py
--check` verifies, without network access, that the two files name the
same release.

Buck2 links with the host's linker driver: `c++` (GCC or Clang) with the
lld bundled in `rustc` on Linux, Xcode command line tools on macOS, and
MSVC build tools on Windows. The prelude's Python tools run on a CPython
that Buck2 downloads.

## Build and test

Buck2 is the primary build system. Cargo builds the same sources.

    buck2 build //...
    buck2 test //...

    cargo build --workspace
    cargo test --workspace

## Xbox 360 module

`openxbdm-server-xbox360` targets `powerpc-unknown-xbox360`, which Buck2
does not build. Its rule requires `//platforms:xbox360`
(`[package.metadata.buck2]` in its `Cargo.toml`), a constraint no Buck
platform provides, so `buck2 build //...` skips it. Build the module with

    ./build_xbox360.sh [--plain | --no-rewrite] [output.xex]

which needs the `llvm-xbox-360` toolchain checkout in `../llvm-xbox-360`
or at `$LLVM_XBOX_360`, and writes `target/openxbdm.xex` by default. It
runs the `cargo` in `PATH`. The standard library overlay must be applied
to that toolchain's `rust-src`, which the read-only Nix store of the devenv
toolchain does not allow, so build the module with rustup's toolchain
outside the devenv shell. Apply the overlay once, from this directory:

    ../llvm-xbox-360/toolchain/rust-std-xbox360/apply.sh

The script needs `patch`. Cargo does not notice the changed `rust-src`, so
delete the cached standard library build (the `powerpc-unknown-xbox360`
directory under the Cargo target directory) after applying the overlay.
Outside the devenv shell, set `LLVM_MC` and `LLVM_OBJDUMP` to the devenv's
LLVM tools.

`OPENXBDM_FEATURES` passes Cargo features to the module build; the
`DEVKIT:\FlashEx` deployment uses `boot-guard`:

    OPENXBDM_FEATURES=boot-guard ./build_xbox360.sh

The module crate emits its LTO module as assembly, and
`openxbdm-asm-rewrite` replaces the callee-saved register saves and
restores in prologues and epilogues with shared helper routines (rules in
`crates/openxbdm-asm-rewrite/src/analysis.rs`). `llvm-mc` assembles the
result, and the link command rustc ran, recorded by
`openxbdm-link-record`, links it. An audit of the `llvm-objdump`
disassembly then fails the build if any rewritable sequence remains.
`llvm-mc` and `llvm-objdump` come from the devenv shell, or from
`$LLVM_MC` and `$LLVM_OBJDUMP`. Intermediate files and the linked image
are in
`target/powerpc-unknown-xbox360/xbox360/asm-rewrite/<features>-<toolchain>/`;
`refusals` there lists each sequence left unchanged and why.

`--no-rewrite` assembles the module without the rewrite; `--plain` links
the object rustc emits, at
`target/powerpc-unknown-xbox360/xbox360/openxbdm-server-xbox360`.

In every mode the build fails if the image holds an `lwarx`, `ldarx`,
`stwcx.`, or `stdcx.` outside the interrupt-protected form the kernel
loader accepts (`crates/openxbdm-asm-rewrite/src/reservation.rs`). LLVM
emits unprotected reservations for `core::sync::atomic` read-modify-write
operations unless the active toolchain's `rust-src` carries the atomics
overlay of `llvm-xbox-360/toolchain/rust-std-xbox360` (`apply.sh`). The
devenv toolchain's `rust-src` is a read-only store path without it, so
build with the rustup toolchain the overlay was applied to.

## Console deployment

### Kernel debugger host

The recommended method writes nothing to the console disk. While a kd
host is attached, the kernel requests each module from the host before
its own devices, so `openxbdm-kd host` can supply openxbdm at boot.
Stopping the host and rebooting returns the console to stock XBDM from
flash.

kdnet setup, once, through stock XBDM (the address and port are stored in
flash):

    openxbdm -H <console> kdnet set IP=<host> Port=50000
    openxbdm -H <console> kdnet enable
    openxbdm -H <console> reboot

The host must reach the kdnet target address on the local link. For an
APIPA target address (169.254.x.y) add a host route, for example

    nmcli device modify eth0 +ipv4.routes 169.254.59.14/32

Development loop:

1. `./build_xbox360.sh` (no `boot-guard` needed).
2. Start the host and reboot the console:

       openxbdm-kd host --file 'host:\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex=target/openxbdm.xex'

3. Test against port 730. To return to stock XBDM, stop the host and
   reboot.

Kernel debugger notes: `docs/re-notes/kd.md`. Do not set breakpoints in
the kd poll path (`0x801b4990`); do not single step with MSR.SE on
hardware (bug check 0x2b).

### FlashEx file

A module placed at `DEVKIT:\FlashEx\xbdm.xex` loads at every boot, before
the network is available, until the file is removed. A build that stops
the console during boot freezes every following boot until the file is
removed. Use only `boot-guard` builds:

1. Build with `OPENXBDM_FEATURES=boot-guard`.
2. Upload `target/openxbdm.xex` to `DEVKIT:\FlashEx\xbdm.xex`.
3. Create the marker file `DEVKIT:\FlashEx\openxbdm.arm` (any content).
4. Reboot the console cold.

For example:

    openxbdm -H <console> file put target/openxbdm.xex 'DEVKIT:\FlashEx\xbdm.xex'
    openxbdm -H <console> file put empty.bin 'DEVKIT:\FlashEx\openxbdm.arm'

Boot behavior of a `boot-guard` build:

- Marker present: the module deletes the marker and starts. Its server
  thread then deletes `DEVKIT:\FlashEx\xbdm.xex` (up to 30 attempts, one
  second apart) before opening the listener, so the next boot loads the
  flash monitor.
- Marker absent: the previous boot of this build started but did not
  remove the override. The module installs no hook, deletes
  `DEVKIT:\FlashEx\xbdm.xex`, and restarts the console into the flash
  monitor. If the deletion fails the console continues without a debug
  monitor.

Recovery: if the armed boot stops, power-cycle the console. The next boot
runs without the marker and restores the flash monitor. This requires the
module to reach its entry point. A stop before that point, or a build
without `boot-guard`, needs the kd host: serve a working image for the
same path with `openxbdm-kd host --file` and reboot; its server thread
deletes the override. Each deployment arms one boot; repeat steps 2 to 4
for the next run.

## Differential testing

`openxbdm parity record` sends each line of a command list to a monitor
and writes every reply (head, body lines, binary length and digest) as
JSON; `openxbdm parity compare` compares two recordings and exits with
status 1 when they differ outside the varying fields. Run the list once
against stock XBDM (kd host stopped) and once against openxbdm (served by
the kd host), each starting without `DEVKIT:\oxtest`:

    openxbdm -H <console> parity record \
        --commands docs/re-notes/parity/hardware-commands.txt --output stock.json
    openxbdm -H <console> parity record \
        --commands docs/re-notes/parity/hardware-commands.txt --output openxbdm.json
    openxbdm parity compare \
        --variances docs/re-notes/parity/hardware-variances.txt stock.json openxbdm.json

The list holds only lines that are safe to repeat; excluded commands and
the varying fields are described in `docs/re-notes/parity/hardware.md`.

## Buck rules

The build files follow the Cargo manifests. Do not edit them; after a
change to a `Cargo.toml` or `Cargo.lock`, run

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
  binaries with `-all-features` after the target name.

A crate that only Cargo builds names a constraint that no Buck2 platform
provides in `[package.metadata.buck2] compatible_with`; host builds skip
its rules. `CARGO_ONLY_CONSTRAINTS` in the script lists the accepted
constraints. Build scripts of other workspace crates are not supported.

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
(`.rustfmt.toml`) and the clippy diagnostics of every workspace target;
`build_defs/lint.py --format` formats the sources.

The test harness layout follows the rarchive repository (`../rarchive`).

## Third-party code

Dependencies are not vendored. Cargo fetches them from crates.io, and
Buck2 downloads each crate from crates.io and checks it against the
SHA-256 in `Cargo.lock`. `build_xbox360.sh` builds the standard library
sources with `-Zbuild-std`; Cargo resolves their dependencies through the
toolchain's `library/Cargo.lock`.

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

`openxbdm kdnet show` prints the kdnet record in flash;
`openxbdm kdnet set --ip <host> --port 50000 [--mac AA-BB-CC-DD-EE-FF]`,
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
