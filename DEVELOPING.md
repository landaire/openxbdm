# Developing

## Environment

`devenv shell` (`devenv.nix`) provides the stable Rust toolchain (with
`rust-src` for `build_xbox360.sh`), Buck2, and Reindeer.

## Build and test

Buck2 is the primary build system. Cargo builds the same sources.

    buck2 build //...
    buck2 test //...

    cargo build --workspace
    cargo test --workspace

## Xbox 360 module

`openxbdm-server-xbox360` targets `powerpc-unknown-xbox360`, which Buck2
does not build. Its rule requires `//platforms:xbox360`
(`fixups/openxbdm-server-xbox360/fixups.toml`), a constraint no Buck
platform provides, so `buck2 build //...` skips it. Build the module with

    ./build_xbox360.sh [output.xex]

which needs the `llvm-xbox-360` toolchain checkout in `../llvm-xbox-360`
or at `$LLVM_XBOX_360`, and writes `target/openxbdm.xex` by default.
`OPENXBDM_FEATURES` passes Cargo features to the module build; deployments
through `DEVKIT:\FlashEx` use `boot-guard`:

    OPENXBDM_FEATURES=boot-guard ./build_xbox360.sh

## Console deployment

The module has not been verified on hardware. A module placed at
`DEVKIT:\FlashEx\xbdm.xex` loads at every boot, before the network is
available, until the file is removed; a module that stops the console
during boot leaves no network path to remove it. The last deployment
(built without `boot-guard`) stopped the console in the boot animation,
and that console stays unreachable until the file is removed by other
means. Do not deploy a build without `boot-guard`.

Deployment, through stock XBDM:

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
module to reach its entry point; a stop before that point, or a build
without `boot-guard`, requires removing `DEVKIT:\FlashEx\xbdm.xex`
without booting the module. Each deployment arms one boot; repeat steps 2
to 4 for the next run.

## Buck rules

`reindeer buckify` generates the root `BUCK` from the workspace `Cargo.toml`:
rules for every vendored crate and for the workspace crates. Do not edit it.
The generated rules list source files explicitly, so run `reindeer buckify`
after adding or removing source files.
Reindeer does not generate test rules; test targets are declared in
`build_defs/rust_tests.bzl`, which the generated file loads through the
`buckfile_imports` setting in `reindeer.toml`. Each `tests/*.rs` file of
a crate listed there becomes a test target, with all of `tests/**` (shared
modules such as `tests/common/mod.rs`, fixtures) in its sources. Update
that file when a crate's test dependencies or features change.

Test-only dependencies are normal dependencies of `openxbdm-testing`, so
that reindeer generates rules for them.

The test harness layout follows the rarchive repository (`../rarchive`).

## Third-party code

All dependencies are vendored in `vendor`, and `.cargo/config.toml`
redirects crates.io to that directory. The redirect also applies to the
standard library sources that `build_xbox360.sh` builds with
`-Zbuild-std`, so their dependencies are vendored as well.

To add or update a dependency, or after changing the Rust toolchain:

1. Edit the workspace `Cargo.toml` and the crate manifests.
2. Run `reindeer --manifest-path <absolute path to Cargo.toml> vendor`.
   This removes crates that the workspace does not use, including the
   standard library dependencies.
3. Vendor the standard library dependencies with the toolchain that
   builds the console module:

       RUSTC_BOOTSTRAP=1 cargo vendor --versioned-dirs --no-delete \
           --manifest-path "$(rustc --print sysroot)/lib/rustlib/src/rust/library/Cargo.toml" \
           vendor

4. Run `reindeer buckify`.
5. Add fixups under `fixups/<crate>/fixups.toml` for build scripts and
   files that sources include at compile time.

Some vendored files exceed the default jj snapshot size limit. Raise it
once per clone:

    jj config set --repo snapshot.max-new-file-size 2097152

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

Live checks need kdnet enabled and nothing else bound to UDP 50000. Boot
with XBDM served from the host, then check XBDM on port 730 and the
`file close ...: 258048 bytes served` line:

    openxbdm-kd host --file 'host:\Device\Flash\xbdm.xex=xbdm.xex'


    openxbdm-kd break
    gdb -batch -ex 'set architecture powerpc:common64' -ex 'set endian big' \
        -ex 'target remote 127.0.0.1:2159' -ex 'info registers pc' \
        -ex 'x/2c 0x80040000' -ex detach
