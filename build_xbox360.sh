#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
toolchain=${LLVM_XBOX_360:-"$root/../llvm-xbox-360"}
target="$toolchain/targets/powerpc-unknown-xbox360.json"
output=${1:-"$root/target/openxbdm.xex"}
case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac

mkdir -p "$(dirname -- "$output")"
(
    cd "$root"
    RUSTC_BOOTSTRAP=1 \
    RUSTFLAGS="-C link-arg=-T$root/crates/openxbdm-server-xbox360/link.x -C link-arg=--no-rosegment -Zunstable-options -Cpanic=immediate-abort" \
    cargo build \
        --profile xbox360 \
        --manifest-path crates/openxbdm-server-xbox360/Cargo.toml \
        --target "$target" \
        -Zbuild-std=core,compiler_builtins \
        -Zbuild-std-features=compiler-builtins-mem \
        -Zjson-target-spec \
        --features "${OPENXBDM_FEATURES:-}"
)

elf="$root/target/powerpc-unknown-xbox360/xbox360/openxbdm-server-xbox360"
# Run from the toolchain so this repository's vendored-source
# configuration does not apply to xex-link.
cd "$toolchain"
cargo run --quiet \
    --manifest-path Cargo.toml \
    -p xex-link -- \
    "$elf" "$output" \
    --load-address 0x91f00000 \
    --version 2.0.21256.0 \
    --base-version 2.0.21256.0 \
    --import-version 2.0.21256.0 \
    --import-min-version 2.0.1861.0 \
    --image-flags SMALL_PAGES \
    --bounding-path '\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex' \
    --module-flags EXPORTS_TO_TITLE,SYSTEM_DEBUGGER,DLL \
    --export-module xbdm.xex \
    --export-min-version 2.0.1861.0 \
    --compress \
    --encrypt devkit
