#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [--plain | --no-rewrite] [output.xex]" >&2
    exit 2
}

# rewrite: assemble the LTO module after replacing callee-saved register
#   saves and restores with shared helpers (crates/openxbdm-asm-rewrite).
# no-rewrite: assemble the LTO module unchanged.
# plain: link the object rustc emits.
mode=rewrite
case "${1:-}" in
    --plain) mode=plain; shift ;;
    --no-rewrite) mode=no-rewrite; shift ;;
    -*) usage ;;
esac
[ $# -le 1 ] || usage

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
toolchain=${LLVM_XBOX_360:-"$root/../llvm-xbox-360"}
target="$toolchain/targets/powerpc-unknown-xbox360.json"
output=${1:-"$root/target/openxbdm.xex"}
case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac

profile_dir="$root/target/powerpc-unknown-xbox360/xbox360"
tools="$root/target/release"
# The assembly path is part of the module's build arguments and cargo keeps
# separate artifacts per toolchain, so each feature set and toolchain keeps
# its own side outputs.
variant=$(printf '%s' "${OPENXBDM_FEATURES:-}" | tr -c 'A-Za-z0-9_-' '_')
toolchain_id=$(cd "$root" && { rustc -vV && rustc --print sysroot; } | cksum | cut -d ' ' -f 1)
work="$profile_dir/asm-rewrite/${variant:-default}-$toolchain_id"
mkdir -p "$(dirname -- "$output")" "$work"

(
    cd "$root"
    cargo build --quiet --release -p openxbdm-asm-rewrite
)

# Every mode emits the assembly and records the link command, so switching
# modes does not rebuild the module.
build_module() {
    (
        cd "$root"
        OPENXBDM_LINK_RECORD="$work/link-record" \
        RUSTC_BOOTSTRAP=1 \
        RUSTFLAGS="-C link-arg=-T$root/crates/openxbdm-server-xbox360/link.x -C link-arg=--no-rosegment -Zunstable-options -Cpanic=immediate-abort" \
        cargo rustc \
            --profile xbox360 \
            --manifest-path crates/openxbdm-server-xbox360/Cargo.toml \
            --bin openxbdm-server-xbox360 \
            --target "$target" \
            -Zbuild-std=core,compiler_builtins \
            -Zbuild-std-features=compiler-builtins-mem \
            -Zjson-target-spec \
            --features "${OPENXBDM_FEATURES:-}" \
            -- \
            --emit="asm=$work/module.s,link" \
            -C linker="$tools/openxbdm-link-record"
    )
}

# Cargo does not track the assembly or the link record. They belong to the
# image cargo just produced when the recorded link output is that image.
side_outputs_current() {
    [ -f "$work/module.s" ] && [ -f "$work/link-record" ] || return 1
    recorded=$(awk -F '\t' '$1 == "arg" { if (take) { print $2; exit } take = ($2 == "-o") }' "$work/link-record")
    [ -n "$recorded" ] && cmp -s "$recorded" "$profile_dir/openxbdm-server-xbox360"
}

build_module
if ! side_outputs_current; then
    (
        cd "$root"
        RUSTC_BOOTSTRAP=1 cargo clean --quiet \
            -p openxbdm-server-xbox360 \
            --profile xbox360 \
            --target "$target" \
            -Zjson-target-spec
    )
    build_module
    if ! side_outputs_current; then
        echo "error: $work does not match the module cargo built" >&2
        exit 1
    fi
fi

elf="$profile_dir/openxbdm-server-xbox360"
if [ "$mode" != plain ]; then
    target_field() {
        sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" "$target"
    }
    asm="$work/module.s"
    if [ "$mode" = rewrite ]; then
        "$tools/openxbdm-asm-rewrite" rewrite "$asm" "$work/rewritten.s" \
            --scope "$work/scope" \
            --refusals "$work/refusals"
        asm="$work/rewritten.s"
    fi
    "${LLVM_MC:-llvm-mc}" \
        -triple="$(target_field llvm-target)" \
        -mcpu="$(target_field cpu)" \
        -mattr="$(target_field features)" \
        -filetype=obj \
        -o "$work/module.o" \
        "$asm"
    elf="$work/openxbdm-server-xbox360"
    if [ "$mode" = rewrite ]; then
        "$tools/openxbdm-asm-rewrite" relink \
            --record "$work/link-record" \
            --object "$work/module.o" \
            --output "$elf" \
            --unstripped "$elf.unstripped"
        "${LLVM_OBJDUMP:-llvm-objdump}" -d --no-show-raw-insn "$elf.unstripped" > "$work/disassembly"
        "$tools/openxbdm-asm-rewrite" audit "$work/disassembly" --scope "$work/scope"
    else
        "$tools/openxbdm-asm-rewrite" relink \
            --record "$work/link-record" \
            --object "$work/module.o" \
            --output "$elf"
    fi
fi

# The kernel loader reports each reservation outside the
# interrupt-protected form.
"$tools/openxbdm-asm-rewrite" reservations "$elf"

# Run from the toolchain so this repository's rustup and Cargo
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
