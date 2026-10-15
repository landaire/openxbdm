"""Checks that rust-toolchain.toml names the Rust release Buck2 builds with.

Usage: check_rust_toolchain.py RUST_TOOLCHAIN_TOML RELEASE

Cargo and rust-analyzer use the release of rust-toolchain.toml; Buck2 uses
the one that the xbox360 cell pins, which the Xbox 360 standard library
overlay is written against.
"""

import sys
import tomllib


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.strip())
    path, release = sys.argv[1:]
    with open(path, "rb") as toolchain_file:
        channel = tomllib.load(toolchain_file)["toolchain"]["channel"]
    if channel != release:
        print(f"error: {path} names Rust {channel}; the xbox360 cell pins {release}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
