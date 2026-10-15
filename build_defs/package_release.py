#!/usr/bin/env python3
"""Builds the release archives of the host with the release profile.

Usage: build_defs/package_release.py --version VERSION --target TRIPLE
                                     [--buck2 PATH] [--out-dir DIR]

Runs from the repository root and writes, `.zip` on Windows and `.tar.gz`
elsewhere:

- `xeedee-VERSION-TRIPLE`: the executables and README.md.
- `xeedee-ffi-VERSION-TRIPLE`: the openxbdm-ffi shared and static
  libraries in `lib/`, their C++ headers in `include/`, and README.md.

Each archive holds one directory of the same name. Prints the archive
paths.
"""

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The XBDM client and the kernel debugger host, and the Cargo name of each.
# Buck2 names an executable after its crate. The other workspace
# executables are development tools: the mock host server, the console
# module's assembly rewrite, and the FFI header generator.
EXECUTABLES = {
    "root//crates/openxbdm-cli:xeedee-bin": "xeedee",
    "root//crates/openxbdm-kd:openxbdm-kd-bin": "openxbdm-kd",
}

FFI_SHARED = "root//crates/openxbdm-ffi:openxbdm_ffi[cdylib]"
FFI_STATIC = "root//crates/openxbdm-ffi:openxbdm_ffi[staticlib]"
FFI_HEADERS = "root//bindings:cpp"

DOCUMENTS = ["README.md"]


def build(buck2_path, targets):
    """Builds `targets` and returns the single output of each."""
    with tempfile.TemporaryDirectory() as scratch:
        report_path = Path(scratch) / "report.json"
        subprocess.run(
            [buck2_path, "build", "-c", "rust.profile=release", f"--build-report={report_path}", *targets],
            cwd=ROOT,
            check=True,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    outputs = {}
    for target in targets:
        label, _, subtarget = target.partition("[")
        result = report["results"][label]["outputs"]
        files = result["DEFAULT" if not subtarget else subtarget.removesuffix("]")]
        if len(files) != 1:
            sys.exit(f"error: {target} has {len(files)} outputs, not 1")
        outputs[target] = ROOT / files[0]
    return outputs


def add_tree(files, path, name):
    """Appends (path, name) for `path` and, for a directory, every file below it."""
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                files.append((child, f"{name}/{child.relative_to(path).as_posix()}"))
    else:
        files.append((path, name))


def write_archive(archive, directory, files):
    """Writes each (path, name) of `files` as `directory/name`.

    Buck2 outputs may be symlinks; the archive holds the files they name.
    """
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as out:
            for path, name in files:
                out.write(path.resolve(), f"{directory}/{name}")
    else:
        with tarfile.open(archive, "w:gz") as out:
            for path, name in files:
                out.add(path.resolve(), f"{directory}/{name}", filter=_without_owner)


def _without_owner(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the release version, for example 0.1.0")
    parser.add_argument("--target", required=True, help="the target triple that names the archives")
    parser.add_argument("--buck2", default="buck2", help="the buck2 executable")
    parser.add_argument("--out-dir", type=Path, default=ROOT, help="the directory to write the archives to")
    args = parser.parse_args()

    windows = "windows" in args.target
    outputs = build(args.buck2, [*EXECUTABLES, FFI_SHARED, FFI_STATIC, FFI_HEADERS])
    documents = [(ROOT / name, name) for name in DOCUMENTS]

    executables = [(outputs[target], name + outputs[target].suffix) for target, name in EXECUTABLES.items()]
    ffi = [
        (outputs[FFI_SHARED], "lib/" + outputs[FFI_SHARED].name),
        # Cargo's name; Buck2 adds a hash to the file name.
        (outputs[FFI_STATIC], "lib/openxbdm_ffi.lib" if windows else "lib/libopenxbdm_ffi.a"),
    ]
    add_tree(ffi, outputs[FFI_HEADERS], "include")

    extension = ".zip" if windows else ".tar.gz"
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for prefix, files in [("xeedee", executables), ("xeedee-ffi", ffi)]:
        directory = f"{prefix}-{args.version}-{args.target}"
        archive = args.out_dir.resolve() / (directory + extension)
        write_archive(archive, directory, files + documents)
        print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
