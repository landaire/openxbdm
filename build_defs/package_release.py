#!/usr/bin/env python3
"""Builds the released executables with the release profile and archives them.

Usage: build_defs/package_release.py --version VERSION --target TRIPLE
                                     [--buck2 PATH] [--out-dir DIR]

Runs from the repository root. The archive, `openxbdm-VERSION-TRIPLE.zip`
on Windows and `.tar.gz` elsewhere, holds one directory with the
executables and README.md. Prints the archive path.
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
# executables are development tools: the mock host server and the tools
# that build_xbox360.sh runs.
EXECUTABLES = {
    "root//crates/openxbdm-cli:openxbdm-bin": "openxbdm",
    "root//crates/openxbdm-kd:openxbdm-kd-bin": "openxbdm-kd",
}

DOCUMENTS = ["README.md"]


def build_executables(buck2_path):
    """Returns (path, archive name) of every executable."""
    with tempfile.TemporaryDirectory() as scratch:
        report_path = Path(scratch) / "report.json"
        subprocess.run(
            [buck2_path, "build", "-c", "rust.profile=release", f"--build-report={report_path}", *EXECUTABLES],
            cwd=ROOT,
            check=True,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    files = []
    for target, name in EXECUTABLES.items():
        outputs = report["results"][target]["outputs"]["DEFAULT"]
        if len(outputs) != 1:
            sys.exit(f"error: {target} has {len(outputs)} default outputs, not 1")
        path = ROOT / outputs[0]
        files.append((path, name + path.suffix))
    return files


def write_archive(archive, directory, files):
    """Writes each (path, name) of `files` as `directory/name`."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as out:
            for path, name in files:
                out.write(path, f"{directory}/{name}")
    else:
        with tarfile.open(archive, "w:gz") as out:
            for path, name in files:
                out.add(path, f"{directory}/{name}", filter=_without_owner)


def _without_owner(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the release version, for example 0.1.0")
    parser.add_argument("--target", required=True, help="the target triple that names the archive")
    parser.add_argument("--buck2", default="buck2", help="the buck2 executable")
    parser.add_argument("--out-dir", type=Path, default=ROOT, help="the directory to write the archive to")
    args = parser.parse_args()

    executables = build_executables(args.buck2)
    directory = f"openxbdm-{args.version}-{args.target}"
    extension = ".zip" if "windows" in args.target else ".tar.gz"
    archive = args.out_dir.resolve() / (directory + extension)
    archive.parent.mkdir(parents=True, exist_ok=True)
    write_archive(archive, directory, executables + [(ROOT / name, name) for name in DOCUMENTS])
    print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
