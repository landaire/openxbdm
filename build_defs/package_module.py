#!/usr/bin/env python3
"""Builds the console module and copies it out under release names.

Usage: build_defs/package_module.py --version VERSION
                                    [--buck2 PATH] [--out-dir DIR]

Runs from the repository root and writes `openxbdm-VERSION.xex`, for the
kernel debugger host, and `openxbdm-boot-guard-VERSION.xex`, for
DEVKIT:\\FlashEx (DEVELOPING.md, Console deployment). The module is the
same on every host. Prints the file paths.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Target and release name prefix of each build of the module.
MODULES = {
    "root//xbox360:openxbdm": "openxbdm",
    "root//xbox360:openxbdm-boot-guard": "openxbdm-boot-guard",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the release version, for example 0.1.0")
    parser.add_argument("--buck2", default="buck2", help="the buck2 executable")
    parser.add_argument("--out-dir", type=Path, default=ROOT, help="the directory to write the files to")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as scratch:
        report_path = Path(scratch) / "report.json"
        subprocess.run([args.buck2, "build", f"--build-report={report_path}", *MODULES], cwd=ROOT, check=True)
        report = json.loads(report_path.read_text(encoding="utf-8"))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for target, prefix in MODULES.items():
        outputs = report["results"][target]["outputs"]["DEFAULT"]
        if len(outputs) != 1:
            sys.exit(f"error: {target} has {len(outputs)} default outputs, not 1")
        destination = args.out_dir.resolve() / f"{prefix}-{args.version}.xex"
        shutil.copyfile(ROOT / outputs[0], destination)
        print(destination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
