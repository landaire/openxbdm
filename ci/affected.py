#!/usr/bin/env python3
"""Select and run CI checks for first-party targets changed since a base commit."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TypedDict


class Target(TypedDict):
    label: str
    hash: str
    type: str
    doctests: bool


ROOT = Path(__file__).resolve().parent.parent
FIRST_PARTY = ("root//:", "root//bindings/...", "root//openxbdm/...", "root//xbox360/...")
FULL_PREFIXES = (
    ".buckconfig",
    ".github/workflows/ci.yml",
    ".rustfmt.toml",
    "bin/",
    "bootstrap.",
    "build_defs/",
    "ci/",
    "devenv.",
    "flake.",
    "nix/",
    "platforms/",
    "prelude/",
    "reindeer.toml",
    "rust-toolchain.toml",
    "toolchains/",
)
FULL_FILES = {"Cargo.lock", "Cargo.toml", "PACKAGE"}
FULL_SUFFIXES = (".bzl", ".bxl", "/PACKAGE")
FULL_BUILD = list(FIRST_PARTY)
FULL_TESTS = list(FIRST_PARTY)
FULL_LINT = ["root//openxbdm/..."]


def executable_command(command: list[str], cwd: Path) -> list[str]:
    if sys.platform == "win32" and command and command[0] == "buck2":
        return [
            str(ROOT / ".tools/bin/dotslash.exe"),
            str(cwd / "toolchains/buck2"),
            *command[1:],
        ]

    return command


def run(
    command: list[str], *, cwd: Path = ROOT, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        executable_command(command, cwd),
        cwd=cwd,
        check=check,
        stdout=subprocess.PIPE,
        text=True,
    )


def full_result(reason: str) -> dict[str, object]:
    return {
        "full": True,
        "reason": reason,
        "build": FULL_BUILD,
        "tests": FULL_TESTS,
        "lint": FULL_LINT,
        "generated": True,
    }


def needs_full(path: str) -> bool:
    return (
        path in FULL_FILES
        or any(path.startswith(prefix) for prefix in FULL_PREFIXES)
        or any(path.endswith(suffix) for suffix in FULL_SUFFIXES)
    )


def target_hashes(root: Path) -> list[Target] | None:
    result = run(
        [
            "buck2",
            "targets",
            "-m",
            "ppc64-ilp32",
            *FIRST_PARTY,
            "--json",
            "--show-target-hash",
            "--target-hash-recursive=true",
            "--target-hash-file-mode=paths_and_contents",
            "--output-attribute",
            r"^(name|doctests|buck\.(type|target_hash|package))$",
        ],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        return None
    targets = json.loads(result.stdout)
    return [
        {
            "label": f'{target["buck.package"]}:{target["name"]}',
            "hash": target["buck.target_hash"],
            "type": target["buck.type"].rsplit(":", 1)[-1],
            "doctests": target.get("doctests", False),
        }
        for target in targets
    ]


def changed_paths(base: str) -> list[str]:
    output = run(["git", "diff", "--name-only", "--no-renames", "-z", base, "--"]).stdout
    return [path for path in output.split("\0") if path]


def ensure_base(base: str) -> bool:
    if run(["git", "cat-file", "-e", f"{base}^{{commit}}"], check=False).returncode == 0:
        return True
    return run(["git", "fetch", "--no-tags", "--depth=1", "origin", base], check=False).returncode == 0


def base_target_hashes(base: str) -> list[Target] | None:
    worktree = Path(tempfile.mkdtemp(prefix="openxbdm-affected-base-"))
    added = False
    try:
        added = (
            run(
                ["git", "worktree", "add", "--detach", "--force", str(worktree), base],
                check=False,
            ).returncode
            == 0
        )
        if not added:
            return None
        local_config = ROOT / ".buckconfig.local"
        if local_config.exists():
            shutil.copy2(local_config, worktree / local_config.name)
        return target_hashes(worktree)
    finally:
        if added:
            run(["buck2", "kill"], cwd=worktree, check=False)
            run(["git", "worktree", "remove", "--force", str(worktree)], check=False)
        else:
            shutil.rmtree(worktree, ignore_errors=True)


def package_prefix(label: str) -> str:
    return label.split(":", 1)[0].removeprefix("root//")


def touched_packages(paths: list[str], targets: list[Target]) -> set[str]:
    packages = {package_prefix(target["label"]) for target in targets}
    touched: set[str] = set()
    for path in paths:
        matches = [
            package
            for package in packages
            if package and (path == package or path.startswith(package + "/"))
        ]
        if matches:
            touched.add(max(matches, key=len))
    return touched


def generated_files_changed(paths: list[str]) -> bool:
    auto_target_directories = ("/benches/", "/examples/", "/src/bin/", "/tests/")
    return any(
        path in {"Cargo.lock", "Cargo.toml", "build.rs", "rust-toolchain.toml"}
        or path.endswith(("/Cargo.toml", "/BUCK", "/build.rs", "/src/lib.rs", "/src/main.rs"))
        or any(directory in f"/{path}" for directory in auto_target_directories)
        for path in paths
    )


def is_test_target(target: Target) -> bool:
    return target["type"].endswith("_test") or (
        target["type"] == "rust_library" and target["doctests"]
    )


def select_affected(base: str) -> dict[str, object]:
    if not base:
        return full_result("no successful mainline run to compare against")
    if not ensure_base(base):
        return full_result(f"could not fetch {base}")

    paths = changed_paths(base)
    forcing = next((path for path in paths if needs_full(path)), None)
    if forcing:
        return full_result(f"{forcing} changed")

    before = base_target_hashes(base)
    if before is None:
        return full_result(f"the graph at {base} does not parse")
    after = target_hashes(ROOT)
    if after is None:
        raise SystemExit("buck2 targets failed on this checkout")

    old_hashes = {target["label"]: target["hash"] for target in before}
    affected = [target for target in after if old_hashes.get(target["label"]) != target["hash"]]
    touched = touched_packages(paths, after)
    tests = {
        target["label"]
        for target in affected
        if is_test_target(target)
    }
    tests.update(
        target["label"]
        for target in after
        if is_test_target(target) and package_prefix(target["label"]) in touched
    )
    lint = sorted(
        target["label"]
        for target in affected
        if target["label"].startswith("root//openxbdm/")
    )
    return {
        "full": False,
        "reason": f"{len(affected)} first-party target(s) changed since {base}",
        "build": sorted(target["label"] for target in affected),
        "tests": sorted(tests),
        "lint": lint,
        "generated": generated_files_changed(paths),
    }


def write_selection(selection: dict[str, object], output: Path, github_output: Path | None) -> None:
    output.write_text(json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = ", ".join(f"{field}={len(selection[field])}" for field in ("build", "tests", "lint"))
    print(f'{selection["reason"]}: {counts}')
    if github_output:
        with github_output.open("a", encoding="utf-8") as stream:
            for field in ("build", "tests", "lint"):
                stream.write(f"{field}={'true' if selection[field] else 'false'}\n")
            stream.write(f"generated={'true' if selection['generated'] else 'false'}\n")


def run_selected(selection_path: Path, field: str, command: list[str]) -> int:
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    targets = selection[field]
    if not isinstance(targets, list) or any(
        not isinstance(target, str) or not target.startswith("root//")
        for target in targets
    ):
        raise SystemExit(f"{field} contains an invalid target")
    if not targets:
        print(f"No {field} target is affected.")
        return 0
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("no command follows --")
    return subprocess.run(executable_command([*command, *targets], ROOT), cwd=ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    select = subparsers.add_parser("select", help="write the affected-target selection")
    select.add_argument("--base", default="")
    select.add_argument("--full", action="store_true")
    select.add_argument("--out", type=Path, required=True)
    select.add_argument("--github-output", type=Path)

    execute = subparsers.add_parser("run", help="append a selected target list to a command")
    execute.add_argument("--selection", type=Path, required=True)
    execute.add_argument("--field", choices=("build", "tests", "lint"), required=True)
    execute.add_argument("command", nargs=argparse.REMAINDER)

    args = parser.parse_args()
    if args.action == "run":
        return run_selected(args.selection, args.field, args.command)

    selection = full_result("a full run was requested") if args.full else select_affected(args.base)
    write_selection(selection, args.out, args.github_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
