"""Test targets for the workspace crates.

Reindeer generates library and binary rules but not tests, so the test
targets are declared here and instantiated from the generated root BUCK.

`rust_test` is the prelude rule with Buck2's internal test runner: each
libtest case is listed and run in its own process, and Buck2 reports a
result and duration for each case. This requires buck2 2026-10-01 or later.
"""

load("@prelude//rules.bzl", "clone_rule")
load("@prelude//rust:rust_binary.bzl", "rust_test_impl")

_LIBTEST_STATUS = {
    "failed": "FAIL",
    "ignored": "SKIP",
    "passed": "PASS",
}

def _parse_test_listing(listing: str) -> list[dict[str, str]]:
    """Parses `--list --format terse` output: one `<name>: test` line per case."""
    cases = []
    for line in listing.splitlines():
        if line.endswith(": test"):
            name = line.removesuffix(": test")
            cases.append({"filter": name, "name": name})
    return cases

def _parse_summary(line: str) -> (dict[str, int], float | None):
    """Parses `test result: ok. 1 passed; 0 failed; ...; finished in 0.01s`."""
    counts = {}
    duration = None
    for field in line.partition(". ")[2].split("; "):
        if field.startswith("finished in ") and field.endswith("s"):
            duration = float(field.removeprefix("finished in ").removesuffix("s"))
        else:
            count, _, kind = field.partition(" ")
            if count.isdigit():
                counts[kind] = int(count)
    return counts, duration

def _parse_test_result(stdout: str, stderr: str, exit_code: int) -> list[dict[str, typing.Any]]:
    """Reports the single case selected by `--exact <name>`.

    Returns no entries when libtest did not print both the case line and the
    summary (for example after a crash); Buck2 then reports the case from
    the exit code.
    """
    name = None
    counts = None
    duration = None
    for line in stdout.splitlines():
        if name == None and line.startswith("test ") and " ... " in line:
            # `#[should_panic]` cases print as `test <name> - should panic ... `.
            name = line.removeprefix("test ").partition(" ... ")[0].removesuffix(" - should panic")
        elif line.startswith("test result: "):
            counts, duration = _parse_summary(line)
    if name == None or counts == None:
        return []

    status = None
    for kind, value in _LIBTEST_STATUS.items():
        if counts.get(kind) == 1:
            status = value
    if status == None:
        return []

    # A case that passes inside libtest still fails if the process does
    # not exit cleanly, for example when a destructor aborts.
    if status != "FAIL" and exit_code != 0:
        status = "FAIL"

    # libtest prints a failing case's captured output; passing cases have
    # none worth showing.
    details = None
    if status == "FAIL":
        details = "---- STDOUT ----\n{}\n---- STDERR ----\n{}\n".format(stdout, stderr)

    return [{
        "details": details,
        "duration": duration,
        "name": name,
        "status": status,
    }]

def _rust_test_impl(ctx: AnalysisContext) -> list[Provider]:
    providers = rust_test_impl(ctx)

    # `framework = False` binaries do not implement the libtest interface.
    if not ctx.attrs.framework:
        return providers

    result = list(providers)
    for provider in providers:
        if isinstance(provider, ExternalRunnerTestInfo):
            # Buck2 uses this provider when `test.use_internal_runner`
            # allows it and the prelude's ExternalRunnerTestInfo otherwise.
            result.append(InternalRunnerTestInfo(
                type = provider.test_type,
                listing_command = provider.command + ["--list", "--format", "terse"],
                command = provider.command + ["--color", "never", "--exact"],
                env = provider.env,
                labels = provider.labels,
                contacts = provider.contacts,
                run_from_project_root = provider.run_from_project_root,
                use_project_relative_paths = provider.use_project_relative_paths,
                default_executor = provider.default_executor,
                executor_overrides = provider.executor_overrides,
                parse_test_listing = _parse_test_listing,
                parse_test_result = _parse_test_result,
            ))
    return result

rust_test = clone_rule("rust_test", impl_override = _rust_test_impl)

_CLIENT_FEATURES = ["capture", "dangerous", "default", "jiff", "tokio"]

# Matches `workspace.package.version` in Cargo.toml.
_WORKSPACE_VERSION = "0.1.0"

def _test_env(directory):
    return {
        "CARGO_MANIFEST_DIR": directory,
        # Tests run from the project root. Without this, insta runs
        # `cargo metadata` to find the workspace root.
        "INSTA_WORKSPACE_ROOT": ".",
    }

def _reindeer_rule(package):
    """Returns the versioned rule name reindeer gives a workspace crate."""
    major, minor, patch = _WORKSPACE_VERSION.split(".")
    if major != "0":
        suffix = major
    elif minor != "0":
        suffix = "0." + minor
    else:
        suffix = "0.0." + patch
    return ":{}-{}".format(package, suffix)

def _unit_test(name, crate, directory, crate_root, deps, features = [], env = {}):
    rust_test(
        name = name,
        srcs = native.glob([directory + "/src/**/*.rs", directory + "/src/**/*.snap"]),
        crate = crate,
        crate_root = directory + "/" + crate_root,
        edition = "2024",
        features = features,
        env = _test_env(directory) | env,
        deps = deps,
    )

def _integration_tests(package, directory, deps, features = []):
    """Declares `<package>-<file>-test` for each `tests/*.rs` file.

    Every target receives all of `tests/**`, which covers shared modules
    and fixture files read through `CARGO_MANIFEST_DIR`.
    """
    for root in native.glob([directory + "/tests/*.rs"]):
        stem = root.removeprefix(directory + "/tests/").removesuffix(".rs")
        rust_test(
            name = "{}-{}-test".format(package, stem.replace("_", "-")),
            srcs = native.glob([directory + "/tests/**"]),
            crate = stem,
            crate_root = root,
            edition = "2024",
            features = features,
            env = _test_env(directory),
            deps = deps,
        )

def rust_tests():
    _unit_test(
        name = "openxbdm-core-test",
        crate = "openxbdm_core",
        directory = "crates/openxbdm-core",
        crate_root = "src/lib.rs",
        deps = [],
    )
    _integration_tests(
        package = "openxbdm-core",
        directory = "crates/openxbdm-core",
        deps = [":openxbdm-core"],
    )
    _unit_test(
        name = "openxbdm-client-test",
        crate = "openxbdm_client",
        directory = "crates/openxbdm-client",
        crate_root = "src/lib.rs",
        features = _CLIENT_FEATURES,
        deps = [
            ":bytes",
            ":futures",
            ":futures-io",
            ":futures-util",
            ":insta",
            ":jiff",
            ":memchr",
            ":openxbdm-core",
            ":powerpc",
            ":rootcause",
            ":thiserror",
            ":tokio",
            ":tokio-util",
            ":tracing",
            ":winnow",
        ],
    )
    _integration_tests(
        package = "openxbdm-client",
        directory = "crates/openxbdm-client",
        features = _CLIENT_FEATURES,
        deps = [
            ":futures",
            ":insta",
            ":openxbdm-client",
            ":tokio",
        ],
    )
    _unit_test(
        name = "openxbdm-cli-test",
        crate = "openxbdm",
        directory = "crates/openxbdm-cli",
        crate_root = "src/main.rs",
        features = ["capture", "dangerous", "default"],
        # Read by clap's `version` attribute.
        env = {"CARGO_PKG_VERSION": _WORKSPACE_VERSION},
        deps = [
            ":clap",
            ":futures-io",
            ":insta",
            ":futures-util",
            ":image",
            ":indicatif",
            ":jiff",
            ":openxbdm-client",
            ":owo-colors",
            ":powerpc",
            ":rootcause",
            ":serde",
            ":serde_json",
            ":similar",
            ":tabled",
            ":thiserror",
            ":tokio",
            ":tokio-util",
            ":tracing",
            ":tracing-subscriber",
            ":xex2",
        ],
    )
    _integration_tests(
        package = "openxbdm-kd-core",
        directory = "crates/openxbdm-kd-core",
        deps = [":insta", ":openxbdm-kd-core"],
    )
    _unit_test(
        name = "openxbdm-kd-test",
        crate = "openxbdm_kd",
        directory = "crates/openxbdm-kd",
        crate_root = "src/lib.rs",
        deps = [
            ":clap",
            ":gdbstub",
            ":jiff",
            ":openxbdm-kd-core",
            ":rootcause",
            ":thiserror",
            ":tracing",
            ":tracing-subscriber",
        ],
    )
    _unit_test(
        name = "openxbdm-server-test",
        crate = "openxbdm_server",
        directory = "crates/openxbdm-server",
        crate_root = "src/lib.rs",
        deps = [":insta", ":openxbdm-core"],
    )
    _integration_tests(
        package = "openxbdm-server",
        directory = "crates/openxbdm-server",
        deps = [
            ":openxbdm-core",
            ":openxbdm-server",
        ],
    )
    # Reindeer emits aliases only for crates that a workspace crate
    # depends on.
    native.alias(
        name = "openxbdm-server-host",
        actual = _reindeer_rule("openxbdm-server-host"),
        visibility = ["PUBLIC"],
    )
    _integration_tests(
        package = "openxbdm-server-host",
        directory = "crates/openxbdm-server-host",
        deps = [
            ":openxbdm-client",
            ":openxbdm-core",
            ":openxbdm-server",
            ":openxbdm-server-host",
            ":tokio",
        ],
    )
