"""Test targets for the workspace crates.

Reindeer generates library and binary rules but not tests, so the test
targets are declared here and instantiated from the generated root BUCK.
"""

_CLIENT_FEATURES = ["capture", "dangerous", "default", "jiff", "tokio"]

# Matches `workspace.package.version` in Cargo.toml.
_WORKSPACE_VERSION = "0.1.0"

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
    native.rust_test(
        name = name,
        srcs = native.glob([directory + "/src/**/*.rs", directory + "/src/**/*.snap"]),
        crate = crate,
        crate_root = directory + "/" + crate_root,
        edition = "2024",
        features = features,
        env = {"CARGO_MANIFEST_DIR": directory} | env,
        deps = deps,
    )

def _integration_tests(package, directory, deps, features = []):
    """Declares `<package>-<file>-test` for each `tests/*.rs` file.

    Every target receives all of `tests/**`, which covers shared modules
    and fixture files read through `CARGO_MANIFEST_DIR`.
    """
    for root in native.glob([directory + "/tests/*.rs"]):
        stem = root.removeprefix(directory + "/tests/").removesuffix(".rs")
        native.rust_test(
            name = "{}-{}-test".format(package, stem.replace("_", "-")),
            srcs = native.glob([directory + "/tests/**"]),
            crate = stem,
            crate_root = root,
            edition = "2024",
            features = features,
            env = {"CARGO_MANIFEST_DIR": directory},
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
