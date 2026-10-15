"""A test that rust-toolchain.toml names the release of the xbox360 cell."""

load("@prelude//decls:toolchains_common.bzl", "toolchains_common")
load("@prelude//python_bootstrap:python_bootstrap.bzl", "PythonBootstrapToolchainInfo")
load("@xbox360//buck:rust_release.bzl", "RUST_RELEASE")

def _rust_toolchain_test_impl(ctx: AnalysisContext) -> list[Provider]:
    command = cmd_args(
        ctx.attrs._python_bootstrap_toolchain[PythonBootstrapToolchainInfo].interpreter,
        ctx.attrs._check,
        ctx.attrs.toolchain_file,
        RUST_RELEASE,
    )
    return [
        DefaultInfo(),
        RunInfo(args = command),
        ExternalRunnerTestInfo(type = "custom", command = [command]),
    ]

rust_toolchain_test = rule(
    impl = _rust_toolchain_test_impl,
    attrs = {
        "toolchain_file": attrs.source(),
        "_check": attrs.source(default = "root//build_defs:check_rust_toolchain.py"),
        "_python_bootstrap_toolchain": toolchains_common.python_bootstrap(),
    },
)
