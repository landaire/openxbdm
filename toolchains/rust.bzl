"""Rust toolchain built from the archives pinned in rust_release.bzl."""

load("@prelude//decls:toolchains_common.bzl", "toolchains_common")
load("@prelude//python_bootstrap:python_bootstrap.bzl", "PythonBootstrapToolchainInfo")
load("@prelude//rust:rust_toolchain.bzl", "PanicRuntime", "RustToolchainInfo")
load(":rust_release.bzl", "RUST_HOSTS")

def _select_host(field: typing.Callable) -> Select:
    """Selects `field(host)` for the configured host."""
    return select({
        "prelude//os:" + os_name: select({
            "prelude//cpu:" + cpu: field(host)
            for cpu, host in cpus.items()
        })
        for os_name, cpus in RUST_HOSTS.items()
    })

def rust_release_archives(components: list[str]) -> list[str]:
    """Declares an `http_file` per component and returns their labels."""
    labels = []
    for component in components:
        name = "rust-{}-archive".format(component)
        native.http_file(
            name = name,
            urls = [_select_host(lambda host: host["archives"][component]["url"])],
            sha256 = _select_host(lambda host: host["archives"][component]["sha256"]),
            out = "{}.tar.xz".format(component),
        )
        labels.append(":" + name)
    return labels

def rust_release_triple() -> Select:
    return _select_host(lambda host: host["triple"])

def _rust_sysroot_impl(ctx: AnalysisContext) -> list[Provider]:
    sysroot = ctx.actions.declare_output("sysroot", dir = True)
    ctx.actions.run(
        cmd_args(
            ctx.attrs._python_bootstrap_toolchain[PythonBootstrapToolchainInfo].interpreter,
            ctx.attrs.assembler,
            sysroot.as_output(),
            [archive[DefaultInfo].default_outputs[0] for archive in ctx.attrs.archives],
        ),
        category = "rust_sysroot",
    )
    return [DefaultInfo(default_output = sysroot)]

# Merges the release archives into one directory.
rust_sysroot = rule(
    impl = _rust_sysroot_impl,
    attrs = {
        "archives": attrs.list(attrs.dep()),
        "assembler": attrs.source(),
        "_python_bootstrap_toolchain": toolchains_common.python_bootstrap(),
    },
)

def _rust_release_toolchain_impl(ctx: AnalysisContext) -> list[Provider]:
    sysroot = ctx.attrs.sysroot[DefaultInfo].default_outputs[0]

    def tool(name):
        return RunInfo(args = cmd_args(sysroot, format = "{}/bin/" + name + ctx.attrs.executable_suffix))

    return [
        DefaultInfo(),
        RustToolchainInfo(
            clippy_driver = tool("clippy-driver"),
            compiler = tool("rustc"),
            default_edition = ctx.attrs.default_edition,
            panic_runtime = PanicRuntime("unwind"),
            rustc_target_triple = ctx.attrs.rustc_target_triple,
            rustdoc = tool("rustdoc"),
        ),
    ]

rust_release_toolchain = rule(
    impl = _rust_release_toolchain_impl,
    attrs = {
        "default_edition": attrs.option(attrs.string(), default = None),
        # Selected for the target platform. Buck2 here builds only for the
        # host it runs on, so this is also the execution platform's suffix.
        "executable_suffix": attrs.string(),
        "rustc_target_triple": attrs.string(),
        # The sysroot, including the standard library, is configured once
        # for the execution platform rather than for every target
        # configuration (each build script has its own). It therefore holds
        # only the standard library of the host, which is also the target.
        "sysroot": attrs.exec_dep(),
    },
    is_toolchain_rule = True,
)
