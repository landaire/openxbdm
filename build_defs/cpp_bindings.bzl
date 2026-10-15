"""C++ headers of a diplomat FFI crate."""

def _cpp_bindings_impl(ctx: AnalysisContext) -> list[Provider]:
    headers = ctx.actions.declare_output(ctx.label.name, dir = True)
    ctx.actions.run(
        cmd_args(
            ctx.attrs.generator[RunInfo],
            cmd_args(ctx.attrs.crate_sources[DefaultInfo].default_outputs[0], format = "{}/" + ctx.attrs.crate_root),
            headers.as_output(),
        ),
        category = "cpp_bindings",
    )
    return [DefaultInfo(default_output = headers)]

cpp_bindings = rule(
    impl = _cpp_bindings_impl,
    attrs = {
        # The crate root, relative to `crate_sources`.
        "crate_root": attrs.string(default = "src/lib.rs"),
        # The `[sources]` subtarget of the FFI crate's rust_library.
        "crate_sources": attrs.dep(),
        "generator": attrs.exec_dep(providers = [RunInfo]),
    },
)
