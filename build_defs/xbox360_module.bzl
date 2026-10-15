"""Xbox 360 executables and the console module built from one.

`xbox360_executable` compiles a binary crate for the console with the
toolchain of the xbox360 cell. The toolchain's console flags make it one
LTO code generation unit (toolchains/BUCK), and rustc writes that unit as
assembly along with the image it links. The prelude's `rust_binary` has
no such output: its `[asm]` subtarget compiles without linking, which
skips LTO.

`xbox360_module` turns that assembly into a XEX. With `rewrite`,
`openxbdm-asm-rewrite` replaces the callee-saved register saves and
restores in prologues and epilogues with calls to shared helper routines,
and an audit of the linked image's disassembly fails the build if a
rewritable sequence remains. rustc assembles the result with the
integrated assembler of its LLVM, rust-lld links it with the code that
LTO leaves out (compiler_builtins), and xex-link converts the image. The
link mirrors the one rustc runs; the build fails if the mirror, applied
to the object rustc linked, does not give rustc's image. In every case the
build fails if the image holds a reservation that the kernel loader
reports as unprotected.
"""

load("@prelude//decls:toolchains_common.bzl", "toolchains_common")
load("@prelude//linking:link_info.bzl", "LinkStrategy")
load("@prelude//python_bootstrap:python_bootstrap.bzl", "PythonBootstrapToolchainInfo")
load("@prelude//rust:build_params.bzl", "MetadataKind")
load("@prelude//rust:link_info.bzl", "RustLinkInfo")
load("@prelude//rust:rust_toolchain.bzl", "RustToolchainInfo")
load("@xbox360//buck:platforms.bzl", "xbox360_core_transition")

Xbox360ExecutableInfo = provider(fields = {
    # The LTO code generation unit as assembly.
    "assembly": provider_field(Artifact),
    # The rlib of compiler_builtins, which LTO leaves out.
    "compiler_builtins": provider_field(Artifact),
    # The image rustc linked.
    "image": provider_field(Artifact),
    "link_script": provider_field(Artifact),
    # The LTO code generation unit as the object rustc linked.
    "object": provider_field(Artifact),
})

def _rlib(dep: Dependency) -> Artifact:
    # Executables for the console link statically (no position-independent
    # code), as with the target specification's relocation model. The
    # `link` rlibs hold the code; `full` ones only metadata.
    return dep[RustLinkInfo].strategies[LinkStrategy("static")].outputs[MetadataKind("link")]

def _dependency_dirs(dep: Dependency) -> cmd_args:
    """`-Ldependency` for the directory of each of `dep`'s transitive rlibs."""
    transitive = dep[RustLinkInfo].strategies[LinkStrategy("static")].transitive_deps[MetadataKind("link")]
    return cmd_args(transitive.project_as_args("artifacts_args"), format = "-Ldependency={}", parent = 1)

def _extern(dep: Dependency, options: str = "") -> cmd_args:
    crate = dep[RustLinkInfo].crate.simple
    return cmd_args(_rlib(dep), format = "--extern=" + options + crate + "={}")

def _xbox360_executable_impl(ctx: AnalysisContext) -> list[Provider]:
    toolchain = ctx.attrs._rust_toolchain[RustToolchainInfo]
    sysroot = toolchain.explicit_sysroot_deps
    sysroot_crates = [sysroot.core] + sysroot.others
    compiler_builtins = [dep for dep in sysroot.others if dep[RustLinkInfo].crate.simple == "compiler_builtins"]
    len(compiler_builtins) == 1 or fail("the toolchain provides no compiler_builtins")

    srcs = ctx.actions.symlinked_dir("srcs", {src.short_path: src for src in ctx.attrs.srcs})
    empty_sysroot = ctx.actions.symlinked_dir("sysroot", {})
    assembly = ctx.actions.declare_output("{}.s".format(ctx.attrs.crate))
    obj = ctx.actions.declare_output("{}.o".format(ctx.attrs.crate))
    image = ctx.actions.declare_output(ctx.attrs.crate)

    ctx.actions.run(
        cmd_args(
            toolchain.compiler,
            cmd_args(srcs, format = "{}/" + ctx.attrs.crate_root),
            "--crate-name=" + ctx.attrs.crate,
            "--crate-type=bin",
            "--edition=" + ctx.attrs.edition,
            "--target=" + toolchain.rustc_target_triple,
            # Only the crates passed with --extern.
            cmd_args(empty_sysroot, format = "--sysroot={}"),
            ['--cfg=feature="{}"'.format(feature) for feature in ctx.attrs.features],
            [_extern(dep) for dep in ctx.attrs.deps],
            [_extern(dep, "noprelude,nounused:") for dep in sysroot_crates],
            [_dependency_dirs(dep) for dep in ctx.attrs.deps + sysroot_crates],
            cmd_args(srcs, format = "--remap-path-prefix={}/=" + ctx.label.package + "/"),
            cmd_args(ctx.attrs._rust_lld[RunInfo], format = "-Clinker={}"),
            cmd_args(ctx.attrs.link_script, format = "-Clink-arg=-T{}"),
            "-Clink-arg=--no-rosegment",
            "-Cstrip=symbols",
            toolchain.rustc_flags,
            toolchain.rustc_binary_flags,
            cmd_args("--emit=asm=", assembly.as_output(), ",obj=", obj.as_output(), ",link", delimiter = ""),
            "-o",
            image.as_output(),
        ),
        env = ctx.attrs.env | {
            "CARGO_MANIFEST_DIR": srcs,
            # The toolchain's console flags include unstable options.
            "RUSTC_BOOTSTRAP": "1",
            "RUST_TARGET_PATH": toolchain.rust_target_path[DefaultInfo].default_outputs[0],
        },
        category = "rustc",
    )

    return [
        DefaultInfo(default_output = image, sub_targets = {
            "asm": [DefaultInfo(default_output = assembly)],
            "obj": [DefaultInfo(default_output = obj)],
        }),
        Xbox360ExecutableInfo(
            assembly = assembly,
            compiler_builtins = _rlib(compiler_builtins[0]),
            image = image,
            link_script = ctx.attrs.link_script,
            object = obj,
        ),
    ]

# A binary crate for the console with core, alloc and compiler_builtins.
# The rule configures itself for the console, so host builds include it.
xbox360_executable = rule(
    impl = _xbox360_executable_impl,
    cfg = xbox360_core_transition,
    attrs = {
        "crate": attrs.string(),
        "crate_root": attrs.string(),
        "deps": attrs.list(attrs.dep(providers = [RustLinkInfo]), default = []),
        "edition": attrs.string(),
        "env": attrs.dict(attrs.string(), attrs.string(), default = {}),
        "features": attrs.list(attrs.string(), default = []),
        "labels": attrs.list(attrs.string(), default = []),
        # GNU ld script that places the sections.
        "link_script": attrs.source(),
        "srcs": attrs.list(attrs.source(), default = []),
        "_rust_lld": attrs.exec_dep(providers = [RunInfo], default = "toolchains//:rust-lld"),
        "_rust_toolchain": toolchains_common.rust(),
    },
)

# Assembles `module.s` with rustc: module-level assembly passes through
# LLVM's assembly parser, as with llvm-mc, for the target specification's
# CPU and features. The crate has no other items, so the object holds only
# the assembly.
_ASSEMBLER_CRATE = """\
#![feature(no_core, rustc_attrs, decl_macro)]
#![allow(internal_features)]
#![no_core]

#[rustc_builtin_macro]
macro global_asm($($arguments:tt)*) {}

#[rustc_builtin_macro]
macro include_str($($arguments:tt)*) {}

global_asm!(include_str!("module.s"), options(raw));
"""

def _write_stdout(ctx: AnalysisContext, output: Artifact, command: cmd_args, category: str):
    ctx.actions.run(
        cmd_args(
            ctx.attrs._python_bootstrap_toolchain[PythonBootstrapToolchainInfo].interpreter,
            ctx.attrs._write_stdout,
            output.as_output(),
            command,
        ),
        category = category,
    )

def _assemble(ctx: AnalysisContext, assembly: Artifact) -> Artifact:
    toolchain = ctx.attrs._rust_toolchain[RustToolchainInfo]
    crate = ctx.actions.symlinked_dir("assembler", {
        "module.rs": ctx.actions.write("assembler.rs", _ASSEMBLER_CRATE),
        "module.s": assembly,
    })
    obj = ctx.actions.declare_output("module.o")
    ctx.actions.run(
        cmd_args(
            toolchain.compiler,
            cmd_args(crate, format = "{}/module.rs"),
            "--crate-name=module",
            "--crate-type=lib",
            "--edition=2024",
            "--target=" + toolchain.rustc_target_triple,
            # Custom target specifications are unstable.
            "-Zunstable-options",
            "--emit=obj",
            # rustc writes its intermediate files next to the output, which
            # is private to this action, rather than in the working directory.
            "-o",
            obj.as_output(),
        ),
        env = {
            "RUSTC_BOOTSTRAP": "1",
            "RUST_TARGET_PATH": toolchain.rust_target_path[DefaultInfo].default_outputs[0],
        },
        category = "assemble",
    )
    return obj

def _link(ctx: AnalysisContext, executable: Xbox360ExecutableInfo, obj: Artifact, name: str, strip: bool) -> Artifact:
    image = ctx.actions.declare_output(name)

    # The command rustc runs to link the executable (`xbox360_executable`),
    # with `obj` as its code generation unit. `_check_link` confirms that
    # it is.
    ctx.actions.run(
        cmd_args(
            ctx.attrs._rust_lld[RunInfo],
            "-flavor",
            "gnu",
            obj,
            "--as-needed",
            "-Bstatic",
            executable.compiler_builtins,
            "-Bdynamic",
            "-z",
            "noexecstack",
            "-o",
            image.as_output(),
            "--gc-sections",
            ["--strip-all"] if strip else [],
            cmd_args(executable.link_script, format = "-T{}"),
            "--no-rosegment",
        ),
        category = "link",
        identifier = name,
    )
    return image

def _check_link(ctx: AnalysisContext, executable: Xbox360ExecutableInfo) -> Artifact:
    """Links the object rustc linked as `_link` does, and compares the images."""
    image = _link(ctx, executable, executable.object, "rustc-image", strip = True)
    result = ctx.actions.declare_output("link-check")
    ctx.actions.run(
        cmd_args(
            ctx.attrs._python_bootstrap_toolchain[PythonBootstrapToolchainInfo].interpreter,
            ctx.attrs._compare_files,
            result.as_output(),
            executable.image,
            image,
        ),
        category = "link_check",
    )
    return result

def _xbox360_module_impl(ctx: AnalysisContext) -> list[Provider]:
    executable = ctx.attrs.executable[Xbox360ExecutableInfo]
    rewrite = ctx.attrs._asm_rewrite[RunInfo]
    assembly = executable.assembly
    sub_targets = {}
    checks = []

    if ctx.attrs.rewrite:
        rewritten = ctx.actions.declare_output("rewritten.s")
        scope = ctx.actions.declare_output("scope")
        refusals = ctx.actions.declare_output("refusals")
        report = ctx.actions.declare_output("rewrite-report")
        _write_stdout(
            ctx,
            report,
            cmd_args(
                rewrite,
                "rewrite",
                assembly,
                rewritten.as_output(),
                "--scope",
                scope.as_output(),
                "--refusals",
                refusals.as_output(),
            ),
            category = "asm_rewrite",
        )
        assembly = rewritten
        sub_targets["refusals"] = [DefaultInfo(default_output = refusals)]
        sub_targets["rewrite-report"] = [DefaultInfo(default_output = report)]

    obj = _assemble(ctx, assembly)
    image = _link(ctx, executable, obj, "image", strip = True)

    if ctx.attrs.rewrite:
        unstripped = _link(ctx, executable, obj, "image.unstripped", strip = False)
        disassembly = ctx.actions.declare_output("disassembly")
        _write_stdout(
            ctx,
            disassembly,
            cmd_args(ctx.attrs._llvm_objdump[RunInfo], "-d", "--no-show-raw-insn", unstripped),
            category = "disassemble",
        )
        audit = ctx.actions.declare_output("audit")
        _write_stdout(
            ctx,
            audit,
            cmd_args(rewrite, "audit", disassembly, "--scope", scope),
            category = "asm_audit",
        )
        checks.append(audit)
        sub_targets["audit"] = [DefaultInfo(default_output = audit)]
        sub_targets["disassembly"] = [DefaultInfo(default_output = disassembly)]
        sub_targets["unstripped"] = [DefaultInfo(default_output = unstripped)]

    reservations = ctx.actions.declare_output("reservations")
    _write_stdout(
        ctx,
        reservations,
        cmd_args(rewrite, "reservations", image),
        category = "reservations",
    )
    checks.append(reservations)
    checks.append(_check_link(ctx, executable))

    xex = ctx.actions.declare_output(ctx.attrs.out)
    ctx.actions.run(
        cmd_args(
            ctx.attrs._xex_link[RunInfo],
            image,
            xex.as_output(),
            "--manifest",
            ctx.attrs.manifest,
            # The XEX exists only if the checks pass.
            hidden = checks,
        ),
        category = "xex_link",
    )

    sub_targets["asm"] = [DefaultInfo(default_output = assembly)]
    sub_targets["elf"] = [DefaultInfo(default_output = image)]
    return [DefaultInfo(default_output = xex, sub_targets = sub_targets)]

xbox360_module = rule(
    impl = _xbox360_module_impl,
    cfg = xbox360_core_transition,
    attrs = {
        "executable": attrs.dep(providers = [Xbox360ExecutableInfo]),
        # xex-link manifest with the XEX metadata.
        "manifest": attrs.source(),
        "out": attrs.string(),
        "rewrite": attrs.bool(default = True),
        "_asm_rewrite": attrs.exec_dep(
            providers = [RunInfo],
            default = "root//crates/openxbdm-asm-rewrite:openxbdm-asm-rewrite-bin",
        ),
        "_compare_files": attrs.source(default = "root//build_defs:compare_files.py"),
        "_llvm_objdump": attrs.exec_dep(providers = [RunInfo], default = "toolchains//:llvm-objdump"),
        "_python_bootstrap_toolchain": toolchains_common.python_bootstrap(),
        "_rust_lld": attrs.exec_dep(providers = [RunInfo], default = "toolchains//:rust-lld"),
        "_rust_toolchain": toolchains_common.rust(),
        "_write_stdout": attrs.source(default = "root//build_defs:write_stdout.py"),
        "_xex_link": attrs.exec_dep(providers = [RunInfo], default = "xbox360//crates/xex-link:xex-link"),
    },
)
