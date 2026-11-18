"""An execution platform that consults a remote action cache.

Actions still run locally. With `remote_cache_enabled`, Buck2 first looks
up each action's digest in the cache that [buck2_re_client] names, and
uploads the result after running it. CI points that section either at the
shared cache of landaire/build-cache or at a local bazel-remote server
whose storage persists between runs (see ci/start-action-cache.sh);
without it, builds use the prelude's local-only platform.

Action keys cover each command and its declared inputs, not the compiler
driver, linker and SDK that commands find on PATH. `host_tools` names
those, and goes into every action key as a platform property, so a cache
shared between runner images does not return results built with other
tools.
"""

def _cached_execution_platform_impl(ctx: AnalysisContext) -> list[Provider]:
    constraints = dict()
    constraints.update(ctx.attrs.cpu_configuration[ConfigurationInfo].constraints)
    constraints.update(ctx.attrs.os_configuration[ConfigurationInfo].constraints)
    for value in ctx.attrs.constraint_values:
        info = value[ConstraintValueInfo]
        constraints[info.setting.label] = info
    configuration = ConfigurationInfo(constraints = constraints, values = {})

    platform = ExecutionPlatformInfo(
        label = ctx.label.raw_target(),
        configuration = configuration,
        executor_config = CommandExecutorConfig(
            local_enabled = True,
            # Without remote execution Buck2 runs every action locally and
            # consults only the action cache. Remote execution would select
            # the hybrid executor, which prepares every action for the
            # remote side and uses far more daemon memory.
            remote_enabled = False,
            remote_cache_enabled = True,
            allow_cache_uploads = True,
            use_windows_path_separators = ctx.attrs.use_windows_path_separators,
            remote_execution_properties = (
                {"host-tools": ctx.attrs.host_tools} if ctx.attrs.host_tools else None
            ),
        ),
    )
    return [
        DefaultInfo(),
        platform,
        PlatformInfo(label = str(ctx.label.raw_target()), configuration = configuration),
        ExecutionPlatformRegistrationInfo(platforms = [platform]),
    ]

cached_execution_platform = rule(
    impl = _cached_execution_platform_impl,
    attrs = {
        "constraint_values": attrs.list(attrs.dep(providers = [ConstraintValueInfo])),
        "cpu_configuration": attrs.dep(providers = [ConfigurationInfo]),
        "host_tools": attrs.option(attrs.string(), default = None),
        "os_configuration": attrs.dep(providers = [ConfigurationInfo]),
        "use_windows_path_separators": attrs.bool(default = False),
    },
)
