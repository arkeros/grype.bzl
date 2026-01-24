"""Grype toolchain definitions."""

GrypeInfo = provider(
    doc = "Information about the grype binary",
    fields = {
        "grype_binary": "The grype executable File",
    },
)

def _grype_toolchain_impl(ctx):
    return [
        platform_common.ToolchainInfo(
            grype_info = GrypeInfo(
                grype_binary = ctx.executable.grype,
            ),
        ),
    ]

grype_toolchain = rule(
    implementation = _grype_toolchain_impl,
    attrs = {
        "grype": attr.label(
            mandatory = True,
            executable = True,
            cfg = "exec",
            doc = "The grype executable",
        ),
    },
    doc = "Defines a grype toolchain.",
)
