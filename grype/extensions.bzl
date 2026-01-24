"""Module extension for grype toolchains and database."""

load(":database.bzl", "grype_database_archive")
load(":versions.bzl", "DEFAULT_VERSION", "GRYPE_VERSIONS", "get_grype_url")

_PLATFORM_CONSTRAINTS = {
    "darwin_amd64": ["@platforms//os:macos", "@platforms//cpu:x86_64"],
    "darwin_arm64": ["@platforms//os:macos", "@platforms//cpu:arm64"],
    "linux_amd64": ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    "linux_arm64": ["@platforms//os:linux", "@platforms//cpu:arm64"],
    "windows_amd64": ["@platforms//os:windows", "@platforms//cpu:x86_64"],
}

def _detect_platform(rctx):
    """Detects the current platform."""
    os = rctx.os.name.lower()
    arch = rctx.os.arch

    if "mac" in os or "darwin" in os:
        platform_os = "darwin"
    elif "linux" in os:
        platform_os = "linux"
    elif "windows" in os:
        platform_os = "windows"
    else:
        fail("Unsupported OS: " + os)

    if arch in ("aarch64", "arm64"):
        platform_arch = "arm64"
    elif arch in ("x86_64", "amd64"):
        platform_arch = "amd64"
    else:
        fail("Unsupported arch: " + arch)

    return platform_os + "_" + platform_arch

def _grype_repo_impl(rctx):
    version = rctx.attr.version
    platform = _detect_platform(rctx)
    key = version + "-" + platform

    if key not in GRYPE_VERSIONS:
        fail("Grype {} not available for {}. Available: {}".format(
            version,
            platform,
            [k for k in GRYPE_VERSIONS.keys() if k.startswith(version)],
        ))

    filename, sha256 = GRYPE_VERSIONS[key]
    url = get_grype_url(version, filename)

    rctx.download_and_extract(
        url = url,
        sha256 = sha256,
    )

    constraints = _PLATFORM_CONSTRAINTS[platform]

    # Determine executable name (grype.exe on Windows, grype otherwise)
    exe_name = "grype.exe" if "windows" in platform else "grype"

    rctx.file("BUILD.bazel", """
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@grype.bzl//grype/toolchain:toolchain.bzl", "grype_toolchain")

# Wrap the binary as a sh_binary so it can be used as an executable
sh_binary(
    name = "grype_bin",
    srcs = ["{exe_name}"],
    visibility = ["//visibility:public"],
)

grype_toolchain(
    name = "toolchain",
    grype = ":grype_bin",
    visibility = ["//visibility:public"],
)

toolchain(
    name = "grype_toolchain",
    toolchain = ":toolchain",
    toolchain_type = "@grype.bzl//grype:toolchain",
    exec_compatible_with = {constraints},
)
""".format(constraints = constraints, exe_name = exe_name))

_grype_repo = repository_rule(
    implementation = _grype_repo_impl,
    attrs = {
        "version": attr.string(mandatory = True),
    },
)

def _grype_extension_impl(mctx):
    version = DEFAULT_VERSION
    for mod in mctx.modules:
        for toolchain in mod.tags.toolchain:
            if toolchain.version:
                version = toolchain.version

    _grype_repo(name = "grype_toolchains", version = version)

grype = module_extension(
    implementation = _grype_extension_impl,
    tag_classes = {
        "toolchain": tag_class(attrs = {
            "version": attr.string(
                doc = "Grype version to use. Defaults to " + DEFAULT_VERSION,
            ),
        }),
    },
)

# Database extension
def _grype_database_extension_impl(mctx):
    for mod in mctx.modules:
        for db in mod.tags.database:
            grype_database_archive(
                name = db.name,
                url = db.url,
                sha256 = db.sha256,
            )

grype_database = module_extension(
    implementation = _grype_database_extension_impl,
    tag_classes = {
        "database": tag_class(attrs = {
            "name": attr.string(
                mandatory = True,
                doc = "Repository name for the database",
            ),
            "url": attr.string(
                mandatory = True,
                doc = "URL of the grype database tarball",
            ),
            "sha256": attr.string(
                mandatory = True,
                doc = "SHA256 checksum of the tarball",
            ),
        }),
    },
)
