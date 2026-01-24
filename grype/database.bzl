"""Grype vulnerability database management rules."""

def _grype_database_archive_impl(repository_ctx):
    """Download grype database archive."""
    repository_ctx.download(
        url = repository_ctx.attr.url,
        sha256 = repository_ctx.attr.sha256,
        output = "vulnerability-db.tar.zst",
    )

    repository_ctx.file("BUILD.bazel", """
load("@grype.bzl//grype:database.bzl", "grype_db_import")

exports_files(["vulnerability-db.tar.zst"])

grype_db_import(
    name = "grype_database",
    tarball = "vulnerability-db.tar.zst",
    visibility = ["//visibility:public"],
)

alias(
    name = "db",
    actual = ":grype_database",
    visibility = ["//visibility:public"],
)
""")

grype_database_archive = repository_rule(
    implementation = _grype_database_archive_impl,
    attrs = {
        "url": attr.string(
            mandatory = True,
            doc = "URL of the grype database tarball",
        ),
        "sha256": attr.string(
            mandatory = True,
            doc = "SHA256 checksum of the tarball",
        ),
    },
    doc = "Downloads a grype vulnerability database archive.",
)

def _grype_db_import_impl(ctx):
    """Import grype database at build time to create indexes."""
    tarball = ctx.file.tarball

    # Get grype binary from explicit attr or toolchain
    if ctx.attr.grype:
        grype = ctx.executable.grype
    else:
        toolchain_info = ctx.toolchains["@grype.bzl//grype:toolchain"]
        if not toolchain_info:
            fail("No grype toolchain found. Either set the 'grype' attribute or register the grype toolchain.")
        grype = toolchain_info.grype_info.grype_binary

    # Output directory for imported database
    db_dir = ctx.actions.declare_directory(ctx.attr.name)

    ctx.actions.run_shell(
        inputs = [tarball],
        outputs = [db_dir],
        tools = [grype],
        command = """
set -euo pipefail

# Set up XDG_CACHE_HOME for grype import
export XDG_CACHE_HOME="$PWD/grype_cache"
mkdir -p "$XDG_CACHE_HOME"

# Import the database (this builds indexes)
{grype} db import {tarball}

# Copy the imported database to output directory
mkdir -p {output}
cp -r "$XDG_CACHE_HOME/grype/db/6"/* {output}/
""".format(
            grype = grype.path,
            tarball = tarball.path,
            output = db_dir.path,
        ),
        mnemonic = "GrypeDbImport",
        progress_message = "Importing grype database for %s" % ctx.label,
    )

    return [DefaultInfo(files = depset([db_dir]))]

grype_db_import = rule(
    implementation = _grype_db_import_impl,
    attrs = {
        "tarball": attr.label(
            allow_single_file = [".tar.zst"],
            mandatory = True,
            doc = "Grype database tarball (.tar.zst)",
        ),
        "grype": attr.label(
            executable = True,
            cfg = "exec",
            doc = "Optional: custom grype binary. If not set, uses toolchain.",
        ),
    },
    toolchains = [
        config_common.toolchain_type("@grype.bzl//grype:toolchain", mandatory = False),
    ],
    doc = "Imports grype database with indexes using grype binary.",
)
