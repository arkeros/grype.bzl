"""Grype vulnerability scanning rules."""

# Transition to build inputs for Linux (OCI images require Linux)
def _linux_transition_impl(settings, attr):
    # Get current platform and determine CPU
    current_platform = settings["//command_line_option:platforms"]

    # Default to arm64 on Apple Silicon, amd64 otherwise
    # Check if current platform contains arm64/aarch64
    platform_str = str(current_platform)
    if "arm64" in platform_str or "aarch64" in platform_str:
        linux_platform = str(Label("@grype.bzl//grype:linux_arm64"))
    else:
        linux_platform = str(Label("@grype.bzl//grype:linux_amd64"))

    return {
        "//command_line_option:platforms": linux_platform,
    }

_linux_transition = transition(
    implementation = _linux_transition_impl,
    inputs = ["//command_line_option:platforms"],
    outputs = ["//command_line_option:platforms"],
)

SUPPORTED_FORMATS = [
    "json",
    "table",
    "cyclonedx-json",
    "cyclonedx-xml",
    "sarif",
]

# File extensions for each format
_FORMAT_EXTENSIONS = {
    "json": "grype.json",
    "table": "grype.txt",
    "cyclonedx-json": "cdx.json",
    "cyclonedx-xml": "cdx.xml",
    "sarif": "sarif.json",
}

# ---------- Shared helpers ----------

def _get_grype_binary(ctx):
    """Get grype binary from explicit attr or toolchain."""
    if hasattr(ctx.attr, "grype") and ctx.attr.grype:
        return ctx.executable.grype
    toolchain_info = ctx.toolchains["@grype.bzl//grype:toolchain"]
    if not toolchain_info:
        return None
    return toolchain_info.grype_info.grype_binary

def _db_setup_commands(database_files):
    """Generate shell commands for database setup.

    Args:
        database_files: List of Files from the database target, or empty list.

    Returns:
        Tuple of (shell_commands_string, list_of_input_files).
    """
    db_dir = None
    for f in database_files:
        if f.is_directory:
            db_dir = f
            break

    if db_dir:
        return ("""
# Create directory structure grype expects: cache_dir/6/
GRYPE_CACHE_DIR=$(mktemp -d)
mkdir -p "$GRYPE_CACHE_DIR/6"
ln -s "$PWD/{db_dir}"/* "$GRYPE_CACHE_DIR/6/"
export GRYPE_DB_CACHE_DIR="$GRYPE_CACHE_DIR"
export GRYPE_DB_AUTO_UPDATE=false
""".format(db_dir = db_dir.path), [db_dir])

    return ("""
export GRYPE_DB_CACHE_DIR=$(mktemp -d)
""", [])

# ---------- Rule: grype_scan ----------

def _grype_scan_impl(ctx):
    """Run grype vulnerability scan."""
    output = ctx.outputs.report

    grype = _get_grype_binary(ctx)
    if grype == None:
        fail("No grype toolchain found. Either set the 'grype' attribute or register the grype toolchain.")

    # Determine input source: SBOM file or OCI image tarball
    if ctx.attr.sbom:
        input_file = ctx.file.sbom
        input_arg = 'sbom:"$PWD/{}"'.format(input_file.path)
        inputs = [input_file]
    elif ctx.attr.image:
        # Support both rules_img (oci_tarball) and rules_oci (tarball)
        tarball = None
        if OutputGroupInfo in ctx.attr.image:
            output_group_info = ctx.attr.image[OutputGroupInfo]
            if hasattr(output_group_info, "oci_tarball"):
                tarball = output_group_info.oci_tarball.to_list()[0]
            elif hasattr(output_group_info, "tarball"):
                tarball = output_group_info.tarball.to_list()[0]

        if tarball == None:
            fail("image must have an 'oci_tarball' (rules_img) or 'tarball' (rules_oci) output group")

        input_file = tarball
        input_arg = 'docker-archive:"$PWD/{}"'.format(tarball.path)
        inputs = [tarball]
    else:
        fail("Either 'sbom' or 'image' must be specified")

    format = ctx.attr.format

    # Build fail-on flag if specified
    fail_on_flag = ""
    if ctx.attr.fail_on:
        fail_on_flag = "--fail-on " + ctx.attr.fail_on

    # Handle database setup
    db_commands, db_inputs = _db_setup_commands(ctx.files.database if ctx.attr.database else [])
    inputs.extend(db_inputs)

    ctx.actions.run_shell(
        inputs = inputs,
        outputs = [output],
        tools = [grype],
        command = """
set -euo pipefail
export GRYPE_CHECK_FOR_APP_UPDATE=false
{db_setup}
{grype} {input} -o {format} --file {output} {fail_on_flag}
""".format(
            db_setup = db_commands,
            grype = grype.path,
            input = input_arg,
            format = format,
            output = output.path,
            fail_on_flag = fail_on_flag,
        ),
        mnemonic = "GrypeScan",
        progress_message = "Scanning for vulnerabilities (%s) for %s" % (format, ctx.label),
    )

    return [DefaultInfo(files = depset([output]))]

def _report_output(name, format):
    """Generate output filename based on format."""
    ext = _FORMAT_EXTENSIONS.get(format, "json")
    return {
        "report": "%s.%s" % (name, ext),
    }

grype_scan = rule(
    implementation = _grype_scan_impl,
    attrs = {
        "image": attr.label(
            cfg = _linux_transition,
            doc = "OCI image target with an 'oci_tarball' (rules_img) or 'tarball' (rules_oci) output group. Mutually exclusive with 'sbom'.",
        ),
        "sbom": attr.label(
            allow_single_file = [".json", ".spdx.json", ".cdx.json"],
            doc = "SBOM file to scan for vulnerabilities. Mutually exclusive with 'image'.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "format": attr.string(
            default = "json",
            values = SUPPORTED_FORMATS,
            doc = "Output format for the vulnerability report. One of: " + ", ".join(SUPPORTED_FORMATS),
        ),
        "grype": attr.label(
            executable = True,
            cfg = "exec",
            doc = "Optional: custom grype binary. If not set, uses toolchain.",
        ),
        "fail_on": attr.string(
            values = ["", "negligible", "low", "medium", "high", "critical"],
            doc = "Fail the build if vulnerabilities are found at or above this severity level.",
        ),
        "database": attr.label(
            doc = "Grype vulnerability database. If not set, grype will download the latest database.",
        ),
    },
    outputs = _report_output,
    toolchains = [
        config_common.toolchain_type("@grype.bzl//grype:toolchain", mandatory = False),
    ],
    doc = """Scan for vulnerabilities using Grype.

This rule scans an OCI container image or SBOM file for vulnerabilities
using [Grype](https://github.com/anchore/grype).

Example (scan SBOM):
    ```starlark
    load("@grype.bzl", "grype_scan")

    grype_scan(
        name = "vuln_report",
        sbom = ":my_sbom",
        format = "json",
    )
    ```

Example (scan image directly):
    ```starlark
    grype_scan(
        name = "vuln_report",
        image = ":my_oci_image",
        fail_on = "high",
    )
    ```
""",
)

_JQ_TOOLCHAIN_TYPE = "@jq.bzl//jq/toolchain:type"

# ---------- Rule & Macro: grype_test ----------

_JQ_FILTER_TEMPLATE = """
[.matches[]? | select(.vulnerability.severity | ascii_downcase | IN({severities})) | select(.vulnerability.id | IN({ignore_cves}) | not) | {{id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions[0]}}] | unique_by(.id + .package)
"""

_JQ_FILTER_NO_IGNORE_TEMPLATE = """
[.matches[]? | select(.vulnerability.severity | ascii_downcase | IN({severities})) | {{id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions[0]}}] | unique_by(.id + .package)
"""

_JQ_STALE_IGNORES_FILTER_TEMPLATE = """
[{ignore_cves}] - [.matches[]?.vulnerability.id] | unique
"""

def _severity_list(fail_on):
    """Return comma-separated list of severities at or above threshold."""
    levels = ["negligible", "low", "medium", "high", "critical"]
    idx = levels.index(fail_on)
    return ", ".join(['"%s"' % s for s in levels[idx:]])

def _grype_test_impl(ctx):
    jq_bin = ctx.toolchains[_JQ_TOOLCHAIN_TYPE].jqinfo.bin
    scan = ctx.file.scan_result
    jq_filter = ctx.attr.jq_filter
    pass_msg = ctx.attr.pass_msg
    fail_msg = ctx.attr.fail_msg

    runner = ctx.actions.declare_file("{}_runner.sh".format(ctx.label.name))
    ctx.actions.write(
        output = runner,
        content = """#!/bin/sh
exec {jq} '{filter} | if length == 0 then "PASS: {pass_msg}" | halt_error(0) else "FAIL: {fail_msg} \\(.)" | halt_error(1) end' {scan}
""".format(
            jq = jq_bin.short_path,
            filter = jq_filter.strip(),
            scan = scan.short_path,
            pass_msg = pass_msg,
            fail_msg = fail_msg,
        ),
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = [scan, jq_bin])
    return [DefaultInfo(
        executable = runner,
        runfiles = runfiles,
    )]

_grype_test = rule(
    implementation = _grype_test_impl,
    test = True,
    attrs = {
        "scan_result": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "jq_filter": attr.string(mandatory = True),
        "pass_msg": attr.string(mandatory = True),
        "fail_msg": attr.string(mandatory = True),
    },
    toolchains = [
        config_common.toolchain_type(_JQ_TOOLCHAIN_TYPE, mandatory = True),
    ],
)

def grype_test(name, scan_result, fail_on_severity = "critical", ignore_cves = None, fail_on_stale_ignores = True, **kwargs):
    """Test macro that checks grype scan result against severity threshold.

    This creates a test target that fails if vulnerabilities at or above the
    specified severity level are found in the grype scan result.

    When `ignore_cves` is provided and `fail_on_stale_ignores` is True (default),
    an additional test target `{name}_stale_ignores` is created that fails if any
    ignored CVE is no longer present in the scan results, indicating the ignore
    entry is stale and should be removed.

    Example:
        ```starlark
        load("@grype.bzl", "grype_scan", "grype_test")

        grype_scan(
            name = "vuln_report",
            sbom = ":my_sbom",
        )

        grype_test(
            name = "vuln_check",
            scan_result = ":vuln_report",
            fail_on_severity = "high",
            ignore_cves = ["CVE-2024-1234"],
        )
        ```

    Args:
        name: Name of the test target
        scan_result: Label of grype_scan output JSON file
        fail_on_severity: Minimum severity level to fail on
        ignore_cves: List of CVE IDs to ignore
        fail_on_stale_ignores: If True (default), create a sibling test that fails when
            ignored CVEs are no longer found in the scan results
        **kwargs: Additional arguments passed to the test rule
    """
    cve_list = ", ".join(['"%s"' % cve for cve in ignore_cves]) if ignore_cves else None

    if cve_list:
        jq_filter = _JQ_FILTER_TEMPLATE.format(
            severities = _severity_list(fail_on_severity),
            ignore_cves = cve_list,
        )
    else:
        jq_filter = _JQ_FILTER_NO_IGNORE_TEMPLATE.format(
            severities = _severity_list(fail_on_severity),
        )

    _grype_test(
        name = name,
        scan_result = scan_result,
        jq_filter = jq_filter,
        pass_msg = "No vulnerabilities at or above %s severity" % fail_on_severity,
        fail_msg = "Found vulnerabilities at or above %s severity:" % fail_on_severity,
        **kwargs
    )

    if cve_list and fail_on_stale_ignores:
        _grype_test(
            name = name + "_stale_ignores",
            scan_result = scan_result,
            jq_filter = _JQ_STALE_IGNORES_FILTER_TEMPLATE.format(ignore_cves = cve_list),
            pass_msg = "All ignored CVEs are still present in scan results",
            fail_msg = "Ignored CVEs not found in scan (stale ignores — remove them):",
            **kwargs
        )
