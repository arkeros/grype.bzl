"""Grype vulnerability scanning rules."""

load("@jq.bzl", "jq")
load("@rules_shell//shell:sh_test.bzl", "sh_test")

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

def _grype_scan_impl(ctx):
    """Run grype vulnerability scan."""
    output = ctx.outputs.report

    # Get grype binary from explicit attr or toolchain
    if ctx.attr.grype:
        grype = ctx.executable.grype
    else:
        toolchain_info = ctx.toolchains["@grype.bzl//grype:toolchain"]
        if not toolchain_info:
            fail("No grype toolchain found. Either set the 'grype' attribute or register the grype toolchain.")
        grype = toolchain_info.grype_info.grype_binary

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
    db_setup = ""
    if ctx.attr.database:
        # Find the database directory from the database target
        db_dir = None
        for f in ctx.files.database:
            if f.is_directory:
                db_dir = f
                break

        if db_dir:
            inputs.append(db_dir)
            db_setup = """
# Create directory structure grype expects: cache_dir/6/
GRYPE_CACHE_DIR=$(mktemp -d)
mkdir -p "$GRYPE_CACHE_DIR/6"
ln -s "$PWD/{db_dir}"/* "$GRYPE_CACHE_DIR/6/"
export GRYPE_DB_CACHE_DIR="$GRYPE_CACHE_DIR"
export GRYPE_DB_AUTO_UPDATE=false
""".format(db_dir = db_dir.path)
        else:
            db_setup = """
export GRYPE_DB_CACHE_DIR=$(mktemp -d)
"""
    else:
        db_setup = """
export GRYPE_DB_CACHE_DIR=$(mktemp -d)
"""

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
            db_setup = db_setup,
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
            cfg = _linux_transition,
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

# jq filter to extract vulnerabilities at or above a severity threshold
# Returns JSON array with CVE id, severity, package name/version, and fix info
# Supports optional CVE ignore list
_JQ_FILTER_TEMPLATE = """
[.matches[]? | select(.vulnerability.severity | ascii_downcase | IN({severities})) | select(.vulnerability.id | IN({ignore_cves}) | not) | {{id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions[0]}}] | unique_by(.id + .package)
"""

_JQ_FILTER_NO_IGNORE_TEMPLATE = """
[.matches[]? | select(.vulnerability.severity | ascii_downcase | IN({severities})) | {{id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions[0]}}] | unique_by(.id + .package)
"""

def _severity_list(fail_on):
    """Return comma-separated list of severities at or above threshold."""
    levels = ["negligible", "low", "medium", "high", "critical"]
    idx = levels.index(fail_on)
    return ", ".join(['"%s"' % s for s in levels[idx:]])

def grype_test(name, scan_result, fail_on_severity = "critical", ignore_cves = None, **kwargs):
    """Test macro that checks grype scan result against severity threshold.

    This creates a test target that fails if vulnerabilities at or above the
    specified severity level are found in the grype scan result.

    Unlike `grype_scan` with `fail_on`, this creates a proper test target that:
    - Can be run separately from builds with `bazel test`
    - Can have test tags like `manual` or `external`
    - Integrates with CI test reporters
    - Supports ignoring specific CVEs

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
            ignore_cves = ["CVE-2024-1234"],  # Known false positive
        )
        ```

    Args:
        name: Name of the test target
        scan_result: Label of grype_scan output JSON file
        fail_on_severity: Minimum severity level to fail on (negligible, low, medium, high, critical)
        ignore_cves: List of CVE IDs to ignore (e.g., ["CVE-2024-1234"])
        **kwargs: Additional arguments passed to native.sh_test
    """

    # Use jq to filter vulnerabilities at or above threshold
    jq_name = name + "_violations"

    if ignore_cves:
        # Format CVE list for jq IN() function
        cve_list = ", ".join(['"%s"' % cve for cve in ignore_cves])
        jq_filter = _JQ_FILTER_TEMPLATE.format(
            severities = _severity_list(fail_on_severity),
            ignore_cves = cve_list,
        )
    else:
        jq_filter = _JQ_FILTER_NO_IGNORE_TEMPLATE.format(
            severities = _severity_list(fail_on_severity),
        )

    jq(
        name = jq_name,
        srcs = [scan_result],
        filter = jq_filter,
    )

    # Simple test that fails if any violations found
    sh_test(
        name = name,
        srcs = ["@grype.bzl//grype:grype_check.sh"],
        data = [":" + jq_name],
        args = ["$(location :" + jq_name + ")", fail_on_severity],
        **kwargs
    )
