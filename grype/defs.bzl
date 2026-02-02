"""Grype vulnerability scanning rules and aspect."""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@jq.bzl", "jq")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("@syft.bzl//syft:defs.bzl", "SyftSBOMInfo", "syft_sbom_aspect")
load("//grype:cve_policy.bzl", "CvePolicyInfo")

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

GrypeScanInfo = provider(
    doc = "Grype vulnerability scan results, propagated by grype_aspect.",
    fields = {
        "report": "File containing the JSON scan report",
    },
)

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

# ---------- Macro: grype_test ----------

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

# ---------- Aspect: grype_aspect ----------

_JQ_TOOLCHAIN_TYPE = "@jq.bzl//jq/toolchain:type"

def _build_jq_filter(fail_on_severity, ignore_cves):
    """Build jq filter for the aspect validation action."""
    severities = _severity_list(fail_on_severity)
    if ignore_cves:
        cve_list = ", ".join(['"%s"' % cve for cve in ignore_cves])
        return _JQ_FILTER_TEMPLATE.format(
            severities = severities,
            ignore_cves = cve_list,
        )
    return _JQ_FILTER_NO_IGNORE_TEMPLATE.format(severities = severities)

def _grype_aspect_impl(target, ctx):
    """Aspect that scans OCI images for vulnerabilities via grype."""

    # Only process targets that have an SBOM (from syft_sbom_aspect via requires)
    if SyftSBOMInfo not in target:
        return []

    sbom = target[SyftSBOMInfo].sbom

    # Get grype binary from toolchain
    toolchain_info = ctx.toolchains["@grype.bzl//grype:toolchain"]
    if not toolchain_info:
        return []
    grype = toolchain_info.grype_info.grype_binary

    # Read policy from build settings
    fail_on_severity = ctx.attr._fail_on_severity[BuildSettingInfo].value
    ignore_cves_value = ctx.attr._ignore_cves[BuildSettingInfo].value
    ignore_cves = [c for c in ignore_cves_value if c] if ignore_cves_value else []

    # Check for per-target CvePolicyInfo override (via aspect_hints)
    for hint in (ctx.rule.attr.aspect_hints if hasattr(ctx.rule.attr, "aspect_hints") else []):
        if CvePolicyInfo in hint:
            fail_on_severity = hint[CvePolicyInfo].fail_on_severity
            ignore_cves = hint[CvePolicyInfo].ignore_cves
            break

    # Handle database setup
    db_files = ctx.attr._database.files.to_list() if ctx.attr._database else []
    db_commands, db_inputs = _db_setup_commands(db_files)

    # Action 1: Scan → JSON report (always succeeds)
    report = ctx.actions.declare_file("{}.grype.json".format(target.label.name))
    scan_inputs = [sbom] + db_inputs
    ctx.actions.run_shell(
        inputs = scan_inputs,
        outputs = [report],
        tools = [grype],
        command = """
set -euo pipefail
export GRYPE_CHECK_FOR_APP_UPDATE=false
{db_setup}
{grype} sbom:"$PWD/{sbom}" -o json --file {output}
""".format(
            db_setup = db_commands,
            grype = grype.path,
            sbom = sbom.path,
            output = report.path,
        ),
        mnemonic = "GrypeScan",
        progress_message = "Scanning for vulnerabilities for %s" % target.label,
    )

    # Action 2: Filter violations with jq
    jq_bin = ctx.toolchains[_JQ_TOOLCHAIN_TYPE].jqinfo.bin
    jq_filter = _build_jq_filter(fail_on_severity, ignore_cves)
    violations = ctx.actions.declare_file("{}.grype_violations.json".format(target.label.name))
    ctx.actions.run_shell(
        inputs = [report],
        outputs = [violations],
        tools = [jq_bin],
        command = """{jq} '{filter}' {input} > {output}""".format(
            jq = jq_bin.path,
            filter = jq_filter.strip(),
            input = report.path,
            output = violations.path,
        ),
        mnemonic = "GrypeFilter",
        progress_message = "Filtering vulnerabilities for %s" % target.label,
    )

    # Action 3: Validate → marker file (fails if violations found)
    check_sh = ctx.attr._check_sh.files.to_list()[0]
    validation = ctx.actions.declare_file("{}.grype_validation".format(target.label.name))
    ctx.actions.run_shell(
        inputs = [violations, check_sh],
        outputs = [validation],
        command = """
set -euo pipefail
bash {check} "{violations}" "{severity}"
touch {marker}
""".format(
            check = check_sh.path,
            violations = violations.path,
            severity = fail_on_severity,
            marker = validation.path,
        ),
        mnemonic = "GrypeValidate",
        progress_message = "Validating CVE policy for %s" % target.label,
    )

    return [
        GrypeScanInfo(report = report),
        OutputGroupInfo(
            cve_scan = depset([report]),
            _validation = depset([validation]),
        ),
    ]

grype_aspect = aspect(
    implementation = _grype_aspect_impl,
    attr_aspects = [],
    requires = [syft_sbom_aspect],
    attrs = {
        "_fail_on_severity": attr.label(
            default = Label("@grype.bzl//grype:fail_on_severity"),
        ),
        "_ignore_cves": attr.label(
            default = Label("@grype.bzl//grype:ignore_cves"),
        ),
        "_database": attr.label(
            default = Label("@grype.bzl//grype:database"),
        ),
        "_check_sh": attr.label(
            default = Label("@grype.bzl//grype:grype_check.sh"),
            allow_single_file = True,
        ),
    },
    toolchains = [
        config_common.toolchain_type("@grype.bzl//grype:toolchain", mandatory = False),
        config_common.toolchain_type(_JQ_TOOLCHAIN_TYPE, mandatory = False),
    ],
    doc = """Aspect that auto-scans OCI images for vulnerabilities using Grype.

Requires syft_sbom_aspect (automatically chained via `requires`).
No-ops on targets without SyftSBOMInfo.

Wire in .bazelrc:
    build --aspects=@grype.bzl//grype:defs.bzl%grype_aspect

Configuration:
    Global (build settings):
        --@grype.bzl//grype:fail_on_severity=high
        --@grype.bzl//grype:ignore_cves=CVE-2024-1234,CVE-2024-5678
        --@grype.bzl//grype:database=@grype_database

    Per-target (via aspect_hints):
        Add a cve_policy() target as an aspect_hint to override global settings.

Provides:
    - GrypeScanInfo: with the JSON scan report
    - OutputGroupInfo: 'cve_scan' (report) and '_validation' (pass/fail marker)

The '_validation' output group integrates with --run_validations to
fail builds when CVE policy is violated.
""",
)
