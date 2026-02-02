"""CVE policy provider for per-target vulnerability configuration."""

CvePolicyInfo = provider(
    doc = "Per-target CVE scanning policy. Attach to image targets to override global defaults.",
    fields = {
        "fail_on_severity": "Minimum severity to fail on (e.g. 'critical', 'high', 'medium', 'low', 'negligible')",
        "ignore_cves": "List of CVE IDs to ignore",
    },
)

def _cve_policy_impl(ctx):
    return [CvePolicyInfo(
        fail_on_severity = ctx.attr.fail_on_severity,
        ignore_cves = ctx.attr.ignore_cves,
    )]

cve_policy = rule(
    implementation = _cve_policy_impl,
    attrs = {
        "fail_on_severity": attr.string(default = "high"),
        "ignore_cves": attr.string_list(default = []),
    },
    doc = """Declares a CVE policy for use with grype_aspect.

Per-target policy overrides the global --@grype.bzl//grype:fail_on_severity
and --@grype.bzl//grype:ignore_cves build settings.

Example:
    ```starlark
    load("@grype.bzl//grype:cve_policy.bzl", "cve_policy")

    cve_policy(
        name = "my_image_cve_policy",
        fail_on_severity = "critical",
        ignore_cves = ["CVE-2024-1234"],
    )
    ```
""",
)
