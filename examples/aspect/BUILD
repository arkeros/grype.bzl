# Example: grype_aspect auto-scans OCI images for vulnerabilities.
#
# No grype_scan() or grype_test() rules needed -- aspects handle everything.
#
# Usage:
#   bazel build :app_image                         # Full pipeline (scan + validate)
#   bazel build :app_image --output_groups=sbom    # Just the SBOM
#   bazel build :app_image --output_groups=cve_scan # Just the scan report
#
# Override severity:
#   bazel build :app_image --@grype.bzl//grype:fail_on_severity=critical

load("@grype.bzl//grype:cve_policy.bzl", "cve_policy")
load("@rules_img//img:image.bzl", "image_manifest")

# Standard image -- uses global fail_on_severity from .bazelrc
image_manifest(
    name = "app_image",
    base = select({
        "@platforms//cpu:arm64": "@alpine_linux_arm64",
        "@platforms//cpu:x86_64": "@alpine_linux_amd64",
    }),
)

# Image with per-target CVE policy override via aspect_hints
cve_policy(
    name = "legacy_image_cve_policy",
    fail_on_severity = "critical",
    ignore_cves = ["CVE-2024-0000"],
)

image_manifest(
    name = "legacy_image",
    aspect_hints = [":legacy_image_cve_policy"],
    base = select({
        "@platforms//cpu:arm64": "@alpine_linux_arm64",
        "@platforms//cpu:x86_64": "@alpine_linux_amd64",
    }),
)
