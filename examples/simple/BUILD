# Simple example: grype vulnerability scanning with pre-built toolchain
#
# This example demonstrates:
# - Generating an SBOM with syft
# - Scanning the SBOM for vulnerabilities with grype
# - Scanning an OCI image directly with grype

load("@grype.bzl//grype:defs.bzl", "grype_scan", "grype_test")
load("@rules_img//img:image.bzl", "image_manifest")
load("@syft.bzl//syft:defs.bzl", "syft_sbom")

# Create a simple image based on Alpine Linux
image_manifest(
    name = "example_image",
    base = select({
        "@platforms//cpu:arm64": "@alpine_linux_arm64",
        "@platforms//cpu:x86_64": "@alpine_linux_amd64",
    }),
)

# Generate SBOM in SPDX JSON format
syft_sbom(
    name = "sbom",
    image = ":example_image",
)

# Scan SBOM for vulnerabilities (JSON output)
grype_scan(
    name = "vuln_report",
    sbom = ":sbom",
)

# Scan SBOM with SARIF output (for CI/CD integration)
grype_scan(
    name = "vuln_report_sarif",
    format = "sarif",
    sbom = ":sbom",
)

# Scan image directly (without SBOM intermediate)
grype_scan(
    name = "vuln_report_direct",
    image = ":example_image",
)

# Scan with severity threshold - fails build if high+ vulnerabilities found
grype_scan(
    name = "vuln_check",
    fail_on = "high",
    sbom = ":sbom",
)

# Test target for vulnerability checking (alternative to fail_on)
# This creates a proper test target that can be run with `bazel test`
grype_test(
    name = "vuln_test",
    scan_result = ":vuln_report",
    fail_on_severity = "high",
)

# Test with ignored CVEs (for known false positives or accepted risks)
grype_test(
    name = "vuln_test_with_ignores",
    scan_result = ":vuln_report",
    fail_on_severity = "critical",
    ignore_cves = ["CVE-2024-0000"],  # Example: known false positive
)
