# Hermetic example: compiled grype with pinned vulnerability database
#
# This example demonstrates:
# - Compiling grype from Go source for hermetic builds
# - Using a pinned vulnerability database (no network at scan time)
# - Full reproducibility with all inputs tracked by Bazel

load("@grype.bzl//grype:defs.bzl", "grype_scan")
load("@grype.bzl//grype/toolchain:toolchain.bzl", "grype_toolchain")
load("@rules_img//img:image.bzl", "image_manifest")
load("@syft.bzl//syft:defs.bzl", "syft_sbom")

# Define a grype toolchain using the compiled binary
grype_toolchain(
    name = "compiled_grype_toolchain",
    grype = "@com_github_anchore_grype//cmd/grype",
    visibility = ["//visibility:public"],
)

# Register the toolchain (referenced in MODULE.bazel)
toolchain(
    name = "grype_toolchain",
    toolchain = ":compiled_grype_toolchain",
    toolchain_type = "@grype.bzl//grype:toolchain",
)

# Create a simple image based on Alpine Linux
image_manifest(
    name = "example_image",
    base = select({
        "@platforms//cpu:arm64": "@alpine_linux_arm64",
        "@platforms//cpu:x86_64": "@alpine_linux_amd64",
    }),
)

# Generate SBOM using syft
syft_sbom(
    name = "sbom",
    image = ":example_image",
)

# Scan with hermetic database - fully reproducible, no network access
grype_scan(
    name = "vuln_report",
    database = "@grype_db//:db",
    sbom = ":sbom",
)

# Scan with SARIF output for CI integration
grype_scan(
    name = "vuln_report_sarif",
    database = "@grype_db//:db",
    format = "sarif",
    sbom = ":sbom",
)

# Scan with severity check - fails if critical vulnerabilities found
grype_scan(
    name = "vuln_check",
    database = "@grype_db//:db",
    fail_on = "critical",
    sbom = ":sbom",
)
