# Aspect Example

Auto-scan all OCI images for CVEs without per-target `grype_scan` or `grype_test` rules.

## How it works

The `.bazelrc` wires everything:

```
build --aspects=@grype.bzl//grype:defs.bzl%grype_aspect
build --run_validations
build --@grype.bzl//grype:fail_on_severity=high
```

Both aspects must be listed. `syft_sbom_aspect` produces the `sbom` output group that `grype_aspect` consumes.

For each OCI image target, the aspect chain:
1. Generates an SBOM (via `syft_sbom_aspect`)
2. Scans the SBOM with grype (produces `cve_scan` output group)
3. Validates against CVE policy (produces `_validation` output group)

With `--run_validations`, step 3 fails the build if violations are found.

## Usage

```bash
# Build with full CVE pipeline
bazel build :app_image

# Get just the SBOM
bazel build :app_image --output_groups=sbom

# Get just the scan report (no policy enforcement)
bazel build :app_image --output_groups=cve_scan

# Override severity for one invocation
bazel build :app_image --@grype.bzl//grype:fail_on_severity=critical
```

## Per-target policy

Use `cve_policy` + `aspect_hints` to override global settings:

```starlark
cve_policy(
    name = "my_policy",
    fail_on_severity = "critical",
    ignore_cves = ["CVE-2024-0000"],
)

image_manifest(
    name = "my_image",
    base = "@alpine",
    aspect_hints = [":my_policy"],
)
```
