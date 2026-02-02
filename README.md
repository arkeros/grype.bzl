# grype.bzl

Bazel rules for [Grype](https://github.com/anchore/grype), an open-source vulnerability scanner by Anchore.

Scan OCI container images and SBOMs for security vulnerabilities as part of your Bazel build.

## Features

- Scan container images or SBOMs for vulnerabilities
- Multiple output formats: JSON, SARIF, CycloneDX, table
- Fail builds on severity thresholds
- Hermetic scanning with pinned vulnerability databases
- Cross-platform support (Linux, macOS, Windows)

## Setup

Add to your `MODULE.bazel`:

```starlark
bazel_dep(name = "grype.bzl", version = "0.0.0")
git_override(
    module_name = "grype.bzl",
    remote = "https://github.com/arkeros/grype.bzl.git",
    commit = "...",
)

grype = use_extension("@grype.bzl//grype:extensions.bzl", "grype")
use_repo(grype, "grype_toolchains")
register_toolchains("@grype_toolchains//:all")
```

## Usage

### Scan an SBOM

```starlark
load("@grype.bzl", "grype_scan")

grype_scan(
    name = "vuln_report",
    sbom = ":my_sbom",
    format = "json",
)
```

### Scan an OCI image

```starlark
grype_scan(
    name = "image_scan",
    image = ":my_oci_image",
    format = "sarif",
)
```

### Fail on severity threshold

```starlark
grype_scan(
    name = "vuln_report",
    sbom = ":my_sbom",
    fail_on = "high",  # Fails if high or critical vulnerabilities found
)
```

### Test with CVE ignore list

```starlark
load("@grype.bzl", "grype_test")

grype_test(
    name = "vuln_check",
    scan_result = ":vuln_report",
    fail_on_severity = "high",
    ignore_cves = ["CVE-2024-1234"],  # Known false positives
)
```

### Aspect: `grype_aspect` (recommended)

Auto-scan all OCI images for vulnerabilities via aspects. No per-target rules needed.

Add to `.bazelrc`:

```
build --aspects=@syft.bzl//syft:defs.bzl%syft_sbom_aspect
build --aspects=@grype.bzl//grype:defs.bzl%grype_aspect
build --run_validations
build --@grype.bzl//grype:fail_on_severity=high
build --@grype.bzl//grype:database=@grype_database
```

Both aspects must be listed. `syft_sbom_aspect` (from [`syft.bzl`](https://github.com/arkeros/syft.bzl)) produces the `sbom` output group that `grype_aspect` consumes.

```bash
bazel build //my/image                                          # Full pipeline
bazel build //my/image --output_groups=sbom                     # Just SBOM
bazel build //my/image --output_groups=cve_scan                 # Just scan report
bazel build //my/image --@grype.bzl//grype:fail_on_severity=critical  # Override threshold
```

#### Per-target CVE policy

Override global settings for specific images using `cve_policy` and `aspect_hints`:

```starlark
load("@grype.bzl//grype:cve_policy.bzl", "cve_policy")
load("@rules_img//img:image.bzl", "image_manifest")

cve_policy(
    name = "my_image_cve_policy",
    fail_on_severity = "critical",
    ignore_cves = ["CVE-2025-15281"],
)

image_manifest(
    name = "my_image",
    base = "@debian",
    aspect_hints = [":my_image_cve_policy"],
)
```

#### Build settings

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--@grype.bzl//grype:fail_on_severity` | string | `high` | Minimum severity to fail on |
| `--@grype.bzl//grype:ignore_cves` | string list | `[]` | CVE IDs to ignore globally |
| `--@grype.bzl//grype:database` | label | none | Pinned vulnerability database |

## Output Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| `json` | `.grype.json` | Grype native JSON |
| `table` | `.grype.txt` | Human-readable table |
| `sarif` | `.sarif.json` | SARIF for GitHub/IDE integration |
| `cyclonedx-json` | `.cdx.json` | CycloneDX JSON |
| `cyclonedx-xml` | `.cdx.xml` | CycloneDX XML |

## Severity Levels

For `fail_on` and `fail_on_severity`:

- `negligible`
- `low`
- `medium`
- `high`
- `critical`

## Examples

See the [`examples/`](examples/) directory:

- [`examples/simple/`](examples/simple/) - Quick start with rules
- [`examples/aspect/`](examples/aspect/) - Aspect-based scanning with per-target CVE policy
- [`examples/hermetic/`](examples/hermetic/) - Fully reproducible builds with compiled grype and pinned database

## License

Apache License 2.0
