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

- [`examples/simple/`](examples/simple/) - Quick start with pre-built binaries
- [`examples/hermetic/`](examples/hermetic/) - Fully reproducible builds with compiled grype and pinned database

## License

Apache License 2.0
