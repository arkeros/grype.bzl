# Simple Example

Demonstrates grype.bzl with pre-built binaries and online vulnerability database.

## Features

- Uses pre-built grype binary from GitHub releases
- Downloads vulnerability database at scan time
- Quick setup, minimal configuration

## Setup

The `MODULE.bazel` registers the grype toolchain:

```starlark
grype = use_extension("@grype.bzl//grype:extensions.bzl", "grype")
grype.toolchain(version = "0.105.0")
use_repo(grype, "grype_toolchains")
register_toolchains("@grype_toolchains//:all")
```

## Run

```bash
# Generate vulnerability report
bazel build //:vuln_report

# Run vulnerability test
bazel test //:vuln_test

# View SARIF output
bazel build //:vuln_report_sarif
```

## Targets

| Target | Description |
|--------|-------------|
| `:vuln_report` | JSON vulnerability report |
| `:vuln_report_sarif` | SARIF format for GitHub/IDE integration |
| `:vuln_test` | Test that fails on high severity vulnerabilities |
