# Hermetic Example

Demonstrates fully reproducible vulnerability scanning with compiled grype and pinned database.

## Features

- Compiles grype from Go source (fully reproducible)
- Pinned vulnerability database (no network access at scan time)
- All inputs tracked by Bazel for true hermeticity
- Suitable for air-gapped environments

## Setup

The `MODULE.bazel` includes:

1. **Grype compiled from source** via rules_go and gazelle
2. **Pinned vulnerability database** with a specific version and date
3. **Patches** for grype/syft source trees to fix BUILD files

```starlark
# Database setup
grype_database = use_extension("@grype.bzl//grype:extensions.bzl", "grype_database")
grype_database.archive(
    version = "6.1.3",
    date = "2026-01-20T01:32:46Z",
    sha256 = "...",
)
use_repo(grype_database, "grype_db")
```

## Run

```bash
# Generate vulnerability report (hermetic)
bazel build //:vuln_report

# Run vulnerability test
bazel test //:vuln_test

# View SARIF output
bazel build //:vuln_report_sarif
```

## Targets

| Target | Description |
|--------|-------------|
| `:vuln_report` | JSON vulnerability report using pinned database |
| `:vuln_report_sarif` | SARIF format output |
| `:vuln_test` | Test that fails on high severity vulnerabilities |

## Updating the Database

To update the pinned database version:

1. Find a new database version from Grype releases
2. Update the `version`, `date`, and `sha256` in `MODULE.bazel`
3. Run `bazel build //:vuln_report` to verify
