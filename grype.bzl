"Re-export for syntax sugar load."

load("//grype:defs.bzl", _SUPPORTED_FORMATS = "SUPPORTED_FORMATS", _grype_scan = "grype_scan", _grype_test = "grype_test")
load("//grype/toolchain:toolchain.bzl", _grype_toolchain = "grype_toolchain")

grype_scan = _grype_scan
grype_test = _grype_test
grype_toolchain = _grype_toolchain
SUPPORTED_FORMATS = _SUPPORTED_FORMATS
