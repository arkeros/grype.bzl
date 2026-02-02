"Re-export for syntax sugar load."

load("//grype:cve_policy.bzl", _CvePolicyInfo = "CvePolicyInfo", _cve_policy = "cve_policy")
load(
    "//grype:defs.bzl",
    _GrypeScanInfo = "GrypeScanInfo",
    _SUPPORTED_FORMATS = "SUPPORTED_FORMATS",
    _grype_aspect = "grype_aspect",
    _grype_scan = "grype_scan",
    _grype_test = "grype_test",
)
load("//grype/toolchain:toolchain.bzl", _grype_toolchain = "grype_toolchain")

grype_scan = _grype_scan
grype_test = _grype_test
grype_aspect = _grype_aspect
grype_toolchain = _grype_toolchain
cve_policy = _cve_policy
GrypeScanInfo = _GrypeScanInfo
CvePolicyInfo = _CvePolicyInfo
SUPPORTED_FORMATS = _SUPPORTED_FORMATS
