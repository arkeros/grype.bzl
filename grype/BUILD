load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag", "string_list_flag")

package(default_visibility = ["//visibility:public"])

# Platforms for Linux targets (used by grype_scan transition)
platform(
    name = "linux_amd64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
)

platform(
    name = "linux_arm64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:aarch64",
    ],
)

exports_files([
    "database.bzl",
    "defs.bzl",
    "extensions.bzl",
    "grype_check.sh",
    "cve_policy.bzl",
])

toolchain_type(
    name = "toolchain",
)

bzl_library(
    name = "defs",
    srcs = ["defs.bzl"],
    deps = [
        ":cve_policy",
        "//grype/toolchain",
    ],
)

bzl_library(
    name = "extensions",
    srcs = ["extensions.bzl"],
    deps = [
        ":database_bzl",
        ":versions",
    ],
)

bzl_library(
    name = "database_bzl",
    deps = ["//grype/toolchain"],
)

# Build settings for grype_aspect configuration
string_flag(
    name = "fail_on_severity",
    build_setting_default = "high",
)

string_list_flag(
    name = "ignore_cves",
    build_setting_default = [],
)

# Database label_flag for aspect. Override with:
#   --@grype.bzl//grype:database=@grype_database
label_flag(
    name = "database",
    build_setting_default = ":no_database",
)

filegroup(
    name = "no_database",
)

bzl_library(
    name = "cve_policy",
    srcs = ["cve_policy.bzl"],
)

bzl_library(
    name = "versions",
    srcs = ["versions.bzl"],
)
