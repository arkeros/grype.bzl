load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

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
])

toolchain_type(
    name = "toolchain",
)

bzl_library(
    name = "defs",
    srcs = ["defs.bzl"],
    deps = ["//grype/toolchain"],
)

bzl_library(
    name = "extensions",
    srcs = ["extensions.bzl"],
    deps = [
        ":database",
        ":versions",
    ],
)

bzl_library(
    name = "database",
    srcs = ["database.bzl"],
    deps = ["//grype/toolchain"],
)

bzl_library(
    name = "versions",
    srcs = ["versions.bzl"],
)
