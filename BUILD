load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

# Prefer generated BUILD files to be called BUILD over BUILD.bazel
# gazelle:build_file_name BUILD,BUILD.bazel
# gazelle:prefix github.com/arkeros/grype.bzl
# gazelle:exclude bazel-grype.bzl

exports_files([
    "BUILD",
    "LICENSE",
    "MODULE.bazel",
])

bzl_library(
    name = "grype",
    srcs = ["grype.bzl"],
    visibility = ["//visibility:public"],
    deps = [
        "//grype:cve_policy",
        "//grype:defs",
        "//grype/toolchain",
    ],
)
