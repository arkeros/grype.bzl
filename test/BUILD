load("@gazelle//:def.bzl", "gazelle_test")
load(":scan_command_test.bzl", "scan_command_test_suite")

package(default_visibility = ["//visibility:public"])

gazelle_test(
    name = "gazelle.check",
    size = "small",
    gazelle = "//tools:gazelle_bin",
    workspace = "//:BUILD",
)

scan_command_test_suite(name = "scan_command_tests")
