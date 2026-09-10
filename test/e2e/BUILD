load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//grype:defs.bzl", "grype_scan")

# End to end, against a real grype and the pinned database in MODULE.bazel.
# The analysis tests in //test assert what the action is told to do; this
# asserts what came back, which is the only thing that would catch grype
# resolving a path itself or stamping a time under a name nobody expected.

grype_scan(
    name = "report",
    database = "@grype_db//:db",
    sbom = "sbom.json",
)

sh_test(
    name = "reproducible",
    size = "large",
    srcs = ["assert_reproducible.sh"],
    args = [
        "$(location :report)",
        "$(location @jq_toolchains//:resolved_toolchain)",
    ],
    data = [
        ":report",
        "@jq_toolchains//:resolved_toolchain",
    ],
)

grype_scan(
    name = "cdx_report",
    database = "@grype_db//:db",
    format = "cyclonedx-json",
    sbom = "sbom.json",
)

sh_test(
    name = "cyclonedx_reproducible",
    size = "large",
    srcs = ["assert_cyclonedx_reproducible.sh"],
    args = [
        "$(location :cdx_report)",
        "$(location @jq_toolchains//:resolved_toolchain)",
    ],
    data = [
        ":cdx_report",
        "@jq_toolchains//:resolved_toolchain",
    ],
)
