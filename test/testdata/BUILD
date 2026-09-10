load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

package(default_visibility = ["//test:__subpackages__"])

exports_files(["sbom.json"])

sh_binary(
    name = "fake_grype",
    srcs = ["fake_grype.sh"],
)
