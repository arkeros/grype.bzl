"""Analysis tests over the command `grype_scan` builds.

The scan report records the path grype was handed, verbatim, under
`source.target`. An absolute path there is the sandbox directory of the
action that produced it — including Bazel's per-action sandbox counter — so
the report differs on every build, on every machine, for a scan that found
exactly the same thing. Reports are published and attested downstream, so
that path is both noise in any build-over-build comparison and the builder's
filesystem layout inside a signed artifact.

These assert on the action's command rather than on a report, so they need
neither a grype toolchain nor a vulnerability database.
"""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//grype:defs.bzl", "grype_scan")

def _scan_action(env):
    """The single GrypeScan action's shell command."""
    actions = [a for a in analysistest.target_actions(env) if a.mnemonic == "GrypeScan"]
    asserts.equals(env, 1, len(actions), "expected exactly one GrypeScan action")
    if len(actions) != 1:
        return ""

    # run_shell spells the command as the last argument of the interpreter.
    return actions[0].argv[-1]

def _records_a_relative_source_path_impl(ctx):
    env = analysistest.begin(ctx)
    command = _scan_action(env)
    asserts.true(
        env,
        "sbom:\"$PWD/" not in command,
        "the sbom is passed as an absolute path, so the report records the " +
        "sandbox directory it was scanned in: " + command,
    )
    asserts.true(
        env,
        "sbom:\"test/testdata/sbom.json\"" in command,
        "expected the sbom passed at its execroot-relative path, got: " + command,
    )
    return analysistest.end(env)

records_a_relative_source_path_test = analysistest.make(_records_a_relative_source_path_impl)

def _records_a_relative_image_path_impl(ctx):
    env = analysistest.begin(ctx)
    command = _scan_action(env)
    scheme = ctx.attr.scheme
    asserts.true(
        env,
        scheme + ":\"$PWD/" not in command,
        "the image tarball is passed as an absolute path, so the report " +
        "records the sandbox directory it was scanned in: " + command,
    )
    asserts.true(
        env,
        scheme + ":\"bazel-out/" in command,
        "expected %s at an execroot-relative path, got: %s" % (scheme, command),
    )
    return analysistest.end(env)

def _reproducible_report_impl(ctx):
    env = analysistest.begin(ctx)
    command = _scan_action(env)

    # A fresh `mktemp -d` per action is echoed back in the report under
    # `descriptor.configuration.db.cache-dir`, so it alone makes two builds of
    # one commit produce different bytes.
    asserts.true(
        env,
        "mktemp" not in command,
        "the database cache directory is a fresh mktemp, which the report " +
        "records: " + command,
    )
    asserts.true(
        env,
        "GRYPE_DB_CACHE_DIR=\"bazel-out/" in command,
        "expected a deterministic, execroot-relative cache directory: " + command,
    )

    # grype stamps `descriptor.timestamp` with the wall clock unless told not
    # to. There is no flag; the config key is reachable as an environment
    # variable.
    asserts.true(
        env,
        "GRYPE_TIMESTAMP=false" in command,
        "expected the report timestamp to be disabled: " + command,
    )

    # grype emits equally-ranked matches in an order that varies between runs
    # of the same command, and no --sort-by strategy settles it, so the report
    # is sorted after the fact.
    asserts.true(
        env,
        "sort_by" in command,
        "expected the matches to be sorted deterministically: " + command,
    )
    return analysistest.end(env)

reproducible_report_test = analysistest.make(_reproducible_report_impl)

records_a_relative_image_path_test = analysistest.make(
    _records_a_relative_image_path_impl,
    # The scheme follows the output group the image target carries:
    # rules_img's `oci_tarball` is an OCI layout, `tarball` a docker save.
    attrs = {"scheme": attr.string(mandatory = True)},
)

def _fake_image_impl(ctx):
    """A target shaped like the image rules `grype_scan` accepts."""
    tarball = ctx.actions.declare_file(ctx.label.name + ".tar")
    ctx.actions.write(tarball, "")
    groups = {ctx.attr.output_group: depset([tarball])}
    return [
        DefaultInfo(files = depset([tarball])),
        OutputGroupInfo(**groups),
    ]

fake_image = rule(
    implementation = _fake_image_impl,
    attrs = {"output_group": attr.string(mandatory = True)},
)

def scan_command_test_suite(name):
    """Declares the analysis tests and the targets they analyse.

    Args:
        name: name of the test_suite to declare.
    """
    grype_scan(
        name = "scan_subject",
        sbom = "//test/testdata:sbom.json",
        grype = "//test/testdata:fake_grype",
        tags = ["manual"],
    )
    records_a_relative_source_path_test(
        name = "records_a_relative_source_path",
        target_under_test = ":scan_subject",
    )

    image_tests = []
    for group, scheme in [("oci_tarball", "oci-archive"), ("tarball", "docker-archive")]:
        fake_image(name = "fake_" + group, output_group = group, tags = ["manual"])
        grype_scan(
            name = group + "_scan_subject",
            image = ":fake_" + group,
            grype = "//test/testdata:fake_grype",
            tags = ["manual"],
        )
        test_name = "records_a_relative_%s_path" % scheme.replace("-", "_")
        records_a_relative_image_path_test(
            name = test_name,
            target_under_test = ":" + group + "_scan_subject",
            scheme = scheme,
        )
        image_tests.append(":" + test_name)

    reproducible_report_test(
        name = "reproducible_report",
        target_under_test = ":scan_subject",
    )

    native.test_suite(
        name = name,
        tests = [
            ":records_a_relative_source_path",
            ":reproducible_report",
        ] + image_tests,
    )
