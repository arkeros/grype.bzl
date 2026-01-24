"""Grype version definitions with URLs and checksums."""

DEFAULT_VERSION = "0.105.0"

# Format: "VERSION-PLATFORM": (filename, sha256)
# Platforms: darwin_amd64, darwin_arm64, linux_amd64, linux_arm64, windows_amd64
GRYPE_VERSIONS = {
    "0.90.0-darwin_amd64": (
        "grype_0.90.0_darwin_amd64.tar.gz",
        "67d9543dc8680a0d9f1df35b6188512dacf5c65717f7d1e16ad2f3efd9eefea3",
    ),
    "0.90.0-darwin_arm64": (
        "grype_0.90.0_darwin_arm64.tar.gz",
        "403edc0f9c3e75cf1da92d4bec911baf8bbd4d86e134fcb7f054962f5dddbbc2",
    ),
    "0.90.0-linux_amd64": (
        "grype_0.90.0_linux_amd64.tar.gz",
        "48430d83f6bd75066ba936fb9e98543194b092cf68dc971ae8ab68b7ff05f8d1",
    ),
    "0.90.0-linux_arm64": (
        "grype_0.90.0_linux_arm64.tar.gz",
        "7e50a4eb0ef5eae6b19106eeceaa0a521bac9d55dce736fc1946ee21023781d9",
    ),
    "0.90.0-windows_amd64": (
        "grype_0.90.0_windows_amd64.zip",
        "d295f6933dade7758bbfea1ebc29e34ce2e90df30988a2fd4f3416bc7ac59c8c",
    ),
    "0.105.0-darwin_amd64": (
        "grype_0.105.0_darwin_amd64.tar.gz",
        "4db34c69c09e0554eba1226ad754b1a1d4ff2fc28f161ab21f68bd1f67666621",
    ),
    "0.105.0-darwin_arm64": (
        "grype_0.105.0_darwin_arm64.tar.gz",
        "f64356365655beaf6346ff11c705cceac6c5a9537a96642328b51cd2d8513841",
    ),
    "0.105.0-linux_amd64": (
        "grype_0.105.0_linux_amd64.tar.gz",
        "3307e0ae2f41ce094b5d9213202f1c553f222f17f944095f7f75f3e2e52235f9",
    ),
    "0.105.0-linux_arm64": (
        "grype_0.105.0_linux_arm64.tar.gz",
        "3aed15e0ab3b4dfed59a8c655a5ea30f460c9b07a7a59c8782c2e1903755c327",
    ),
    "0.105.0-windows_amd64": (
        "grype_0.105.0_windows_amd64.zip",
        "ebf1b3b359d49be320494d7d6a4e7db19ddeca25d4e43c2994b74ed259db2bae",
    ),
}

def get_grype_url(version, filename):
    """Returns the download URL for a grype release."""
    return "https://github.com/anchore/grype/releases/download/v{}/{}".format(version, filename)
