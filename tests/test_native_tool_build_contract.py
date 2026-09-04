"""Regression coverage for the native scanner build and its metadata verifier."""
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "scanner/Dockerfile.model-intake").read_text()
BUILDER = DOCKERFILE.split("FROM ${SCANNER_RUNTIME_IMAGE}", 1)[0]


@pytest.mark.parametrize("metadata,expected", [
    ("\tdep\tgolang.org/x/crypto\tv0.55.0\th1:fixture\n", 0),
    ("  dep  golang.org/x/crypto  v0.55.0  h1:fixture\n", 0),
    ("\tdep\tgolang.org/x/crypto\tv0.54.0\th1:fixture\n", 1),
    ("\tdep\tgolang.org/x/crypto\tv0.55.00\th1:fixture\n", 1),
    ("\tdep\tgolang.org/x/crypto/other\tv0.55.0\th1:fixture\n", 1),
    ("\tbuild\tgolang.org/x/crypto\tv0.55.0\n", 1),
    (r"dep\tgolang.org/x/crypto\tv0.55.0", 1),
    ("", 1),
])
def test_native_dependency_verifier_matches_metadata_fields(metadata, expected):
    # Execute the actual awk program used in the Docker build, not a test copy.
    program = re.search(r"check_dep\(\) \{ awk [^\n]*?'([^']+)'", BUILDER)
    assert program is not None
    result = subprocess.run(
        ["awk", "-v", "module=golang.org/x/crypto", "-v", "version=v0.55.0", program[1]],
        input=metadata, text=True, capture_output=True, check=False,
    )
    assert result.returncode == expected, result.stderr


def test_runtime_base_arg_is_global_and_native_sources_are_pinned():
    assert BUILDER.index("ARG SCANNER_RUNTIME_IMAGE=") < BUILDER.index("FROM ")
    assert 'test "$(git rev-parse HEAD)" = "$TRIVY_COMMIT"' in BUILDER
    assert 'test "$(git rev-parse HEAD)" = "$OSV_SCANNER_COMMIT"' in BUILDER
    assert "ENV GOTOOLCHAIN=local" in BUILDER


def test_native_build_preserves_upstream_version_metadata_and_checks_it():
    assert "GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build" in BUILDER
    assert "-X=github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" in BUILDER
    assert "-X=github.com/google/osv-scanner/v2/internal/version.OSVVersion=${OSV_SCANNER_VERSION}" in BUILDER
    assert 'grep -Fx "Version: ${TRIVY_VERSION}"' in BUILDER
    assert 'grep -Fx "osv-scanner version: ${OSV_SCANNER_VERSION}"' in BUILDER
    assert "check_dep" in BUILDER
