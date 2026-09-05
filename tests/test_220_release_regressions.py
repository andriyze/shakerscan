from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_model_intake_final_image_has_clean_stage_boundary():
    text = (ROOT / "scanner" / "Dockerfile.model-intake").read_text()
    assert "FROM ${SCANNER_RUNTIME_IMAGE} AS model-intake-python-tools" in text

    marker = "# The final release image starts from a fresh scanner runtime."
    assert marker in text
    final = text.split(marker, 1)[1]

    assert "FROM ${SCANNER_RUNTIME_IMAGE}" in final
    assert "COPY --from=model-intake-python-tools /opt/model-intake-tools" in final
    assert "COPY --from=model-intake-python-tools /opt/pip-audit-cache" in final
    assert "COPY --from=model-intake-python-tools /opt/trivy-cache" in final
    assert "COPY --from=model-intake-python-tools /opt/osv-cache" in final

    # Build-only packages that caused RC103's high-severity SBOM findings must
    # never be introduced in the final stage. Removing them in a later RUN is
    # insufficient because BuildKit attestations retain packages from old layers.
    assert "apt-get install" not in final
    assert "python3-pip-whl" not in final
    assert "python3-setuptools-whl" not in final

    # The final runtime also asserts that scrubbed venv payloads did not regain
    # either vulnerable package while crossing the stage boundary.
    assert "pip/_vendor/msgpack" in final
    assert "setuptools-70.3.0.dist-info" in final
