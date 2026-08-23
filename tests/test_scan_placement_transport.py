from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat

import pytest

from api.scan.placement_transport import (
    MAX_PLACEMENT_BUNDLE_BYTES,
    PLACEMENT_DIGEST_ENV,
    PLACEMENT_FILE_ENV,
    PlacementTransportError,
    load_private_placement_bundle,
    write_private_placement_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
EXECUTION = {
    "execution_plan_digest": "a" * 64,
    "target_binding_digest": "b" * 64,
}


def _payload(*, capabilities=None):
    return {
        "schema_version": "canonical-scan-placements/v1",
        **EXECUTION,
        "capabilities": capabilities or {
            "web.crawl": {"status": "success", "observations": []},
        },
    }


def test_private_placement_bundle_is_owner_only_digest_checked_and_one_shot(tmp_path):
    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    assert stat.S_IMODE(bundle.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(bundle.path.stat().st_mode) == 0o600
    environment = bundle.environment()

    loaded = load_private_placement_bundle(EXECUTION, environ=environment)

    assert loaded == _payload()
    assert environment == {}
    assert not bundle.path.exists()
    assert not bundle.path.parent.exists()


def test_private_placement_bundle_rejects_tamper_permissions_and_symlinks(tmp_path):
    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    bundle.path.write_bytes(bundle.path.read_bytes() + b" ")
    with pytest.raises(PlacementTransportError, match="digest or size mismatch"):
        load_private_placement_bundle(EXECUTION, environ=bundle.environment())
    assert not bundle.path.exists()

    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    bundle.path.chmod(0o644)
    with pytest.raises(PlacementTransportError, match="owner-only regular file"):
        load_private_placement_bundle(EXECUTION, environ=bundle.environment())

    protected = tmp_path / "protected.json"
    protected.write_text("do not delete", encoding="utf-8")
    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    bundle.path.unlink()
    bundle.path.symlink_to(protected)
    with pytest.raises(PlacementTransportError, match="owner-only regular file"):
        load_private_placement_bundle(EXECUTION, environ=bundle.environment())
    assert protected.read_text(encoding="utf-8") == "do not delete"


def test_private_placement_bundle_rejects_wrong_authority_and_noncanonical_json(tmp_path):
    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    with pytest.raises(PlacementTransportError, match="do not match"):
        load_private_placement_bundle(
            {**EXECUTION, "target_binding_digest": "c" * 64},
            environ=bundle.environment(),
        )

    bundle = write_private_placement_bundle(_payload(), parent_directory=tmp_path)
    raw = bundle.path.read_bytes() + b"\n"
    bundle.path.write_bytes(raw)
    bundle.path.chmod(0o600)
    environment = {
        PLACEMENT_FILE_ENV: str(bundle.path),
        PLACEMENT_DIGEST_ENV: hashlib.sha256(raw).hexdigest(),
    }
    with pytest.raises(PlacementTransportError, match="not canonical JSON"):
        load_private_placement_bundle(EXECUTION, environ=environment)


def test_private_placement_file_handles_bounded_worst_case_urls_without_environment_body(tmp_path):
    long_url = "https://example.test/" + ("a" * 1_980)
    capabilities = {
        f"capability.{index}": {
            "status": "success",
            "observations": [{"url": long_url} for _ in range(200)],
        }
        for index in range(10)
    }
    bundle = write_private_placement_bundle(
        _payload(capabilities=capabilities), parent_directory=tmp_path,
    )
    try:
        assert 3_000_000 < bundle.size_bytes < MAX_PLACEMENT_BUNDLE_BYTES
        environment = bundle.environment()
        assert set(environment) == {PLACEMENT_FILE_ENV, PLACEMENT_DIGEST_ENV}
        assert long_url not in json.dumps(environment)
        assert load_private_placement_bundle(
            EXECUTION, environ=environment,
        )["capabilities"].keys() == capabilities.keys()
    finally:
        bundle.cleanup()


def test_production_sources_do_not_transport_placement_bodies_in_environment():
    worker_source = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    scanner_source = (ROOT / "scanner" / "scanner.py").read_text(encoding="utf-8")
    obsolete_name = "SHAKERSCAN_CANONICAL_SCAN_" + "PLACEMENTS"
    assert obsolete_name not in worker_source
    assert obsolete_name not in scanner_source
    assert PLACEMENT_FILE_ENV in worker_source
    assert PLACEMENT_DIGEST_ENV in worker_source
