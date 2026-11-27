from __future__ import annotations

import uuid

import pytest

from api.runtime.observation_manifests import (
    ObservationManifest,
    ObservationManifestError,
    ObservationManifestReference,
    validate_observation_manifest_reference,
)


def _manifest() -> ObservationManifest:
    return ObservationManifest(
        manifest_id=str(uuid.UUID("00000000-0000-0000-0000-000000000201")),
        owner_id=str(uuid.UUID("00000000-0000-0000-0000-000000000202")),
        action_id="discover.web_crawl",
        capability_name="web.crawl",
        output_schema="katana-lines/v1",
        observation_count=147,
        content_sha256="a" * 64,
        size_bytes=18_342,
        object_key="scans/00000000-0000-0000-0000-000000000202/web-crawl.jsonl",
    )


def test_observation_manifest_is_content_free_and_reference_is_digest_bound():
    manifest = _manifest()
    reference = manifest.reference()

    assert manifest.canonical_dict()["observation_count"] == 147
    assert "observations" not in manifest.canonical_dict()
    assert len(manifest.manifest_digest) == 64
    assert ObservationManifest.from_dict(manifest.canonical_dict()) == manifest
    assert ObservationManifestReference.from_dict(reference.canonical_dict()) == reference
    validate_observation_manifest_reference(reference, manifest)

    altered = ObservationManifestReference(
        **{**reference.canonical_dict(), "count": 146},
    )
    with pytest.raises(ObservationManifestError, match="does not match"):
        validate_observation_manifest_reference(altered, manifest)


@pytest.mark.parametrize("object_key", [
    "/tmp/observations.json", "../observations.json", "https://objects.test/item",
])
def test_observation_manifest_rejects_public_absolute_or_traversing_object_keys(object_key):
    payload = _manifest().canonical_dict()
    payload["object_key"] = object_key
    with pytest.raises(ObservationManifestError, match="object_key"):
        ObservationManifest.from_dict(payload)


def test_nonempty_observation_manifest_requires_bounded_content():
    payload = _manifest().canonical_dict()
    payload["size_bytes"] = 0
    with pytest.raises(ObservationManifestError, match="non-empty"):
        ObservationManifest.from_dict(payload)
    payload["size_bytes"] = 18_342
    payload["observation_count"] = 100_001
    with pytest.raises(ObservationManifestError, match="allowed range"):
        ObservationManifest.from_dict(payload)
