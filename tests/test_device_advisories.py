import hashlib
import json
import os

from scanner.scanner_tools import device_advisories


def test_cpe_version_range_match_is_promotable_advisory_evidence():
    matches = device_advisories.match_advisories([
        {
            "cve": "CVE-2026-0001",
            "cpe": "cpe:2.3:o:acme:tv_firmware:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0.0",
            "version_end_excluding": "2.4.0",
            "severity": "high",
        }
    ], cpe="cpe:2.3:o:acme:tv_firmware:2.3.1:*:*:*:*:*:*:*", product=None, version="2.3.1")

    assert len(matches) == 1
    assert matches[0]["promotable"] is True
    assert matches[0]["proof_basis"] == "advisory_matched"
    assert matches[0]["match_type"] == "exact_cpe_version_range"


def test_out_of_range_or_heuristic_product_match_cannot_promote():
    records = [{
        "cve": "CVE-2026-0002",
        "cpe": "cpe:2.3:o:acme:camera:*:*:*:*:*:*:*:*",
        "product": "Acme Camera",
        "version_end_including": "3.0.0",
    }]

    assert device_advisories.match_advisories(
        records,
        cpe="cpe:2.3:o:acme:camera:4.0.0:*:*:*:*:*:*:*",
        product="Acme Camera",
        version="4.0.0",
    ) == []
    heuristic = device_advisories.match_advisories(
        records, cpe=None, product="Acme Camera", version="2.0.0",
    )[0]
    assert heuristic["promotable"] is False
    assert heuristic["proof_basis"] == "signal_only"


def test_cpe_part_is_part_of_exact_identity():
    records = [{
        "cve": "CVE-2026-0003",
        "cpe": "cpe:2.3:o:acme:controller:*:*:*:*:*:*:*:*",
        "version_end_excluding": "2.0",
    }]
    # Same vendor/product/version but an application CPE must never match an OS advisory.
    assert device_advisories.match_advisories(
        records,
        cpe="cpe:2.3:a:acme:controller:1.0:*:*:*:*:*:*:*",
        product=None,
        version="1.0",
    ) == []


def test_escaped_cpe_components_match_but_identity_wildcards_do_not_promote():
    escaped = [{
        "cve": "CVE-2026-0004",
        "cpe": r"cpe:2.3:a:acme:smart\:tv:*:*:*:*:*:*:*:*",
        "version_end_including": "3.0",
    }]
    matches = device_advisories.match_advisories(
        escaped,
        cpe=r"cpe:2.3:a:acme:smart\:tv:2.0:*:*:*:*:*:*:*",
        product=None,
        version="2.0",
    )
    assert matches[0]["promotable"] is True

    wildcard_product = [{
        "cve": "CVE-2026-0005",
        "cpe": "cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*",
        "version_end_including": "3.0",
    }]
    assert device_advisories.match_advisories(
        wildcard_product,
        cpe="cpe:2.3:a:acme:smart_tv:2.0:*:*:*:*:*:*:*",
        product=None,
        version="2.0",
    ) == []


def test_cpe_22_and_exact_version_from_advisory_cpe_are_supported():
    matches = device_advisories.match_advisories([{
        "cve": "CVE-2026-0006",
        "cpe": "cpe:/a:acme:smart%3Atv:2.0",
    }], cpe="cpe:/a:acme:smart%3Atv:2.0", product=None, version=None)
    assert matches[0]["promotable"] is True
    assert matches[0]["version_range"] == {"version": "2.0"}


def test_unconstrained_wildcard_version_is_signal_only():
    matches = device_advisories.match_advisories([{
        "cve": "CVE-2026-0007",
        "cpe": "cpe:2.3:a:acme:smart_tv:*:*:*:*:*:*:*:*",
    }], cpe="cpe:2.3:a:acme:smart_tv:2.0:*:*:*:*:*:*:*", product=None, version=None)
    assert matches[0]["promotable"] is False
    assert matches[0]["match_type"] == "exact_cpe_version_unknown"


def test_embedded_version_comparison_handles_numeric_segments():
    assert device_advisories.compare_versions("2.10.0", "2.9.9") > 0
    assert device_advisories.compare_versions("1.0", "1.0.0") == 0


def test_snapshot_loader_requires_pinned_digest_and_rejects_mismatch(tmp_path):
    path = tmp_path / "device-advisories.json"
    path.write_text(json.dumps({"generated_at": "2026-08-16T00:00:00Z", "advisories": [{"cve": "CVE-1"}]}))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    loaded = device_advisories.load_verified_snapshot(path, digest)
    assert loaded["status"] == "available"
    assert loaded["snapshot_sha256"] == digest
    assert loaded["record_count"] == 1
    assert device_advisories.load_verified_snapshot(path, "0" * 64)["status"] == "integrity_mismatch"
    assert device_advisories.load_verified_snapshot(path, "")["status"] == "untrusted_snapshot"


def test_default_install_uses_the_hash_pinned_bundled_snapshot():
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert loaded["status"] == "available"
    assert loaded["snapshot_sha256"] == device_advisories.BUNDLED_SNAPSHOT_SHA256
    assert loaded["record_count"] >= 5
    assert all(item.get("reference", "").startswith("https://nvd.nist.gov/") for item in loaded["advisories"])


def test_bundled_snapshot_hash_and_release_image_defaults_cannot_drift():
    with open(device_advisories.BUNDLED_SNAPSHOT_PATH, "rb") as handle:
        actual = hashlib.sha256(handle.read()).hexdigest()
    assert actual == device_advisories.BUNDLED_SNAPSHOT_SHA256
    dockerfile_path = os.path.join(os.path.dirname(__file__), "..", "scanner", "Dockerfile")
    dockerfile = open(dockerfile_path, encoding="utf-8").read()
    assert "ENV DEVICE_INTEL_DB_PATH=/app/data/device_advisories.json" in dockerfile
    assert f"ENV DEVICE_INTEL_DB_SHA256={actual}" in dockerfile
