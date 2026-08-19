import hashlib
import json
import os
import runpy
import subprocess
import sys

from scanner.scanner_tools import device_advisories


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR_PATH = os.path.join(REPO_ROOT, "scripts", "generate_device_advisories.py")

BOUNDED_KEYS = (
    "version", "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
)


def _probe_versions(record):
    """Candidate versions that should fall inside the advisory's affected range."""
    if record.get("version"):
        return [str(record["version"])]
    candidates = []
    start_including = record.get("version_start_including")
    if start_including:
        candidates.extend([str(start_including), f"{start_including}a"])
    if record.get("version_start_excluding"):
        candidates.append("9999")
    if record.get("version_end_including") or record.get("version_end_excluding"):
        candidates.append("0")
    candidates.append("1.0")
    return candidates


def test_cpe_version_range_match_requires_authoritative_identity_to_promote():
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
    assert matches[0]["advisory_match_complete"] is True
    assert matches[0]["promotable"] is False
    assert matches[0]["proof_basis"] == "advisory_matched_fingerprint_only"
    assert matches[0]["match_type"] == "exact_cpe_version_range"

    authoritative = device_advisories.match_advisories([
        {
            "cve": "CVE-2026-0001",
            "cpe": "cpe:2.3:o:acme:tv_firmware:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0.0",
            "version_end_excluding": "2.4.0",
        }
    ], cpe="cpe:2.3:o:acme:tv_firmware:2.3.1:*:*:*:*:*:*:*", product=None,
       version="2.3.1", identity_evidence_tier="authenticated_firmware_inventory")
    assert authoritative[0]["promotable"] is True
    assert authoritative[0]["authoritative_product_identity"] is True


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
        identity_evidence_tier="signed_firmware_manifest",
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
    }], cpe="cpe:/a:acme:smart%3Atv:2.0", product=None, version=None,
       identity_evidence_tier="vendor_attested_inventory")
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


def test_bundled_snapshot_loads_through_the_real_loader_with_a_real_dataset():
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert loaded["status"] == "available"
    assert loaded["record_count"] >= 15
    products = {str(item.get("product") or "").lower() for item in loaded["advisories"]}
    assert len(products) >= 8
    assert all(str(item.get("cve") or "").startswith("CVE-") for item in loaded["advisories"])


def test_every_bundled_advisory_is_version_bounded_and_promotable():
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert loaded["status"] == "available"
    for record in loaded["advisories"]:
        assert any(record.get(key) not in (None, "", "*", "-") for key in BOUNDED_KEYS), record
        promoted = False
        for version in _probe_versions(record):
            components = str(record.get("cpe") or "").split(":")
            if len(components) >= 6:
                components[5] = version
            matches = device_advisories.match_advisories(
                [record], cpe=":".join(components), product=None, version=version,
                identity_evidence_tier="authenticated_firmware_inventory",
            )
            if matches and matches[0]["promotable"]:
                promoted = True
                break
        assert promoted, f"{record.get('cve')} never promotes for an in-range version"


def test_identity_evidence_tier_never_upgrades_unrecognized_or_banner_metadata():
    assert device_advisories.identity_evidence_tier({
        "cpe": "cpe:2.3:a:acme:tv:1.0:*:*:*:*:*:*:*",
        "confidence": "confirmed",
    }) == {"tier": "network_service_fingerprint", "authoritative": False}
    assert device_advisories.identity_evidence_tier({
        "metadata_json": {"identity_evidence_tier": "made_up_super_confident"},
    })["authoritative"] is False
    assert device_advisories.identity_evidence_tier({
        "identity_evidence_tier": "authenticated_package_inventory",
    }) == {"tier": "authenticated_package_inventory", "authoritative": True}


def test_generator_verify_mode_accepts_the_bundled_snapshot():
    result = subprocess.run(
        [sys.executable, GENERATOR_PATH, "--verify", device_advisories.BUNDLED_SNAPSHOT_PATH],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "self-check:" in result.stdout


def test_generator_offline_mode_emits_a_loadable_curated_snapshot(tmp_path):
    output = tmp_path / "device_advisories.json"
    result = subprocess.run(
        [sys.executable, GENERATOR_PATH, "--offline", "--output", str(output), "--self-check"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    snapshot = json.loads(output.read_text(encoding="utf-8"))
    assert snapshot["schema_version"] == "shakerscan-device-advisories/v1"
    assert len(snapshot["advisories"]) >= 5
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    loaded = device_advisories.load_verified_snapshot(str(output), digest)
    assert loaded["status"] == "available"
    assert loaded["record_count"] == len(snapshot["advisories"])


def test_generator_rejects_non_vulnerable_and_conditional_nvd_cpes():
    generator = runpy.run_path(GENERATOR_PATH)
    iter_matches = generator["iter_cpe_matches"]
    vulnerable_match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:acme:tv_admin:1.0:*:*:*:*:*:*:*",
    }
    context_match = {
        "vulnerable": False,
        "criteria": "cpe:2.3:o:acme:tv_os:1.0:*:*:*:*:*:*:*",
    }

    explicit_false = {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [context_match]}]}]}
    assert list(iter_matches(explicit_false)) == []

    conditional = {
        "configurations": [{
            "nodes": [{"operator": "AND", "cpeMatch": [vulnerable_match, context_match]}]
        }]
    }
    assert list(iter_matches(conditional)) == []

    unconditional = {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [vulnerable_match]}]}]}
    assert list(iter_matches(unconditional)) == [(vulnerable_match["criteria"], vulnerable_match)]


def test_upstream_package_version_strips_epoch_and_revision():
    assert device_advisories.upstream_package_version("1:8.9p1-3ubuntu0.4") == "8.9p1"
    assert device_advisories.upstream_package_version("3.0.11-r0") == "3.0.11"
    assert device_advisories.upstream_package_version("2020.81-1") == "2020.81"
    assert device_advisories.upstream_package_version("") == ""


def test_parse_authenticated_package_inventory_tiers_curated_vs_unmapped():
    host_review = {"status": "ok", "bundles": [{
        "bundle": "software_packages",
        "stdout": (
            "openssl 1.0.1f\n"        # curated -> cpe
            "dropbear - 2016.74\n"    # opkg format, curated -> cpe
            "systemd 252-1\n"         # unmapped -> product only
            "openssl 1.0.1f\n"        # duplicate -> deduped
            "\n"
            "garbage-line-without-version\n"
        ),
    }]}
    records = device_advisories.parse_authenticated_package_inventory(host_review)
    by_pkg = {r["package"]: r for r in records}
    assert set(by_pkg) == {"openssl", "dropbear", "systemd"}
    assert all(r["identity_evidence_tier"] == "authenticated_package_inventory" for r in records)
    assert by_pkg["openssl"]["cpe"].startswith("cpe:2.3:a:openssl:openssl:1.0.1f")
    assert by_pkg["openssl"]["curated_identity"] is True
    assert by_pkg["dropbear"]["version"] == "2016.74" and by_pkg["dropbear"]["cpe"]
    assert by_pkg["systemd"]["cpe"] == "" and by_pkg["systemd"]["curated_identity"] is False


def test_parse_authenticated_package_inventory_ignores_rejected_or_missing_bundle():
    assert device_advisories.parse_authenticated_package_inventory(
        {"status": "rejected", "bundles": []}
    ) == []
    assert device_advisories.parse_authenticated_package_inventory({"bundles": []}) == []
    assert device_advisories.parse_authenticated_package_inventory(None) == []


def test_authenticated_tier_promotes_only_with_curated_cpe():
    records = [{
        "cve": "CVE-2014-0160", "product": "openssl",
        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "version_end_excluding": "1.0.1g",
    }]
    # Curated CPE + authenticated tier -> promotable.
    curated = device_advisories.match_advisories(
        records, cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        product="openssl", version="1.0.1f",
        identity_evidence_tier="authenticated_package_inventory",
    )
    assert curated and curated[0]["promotable"] is True
    # Same authenticated tier but product-name only (no cpe) -> never promotable.
    heuristic = device_advisories.match_advisories(
        records, cpe=None, product="openssl", version="1.0.1f",
        identity_evidence_tier="authenticated_package_inventory",
    )
    assert all(m["promotable"] is False for m in heuristic)
