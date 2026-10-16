"""Signed intelligence bundles outside the image: signing, verification, preference, install."""

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scanner.scanner_tools import device_advisories, intel_bundle

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _seed():
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _snapshot(generated_at="2026-10-20T00:00:00Z", cve="CVE-2099-0001"):
    return (json.dumps({
        "schema_version": "shakerscan-device-advisories/v2", "generated_at": generated_at,
        "titles": {cve: "Bundle-only advisory"},
        "advisories": [{
            "cve": cve, "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "product": "http_server", "version_start_including": "2.4.0",
            "version_end_excluding": "2.4.99", "severity": "critical",
        }],
    }, separators=(",", ":")) + "\n").encode()


def _write_bundle(directory, seed, *, version=1, snapshot=None, generated_at="2026-10-20T00:00:00Z"):
    snapshot = snapshot if snapshot is not None else _snapshot(generated_at)
    public = intel_bundle.public_key_for(seed)
    key_id = intel_bundle.key_id_for(public)
    manifest = intel_bundle.build_manifest(snapshot, key_id=key_id, bundle_version=version,
                                           generated_at=generated_at, record_count=1)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, intel_bundle.SNAPSHOT_NAME), "wb") as handle:
        handle.write(snapshot)
    with open(os.path.join(directory, intel_bundle.MANIFEST_NAME), "wb") as handle:
        handle.write(manifest)
    with open(os.path.join(directory, intel_bundle.SIGNATURE_NAME), "wb") as handle:
        handle.write(intel_bundle.sign_manifest(seed, manifest))
    return key_id, public


@pytest.fixture
def vendor(monkeypatch, tmp_path):
    seed = _seed()
    public = intel_bundle.public_key_for(seed)
    key_id = intel_bundle.key_id_for(public)
    monkeypatch.setitem(intel_bundle.TRUSTED_BUNDLE_KEYS, key_id, base64.b64encode(public).decode())
    monkeypatch.delenv(intel_bundle.TRUSTED_KEYS_ENV, raising=False)
    bundle_dir = tmp_path / "intel"
    monkeypatch.setenv(intel_bundle.BUNDLE_DIR_ENV, str(bundle_dir))
    device_advisories._SNAPSHOT_CACHE.clear()
    yield seed, bundle_dir
    device_advisories._SNAPSHOT_CACHE.clear()


def test_builtin_constant_matches_the_shipped_snapshot():
    with open(device_advisories.BUNDLED_SNAPSHOT_PATH, "rb") as handle:
        raw = handle.read()
    assert hashlib.sha256(raw).hexdigest() == device_advisories.BUNDLED_SNAPSHOT_SHA256
    head = json.loads(raw)
    assert head["generated_at"] == device_advisories.BUNDLED_SNAPSHOT_GENERATED_AT


def test_no_bundle_keeps_the_builtin_snapshot(vendor):
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert loaded["status"] == "available"
    assert loaded["source"] == "builtin"
    assert loaded["bundle"] == {"status": "absent"}
    # The image's own env pin (built-in path + digest) is the built-in, not an operator pin.
    pinned = device_advisories.load_verified_snapshot(
        device_advisories.BUNDLED_SNAPSHOT_PATH, device_advisories.BUNDLED_SNAPSHOT_SHA256)
    assert pinned["source"] == "builtin"


def test_verified_bundle_is_preferred_over_the_builtin_snapshot(vendor):
    seed, bundle_dir = vendor
    _write_bundle(str(bundle_dir), seed, version=7)
    loaded = device_advisories.load_verified_snapshot(
        device_advisories.BUNDLED_SNAPSHOT_PATH, device_advisories.BUNDLED_SNAPSHOT_SHA256)
    assert loaded["status"] == "available"
    assert loaded["source"] == "external_bundle"
    assert loaded["bundle"]["bundle_version"] == 7
    assert [row["cve"] for row in loaded["advisories"]] == ["CVE-2099-0001"]
    assert loaded["advisories"][0]["title"] == "Bundle-only advisory"


@pytest.mark.parametrize("tamper, reason", [
    ("snapshot", "builtin"), ("manifest", "bad_signature"), ("signature", "bad_signature"),
    ("unsigned", "unsigned"),
])
def test_tampered_bundle_falls_back_with_a_reason(vendor, tamper, reason):
    seed, bundle_dir = vendor
    _write_bundle(str(bundle_dir), seed)
    if tamper == "snapshot":
        # Same size, different content: the signed digest refuses it.
        path = bundle_dir / intel_bundle.SNAPSHOT_NAME
        data = path.read_bytes().replace(b"CVE-2099-0001", b"CVE-2099-0002")
        path.write_bytes(data)
    elif tamper == "manifest":
        path = bundle_dir / intel_bundle.MANIFEST_NAME
        path.write_bytes(path.read_bytes().replace(b'"bundle_version":1', b'"bundle_version":9'))
    elif tamper == "signature":
        other = _seed()
        manifest = (bundle_dir / intel_bundle.MANIFEST_NAME).read_bytes()
        (bundle_dir / intel_bundle.SIGNATURE_NAME).write_bytes(intel_bundle.sign_manifest(other, manifest))
    else:
        (bundle_dir / intel_bundle.SIGNATURE_NAME).unlink()
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert loaded["status"] == "available"
    assert loaded["source"] == "builtin"
    expected = "snapshot_integrity_mismatch" if tamper == "snapshot" else reason
    assert loaded["bundle"]["status"] == expected
    assert all(row.get("cve") != "CVE-2099-0002" for row in loaded["advisories"])


def test_bundle_signed_by_an_unknown_key_is_not_used(vendor, monkeypatch):
    _seed_trusted, bundle_dir = vendor
    _write_bundle(str(bundle_dir), _seed())
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert (loaded["source"], loaded["bundle"]["status"]) == ("builtin", "untrusted_key")


def test_operator_pinned_key_is_trusted_only_when_its_id_matches(vendor, monkeypatch):
    _trusted, bundle_dir = vendor
    seed = _seed()
    key_id, public = _write_bundle(str(bundle_dir), seed)
    encoded = base64.b64encode(public).decode()
    monkeypatch.setenv(intel_bundle.TRUSTED_KEYS_ENV, f"0000000000000000={encoded}")
    assert device_advisories.load_verified_snapshot(None, None)["bundle"]["status"] == "untrusted_key"
    monkeypatch.setenv(intel_bundle.TRUSTED_KEYS_ENV, f"{key_id}={encoded}")
    assert device_advisories.load_verified_snapshot(None, None)["source"] == "external_bundle"


def test_bundle_older_than_the_builtin_snapshot_is_refused(vendor):
    seed, bundle_dir = vendor
    _write_bundle(str(bundle_dir), seed, generated_at="2026-01-01T00:00:00Z")
    loaded = device_advisories.load_verified_snapshot(None, None)
    assert (loaded["source"], loaded["bundle"]["status"]) == ("builtin", "older_than_builtin")


def test_operator_pin_is_used_as_given_and_never_replaced_by_a_bundle(vendor, tmp_path):
    seed, bundle_dir = vendor
    _write_bundle(str(bundle_dir), seed)
    custom = tmp_path / "custom.json"
    custom.write_bytes(_snapshot(cve="CVE-2099-0042"))
    digest = hashlib.sha256(custom.read_bytes()).hexdigest()
    loaded = device_advisories.load_verified_snapshot(str(custom), digest)
    assert loaded["source"] == "operator_pinned"
    assert [row["cve"] for row in loaded["advisories"]] == ["CVE-2099-0042"]


def test_symlinked_bundle_files_are_refused(vendor, tmp_path):
    seed, bundle_dir = vendor
    real = tmp_path / "real"
    _write_bundle(str(real), seed)
    bundle_dir.mkdir()
    for name in (intel_bundle.MANIFEST_NAME, intel_bundle.SIGNATURE_NAME, intel_bundle.SNAPSHOT_NAME):
        os.symlink(real / name, bundle_dir / name)
    assert device_advisories.load_verified_snapshot(None, None)["source"] == "builtin"


def _archive(directory, path, extra=None):
    with tarfile.open(path, "w:gz") as bundle:
        for name in (intel_bundle.MANIFEST_NAME, intel_bundle.SIGNATURE_NAME, intel_bundle.SNAPSHOT_NAME):
            bundle.add(os.path.join(directory, name), arcname=name)
        if extra:
            info = tarfile.TarInfo(extra)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            bundle.addfile(info)


def test_install_verifies_activates_and_refuses_rollback(vendor, tmp_path):
    seed, bundle_dir = vendor
    v2, v1 = tmp_path / "v2", tmp_path / "v1"
    _write_bundle(str(v2), seed, version=2)
    _write_bundle(str(v1), seed, version=1)
    _archive(str(v2), tmp_path / "v2.tar.gz")
    result = intel_bundle.install_bundle(str(tmp_path / "v2.tar.gz"), str(bundle_dir))
    assert result["bundle_version"] == 2 and result["record_count"] == 1
    assert device_advisories.load_verified_snapshot(None, None)["source"] == "external_bundle"
    with pytest.raises(intel_bundle.BundleError) as refused:
        intel_bundle.install_bundle(str(v1), str(bundle_dir))
    assert refused.value.reason == "version_rollback"
    assert intel_bundle.verify_bundle(str(bundle_dir))["bundle_version"] == 2
    # Re-installing the same version is allowed and keeps the previous copy beside it.
    intel_bundle.install_bundle(str(v2), str(bundle_dir))
    assert (tmp_path / "intel.previous" / intel_bundle.MANIFEST_NAME).exists()


def test_install_refuses_untrusted_or_hostile_archives_and_leaves_the_installed_bundle(vendor, tmp_path):
    seed, bundle_dir = vendor
    good = tmp_path / "good"
    _write_bundle(str(good), seed, version=3)
    intel_bundle.install_bundle(str(good), str(bundle_dir))
    hostile = tmp_path / "hostile"
    _write_bundle(str(hostile), seed, version=4)
    _archive(str(hostile), tmp_path / "hostile.tar.gz", extra="link")
    with pytest.raises(intel_bundle.BundleError) as refused:
        intel_bundle.install_bundle(str(tmp_path / "hostile.tar.gz"), str(bundle_dir))
    assert refused.value.reason == "unexpected_archive_member"
    foreign = tmp_path / "foreign"
    _write_bundle(str(foreign), _seed(), version=5)
    with pytest.raises(intel_bundle.BundleError) as refused:
        intel_bundle.install_bundle(str(foreign), str(bundle_dir))
    assert refused.value.reason == "untrusted_key"
    assert intel_bundle.verify_bundle(str(bundle_dir))["bundle_version"] == 3
    assert not [name for name in os.listdir(tmp_path) if name.startswith(".intel-staging-")]


def test_traversal_member_names_are_refused(vendor, tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        data = b"{}"
        info = tarfile.TarInfo("../manifest.json")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    with pytest.raises(intel_bundle.BundleError) as refused:
        intel_bundle.install_bundle(str(archive), str(tmp_path / "intel"))
    assert refused.value.reason == "unexpected_archive_member"


def test_vendor_tool_keygen_build_verify_round_trip(tmp_path):
    env = {**os.environ, "PYTHONPATH": REPO_ROOT}
    key = tmp_path / "vendor" / "intel.key"
    out = subprocess.run([sys.executable, "scripts/intel_bundle.py", "keygen", "--private-key", str(key)],
                         cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True)
    generated = json.loads(out.stdout)
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert base64.b64encode(intel_bundle.public_key_for(
        base64.b64decode(key.read_text().strip()))).decode() == generated["public_key"]
    snapshot = tmp_path / "advisories.json"
    snapshot.write_bytes(_snapshot())
    subprocess.run([sys.executable, "scripts/intel_bundle.py", "build", "--snapshot", str(snapshot),
                    "--private-key", str(key), "--bundle-version", "2026102001",
                    "--out", str(tmp_path / "bundle"), "--archive", str(tmp_path / "bundle.tar.gz")],
                   cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True)
    trusted = f"{generated['key_id']}={generated['public_key']}"
    verified = subprocess.run([sys.executable, "scripts/intel_bundle.py", "verify", "--bundle",
                               str(tmp_path / "bundle.tar.gz"), "--trusted-key", trusted],
                              cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert json.loads(verified.stdout)["bundle_version"] == 2026102001
    refused = subprocess.run([sys.executable, "scripts/intel_bundle.py", "verify", "--bundle",
                              str(tmp_path / "bundle")], cwd=REPO_ROOT,
                             env={**env, intel_bundle.TRUSTED_KEYS_ENV: ""}, capture_output=True, text=True)
    assert refused.returncode == 2 and json.loads(refused.stdout)["reason"] == "untrusted_key"


def test_vendor_tool_refuses_a_private_key_inside_the_checkout():
    result = subprocess.run([sys.executable, "scripts/intel_bundle.py", "keygen", "--private-key",
                             os.path.join(REPO_ROOT, "results", "never.key")],
                            cwd=REPO_ROOT, env={**os.environ, "PYTHONPATH": REPO_ROOT},
                            capture_output=True, text=True)
    assert result.returncode != 0 and "inside the source checkout" in result.stderr
    assert not os.path.exists(os.path.join(REPO_ROOT, "results", "never.key"))
