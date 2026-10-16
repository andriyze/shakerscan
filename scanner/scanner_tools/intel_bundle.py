"""Signed vulnerability-intelligence bundles delivered outside the image.

A bundle is a directory with three regular files:

* ``device_advisories.json`` -- a snapshot in the format the built-in one uses;
* ``manifest.json`` -- what the bundle is: schema, signing key id, a monotonic
  ``bundle_version``, ``generated_at`` and the snapshot's SHA-256 and size;
* ``manifest.sig`` -- a base64 Ed25519 signature over the exact manifest bytes.

The engine trusts a bundle only when the signature verifies under a vendor key it
already knows (``TRUSTED_BUNDLE_KEYS`` in this file, or keys an operator pins with
``SHAKERSCAN_INTEL_TRUSTED_KEYS``), the snapshot's digest matches the signed
manifest, and the bundle is not older than the snapshot built into the image. Any
other state falls back to the built-in snapshot with a stated reason. Nothing here
fetches from the network: the vendor tool (``scripts/intel_bundle.py``) builds and
signs, and the host installs the files; workers and the API only read them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from typing import Any, Mapping

BUNDLE_SCHEMA = "shakerscan-intel-bundle/v1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
SNAPSHOT_NAME = "device_advisories.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024
BUNDLE_DIR_ENV = "SHAKERSCAN_INTEL_BUNDLE_DIR"
TRUSTED_KEYS_ENV = "SHAKERSCAN_INTEL_TRUSTED_KEYS"
_KEY_ID = re.compile(r"^[0-9a-f]{16}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Vendor Ed25519 public keys trusted for intelligence bundles: key id -> raw public key (base64).
# The key id is the first 16 hex characters of SHA-256 over the 32 raw public-key bytes.
# Empty until the vendor signing key is provisioned; until then only the built-in snapshot (or an
# operator-pinned key/path) is used, and an installed bundle reports ``untrusted_key``.
TRUSTED_BUNDLE_KEYS: dict[str, str] = {}


class BundleError(ValueError):
    """A bundle that must not be used; ``reason`` is a stable, value-free code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason


def default_bundle_dir() -> str:
    configured = str(os.environ.get("SHAKERSCAN_INTEL_BUNDLE_DIR") or "").strip()
    if configured:
        return configured
    return os.path.join(str(os.environ.get("RESULTS_DIR") or "/results"), "intel")


def key_id_for(public_key: bytes) -> str:
    return hashlib.sha256(bytes(public_key)).hexdigest()[:16]


def _decode_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(str(value).strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleError("malformed_trusted_key") from exc
    if len(raw) != 32:
        raise BundleError("malformed_trusted_key")
    return raw


def trusted_keys(extra: str | None = None) -> dict[str, bytes]:
    """Vendor keys plus operator-pinned ``id=base64`` pairs; a pair whose id does not match
    its key is ignored, so a typo cannot alias a trusted id."""
    keys: dict[str, bytes] = {}
    for key_id, encoded in TRUSTED_BUNDLE_KEYS.items():
        raw = _decode_key(encoded)
        if key_id_for(raw) == key_id:
            keys[key_id] = raw
    pinned = os.environ.get("SHAKERSCAN_INTEL_TRUSTED_KEYS") if extra is None else extra
    for item in str(pinned or "").split(","):
        key_id, _, encoded = item.strip().partition("=")
        if not key_id or not encoded:
            continue
        try:
            raw = _decode_key(encoded)
        except BundleError:
            continue
        if key_id_for(raw) == key_id.strip().lower():
            keys[key_id.strip().lower()] = raw
    return keys


def _read_regular(path: str, limit: int) -> bytes:
    """Read a bounded regular file without following a symlink at the final component."""
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BundleError("not_regular_file")
        if info.st_size > limit:
            raise BundleError("file_too_large")
        data = os.read(descriptor, limit + 1)
        if len(data) > limit:
            raise BundleError("file_too_large")
        return data
    except FileNotFoundError as exc:
        raise BundleError("absent") from exc
    except OSError as exc:
        raise BundleError("unreadable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise BundleError("malformed_manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA:
        raise BundleError("unsupported_schema")
    snapshot = manifest.get("snapshot")
    version = manifest.get("bundle_version")
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("file") != SNAPSHOT_NAME
        or not _SHA256.fullmatch(str(snapshot.get("sha256") or ""))
        or isinstance(snapshot.get("size_bytes"), bool)
        or not isinstance(snapshot.get("size_bytes"), int)
        or snapshot["size_bytes"] < 1
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version < 1
        or not _KEY_ID.fullmatch(str(manifest.get("key_id") or ""))
        or _timestamp(manifest.get("generated_at")) is None
    ):
        raise BundleError("malformed_manifest")
    return manifest


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ModuleNotFoundError as exc:  # pragma: no cover - the runtime image ships it
        raise BundleError("verifier_unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature:
        return False
    except ValueError:
        return False
    return True


def verify_bundle(
    directory: str | None = None, *, keys: Mapping[str, bytes] | None = None,
    not_older_than: str | None = None, minimum_version: int | None = None,
) -> dict[str, Any]:
    """Verify one bundle directory and return where its snapshot is and which digest pins it.

    Raises ``BundleError`` with a stable reason when the bundle must not be used. The snapshot
    content itself is checked against the signed digest by the snapshot loader, which reads it
    once; this function only checks that the file is present at the signed size.
    """
    location = str(directory or default_bundle_dir())
    manifest_raw = _read_regular(os.path.join(location, MANIFEST_NAME), MAX_MANIFEST_BYTES)
    try:
        signature_raw = _read_regular(os.path.join(location, SIGNATURE_NAME), MAX_SIGNATURE_BYTES)
    except BundleError as exc:
        raise BundleError("unsigned" if exc.reason == "absent" else exc.reason) from exc
    manifest = parse_manifest(manifest_raw)
    try:
        signature = base64.b64decode(signature_raw.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleError("malformed_signature") from exc
    if len(signature) != 64:
        raise BundleError("malformed_signature")
    available = dict(trusted_keys() if keys is None else keys)
    public_key = available.get(manifest["key_id"])
    if public_key is None:
        raise BundleError("untrusted_key")
    if not verify_signature(public_key, manifest_raw, signature):
        raise BundleError("bad_signature")
    generated = _timestamp(manifest["generated_at"])
    floor = _timestamp(not_older_than) if not_older_than else None
    if floor is not None and generated is not None and generated < floor:
        raise BundleError("older_than_builtin")
    if minimum_version is not None and manifest["bundle_version"] < int(minimum_version):
        raise BundleError("version_rollback")
    snapshot_path = os.path.join(location, SNAPSHOT_NAME)
    try:
        info = os.lstat(snapshot_path)
    except FileNotFoundError as exc:
        raise BundleError("snapshot_missing") from exc
    except OSError as exc:
        raise BundleError("unreadable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise BundleError("not_regular_file")
    if info.st_size != manifest["snapshot"]["size_bytes"]:
        raise BundleError("snapshot_size_mismatch")
    return {
        "status": "verified",
        "directory": location,
        "snapshot_path": snapshot_path,
        "snapshot_sha256": manifest["snapshot"]["sha256"],
        "bundle_version": manifest["bundle_version"],
        "generated_at": manifest["generated_at"],
        "key_id": manifest["key_id"],
        "record_count": manifest["snapshot"].get("record_count"),
    }


def bundle_status(directory: str | None = None, *, not_older_than: str | None = None,
                  minimum_version: int | None = None) -> dict[str, Any]:
    """Non-raising form for the loader and status views: ``verified`` or the refusal reason."""
    location = str(directory or default_bundle_dir())
    try:
        return verify_bundle(location, not_older_than=not_older_than, minimum_version=minimum_version)
    except BundleError as exc:
        return {"status": exc.reason, "directory": location}


# --- Rollback protection -----------------------------------------------------------------
#
# The highest bundle_version ever put in force is recorded outside the bundle directory, in a mark
# file beside it (results/intel.high-water) and in the database (intel_bundle_high_water), and kept
# per process. The loader refuses a bundle below it (``version_rollback``), so swapping an older but
# validly signed bundle into results/intel does not roll the intelligence back. API startup repairs
# a missing or lower mark file from the database row.

_PROCESS_HIGH_WATER: dict[str, int] = {}


def high_water_path(directory: str | None = None) -> str:
    return os.path.abspath(str(directory or default_bundle_dir())).rstrip("/") + ".high-water"


def read_high_water(directory: str | None = None) -> int:
    path = high_water_path(directory)
    recorded = 0
    try:
        value = json.loads(_read_regular(path, 4096).decode("utf-8")).get("bundle_version")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            recorded = value
    except (BundleError, UnicodeError, ValueError, AttributeError):
        recorded = 0
    return max(recorded, _PROCESS_HIGH_WATER.get(path, 0))


def note_version_in_force(version: int, directory: str | None = None) -> None:
    path = high_water_path(directory)
    _PROCESS_HIGH_WATER[path] = max(int(version), _PROCESS_HIGH_WATER.get(path, 0))


def record_high_water(version: int, directory: str | None = None) -> int:
    """Raise the mark file to ``version`` (never lower it); returns the mark now in force."""
    path = high_water_path(directory)
    current = read_high_water(directory)
    target = max(int(version), current)
    note_version_in_force(target, directory)
    if target == current and os.path.exists(path):
        return target
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"bundle_version": target}) + "\n")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return target


HIGH_WATER_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS intel_bundle_high_water (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    bundle_version BIGINT NOT NULL CHECK (bundle_version > 0),
    key_id TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


async def database_high_water(conn: Any) -> int:
    value = await conn.fetchval(
        "SELECT bundle_version FROM intel_bundle_high_water WHERE singleton")
    return int(value or 0)


async def record_database_high_water(conn: Any, version: int, key_id: str | None) -> int:
    value = await conn.fetchval("""
        INSERT INTO intel_bundle_high_water (singleton, bundle_version, key_id) VALUES (true, $1, $2)
        ON CONFLICT (singleton) DO UPDATE SET
          bundle_version=GREATEST(intel_bundle_high_water.bundle_version, EXCLUDED.bundle_version),
          key_id=CASE WHEN EXCLUDED.bundle_version >= intel_bundle_high_water.bundle_version
                      THEN EXCLUDED.key_id ELSE intel_bundle_high_water.key_id END,
          recorded_at=now()
        RETURNING bundle_version""", int(version), key_id)
    return int(value)


async def sync_high_water_from_database(conn: Any, directory: str | None = None) -> int:
    """At API startup: the mark file is never lower than the database row."""
    version = await database_high_water(conn)
    if version:
        try:
            return record_high_water(version, directory)
        except OSError:
            note_version_in_force(version, directory)
    return version


# --- Vendor side ---------------------------------------------------------------------------


def build_manifest(snapshot_bytes: bytes, *, key_id: str, bundle_version: int,
                   generated_at: str | None = None, record_count: int | None = None,
                   source: str | None = None) -> bytes:
    if not _KEY_ID.fullmatch(key_id):
        raise BundleError("malformed_key_id")
    if isinstance(bundle_version, bool) or not isinstance(bundle_version, int) or bundle_version < 1:
        raise BundleError("malformed_manifest")
    manifest: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "key_id": key_id,
        "bundle_version": bundle_version,
        "generated_at": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "snapshot": {
            "file": SNAPSHOT_NAME,
            "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
            "size_bytes": len(snapshot_bytes),
        },
    }
    if record_count is not None:
        manifest["snapshot"]["record_count"] = int(record_count)
    if source:
        manifest["source"] = str(source)[:300]
    parse_manifest(json.dumps(manifest).encode())
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sign_manifest(private_key_raw: bytes, manifest_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes(private_key_raw))
    return base64.b64encode(key.sign(manifest_bytes)) + b"\n"


def public_key_for(private_key_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes(private_key_raw))
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )


# --- Host side: verify and activate --------------------------------------------------------

MAX_SNAPSHOT_FILE_BYTES = 32 * 1024 * 1024
_BUNDLE_FILES = {MANIFEST_NAME: MAX_MANIFEST_BYTES, SIGNATURE_NAME: MAX_SIGNATURE_BYTES,
                 SNAPSHOT_NAME: MAX_SNAPSHOT_FILE_BYTES}


def _extract_archive(archive: str, staging: str) -> None:
    """Extract exactly the three bundle files from a tar(.gz); links, devices, nested paths and
    anything else are refused rather than skipped."""
    import tarfile

    try:
        with tarfile.open(archive, "r:*") as bundle:
            seen: set[str] = set()
            for member in bundle.getmembers():
                name = member.name[2:] if member.name.startswith("./") else member.name
                if member.isdir() and name in {"", "."}:
                    continue
                if name not in _BUNDLE_FILES or not member.isfile() or name in seen:
                    raise BundleError("unexpected_archive_member")
                if member.size > _BUNDLE_FILES[name]:
                    raise BundleError("file_too_large")
                source = bundle.extractfile(member)
                if source is None:
                    raise BundleError("unexpected_archive_member")
                with source, open(os.path.join(staging, name), "xb") as handle:
                    remaining = _BUNDLE_FILES[name] + 1
                    while chunk := source.read(min(1024 * 1024, remaining)):
                        remaining -= len(chunk)
                        if remaining <= 0:
                            raise BundleError("file_too_large")
                        handle.write(chunk)
                seen.add(name)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BundleError("malformed_archive") from exc


def _copy_directory(source: str, staging: str) -> None:
    for name, limit in _BUNDLE_FILES.items():
        try:
            data = _read_regular(os.path.join(source, name), limit)
        except BundleError as exc:
            if exc.reason == "absent" and name == SIGNATURE_NAME:
                raise BundleError("unsigned") from exc
            raise
        with open(os.path.join(staging, name), "xb") as handle:
            handle.write(data)


def install_bundle(source: str, target: str | None = None, *,
                   keys: Mapping[str, bytes] | None = None, floor: int = 0) -> dict[str, Any]:
    """Verify a bundle (directory or tar archive) and make it the one in force.

    The installed bundle is replaced only by a verified bundle whose ``bundle_version`` is not
    lower; the previous one is kept beside it as ``<target>.previous``. On any refusal the
    installed bundle is untouched.
    """
    import shutil
    import tempfile

    from . import device_advisories

    destination = os.path.abspath(str(target or default_bundle_dir()))
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    current_version = None
    try:
        current_version = verify_bundle(destination, keys=keys)["bundle_version"]
    except BundleError:
        current_version = None
    # The recorded high-water mark holds even when the installed bundle no longer verifies.
    minimum = max(int(floor or 0), read_high_water(destination), int(current_version or 0)) or None
    staging = tempfile.mkdtemp(prefix=".intel-staging-", dir=parent)
    try:
        if os.path.isdir(source):
            _copy_directory(source, staging)
        else:
            _extract_archive(source, staging)
        verified = verify_bundle(
            staging, keys=keys, not_older_than=device_advisories.BUNDLED_SNAPSHOT_GENERATED_AT,
            minimum_version=minimum,
        )
        loaded = device_advisories._load_pinned_snapshot(
            verified["snapshot_path"], verified["snapshot_sha256"],
        )
        if loaded.get("status") != "available":
            raise BundleError(f"snapshot_{loaded.get('status') or 'unavailable'}")
        for name in _BUNDLE_FILES:
            os.chmod(os.path.join(staging, name), 0o644)
        os.chmod(staging, 0o755)
        previous = destination + ".previous"
        if os.path.lexists(destination):
            if os.path.lexists(previous):
                shutil.rmtree(previous)
            os.rename(destination, previous)
        os.rename(staging, destination)
        staging = ""
        record_high_water(verified["bundle_version"], destination)
        return {**verified, "directory": destination, "snapshot_path": os.path.join(destination, SNAPSHOT_NAME),
                "record_count": loaded.get("record_count"), "replaced_version": current_version}
    finally:
        if staging and os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)


def _install_with_database(source: str, target: str | None) -> dict[str, Any]:
    """Install under the database high-water mark and raise it; without a configured database
    (development) only the mark file applies. A configured but unreachable database refuses."""
    import asyncio

    url = str(os.environ.get("DATABASE_URL") or "").strip()
    if not url:
        return install_bundle(source, target)

    async def run() -> dict[str, Any]:
        try:
            import asyncpg

            conn = await asyncpg.connect(url, timeout=15)
        except Exception as exc:  # noqa: BLE001 - any connection failure refuses the install
            raise BundleError("high_water_unavailable") from exc
        try:
            await conn.execute(HIGH_WATER_SCHEMA_SQL)
            floor = await database_high_water(conn)
            result = install_bundle(source, target, floor=floor)
            await record_database_high_water(conn, result["bundle_version"], result.get("key_id"))
            return result
        finally:
            await conn.close()

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    """``python -m scanner_tools.intel_bundle status|install`` inside the API container."""
    import argparse

    parser = argparse.ArgumentParser(prog="intel_bundle", description="Signed intelligence bundles")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="the snapshot in force and the installed bundle's state")
    install = commands.add_parser("install", help="verify a bundle and make it the one in force")
    install.add_argument("--from", dest="source", required=True, help="bundle directory or tar(.gz)")
    install.add_argument("--to", dest="target", default=None, help="installed bundle directory")
    args = parser.parse_args(argv)
    if args.command == "status":
        from . import device_advisories

        loaded = device_advisories.load_verified_snapshot(
            os.environ.get("DEVICE_INTEL_DB_PATH"), os.environ.get("DEVICE_INTEL_DB_SHA256"),
        )
        print(json.dumps({
            "in_force": {key: loaded.get(key) for key in (
                "status", "source", "snapshot_sha256", "record_count", "generated_at")},
            "bundle": bundle_status(not_older_than=device_advisories.BUNDLED_SNAPSHOT_GENERATED_AT),
            "trusted_key_ids": sorted(trusted_keys()),
        }, indent=2, sort_keys=True))
        return 0
    try:
        result = _install_with_database(args.source, args.target)
    except BundleError as exc:
        print(json.dumps({"status": "refused", "reason": exc.reason}))
        return 2
    print(json.dumps({key: result.get(key) for key in (
        "status", "bundle_version", "generated_at", "key_id", "record_count", "replaced_version")},
        sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
