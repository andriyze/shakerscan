#!/usr/bin/env python3
"""Vendor tool: create a signing key, build and sign an intelligence bundle, verify one.

The private key never belongs in this repository. ``keygen`` writes it (base64 of the 32 raw
Ed25519 seed bytes, mode 0600) to a path you choose outside the checkout and prints the key id and
public key to place in ``TRUSTED_BUNDLE_KEYS`` (scanner/scanner_tools/intel_bundle.py).

    scripts/intel_bundle.py keygen --private-key ~/.shakerscan-vendor/intel-bundle.key
    scripts/generate_device_advisories.py --network-services ... --output /tmp/advisories.json
    scripts/intel_bundle.py build --snapshot /tmp/advisories.json \
        --private-key ~/.shakerscan-vendor/intel-bundle.key --bundle-version 2026101601 \
        --out /tmp/intel-bundle --archive /tmp/intel-bundle.tar.gz
    scripts/intel_bundle.py verify --bundle /tmp/intel-bundle.tar.gz --trusted-key <id>=<public>

Publish the archive where installations fetch it; an installation activates it with
``./scanner.sh intel install <path or https URL>``, which verifies it again inside the engine.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.scanner_tools import device_advisories, intel_bundle  # noqa: E402


def _inside_checkout(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    return True


def _read_private_key(path: str) -> bytes:
    raw = base64.b64decode(Path(path).expanduser().read_text().strip(), validate=True)
    if len(raw) != 32:
        raise SystemExit("private key file must hold base64 of 32 raw Ed25519 seed bytes")
    return raw


def keygen(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = Path(args.private_key).expanduser()
    if _inside_checkout(path):
        raise SystemExit("refusing to write a private key inside the source checkout")
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(base64.b64encode(seed).decode() + "\n")
    public = intel_bundle.public_key_for(seed)
    key_id = intel_bundle.key_id_for(public)
    print(json.dumps({
        "private_key_file": str(path), "key_id": key_id,
        "public_key": base64.b64encode(public).decode(),
        "trusted_bundle_keys_entry": f'"{key_id}": "{base64.b64encode(public).decode()}"',
    }, indent=2))
    return 0


def _archive(directory: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz") as bundle:
        for name in (intel_bundle.MANIFEST_NAME, intel_bundle.SIGNATURE_NAME, intel_bundle.SNAPSHOT_NAME):
            data = (directory / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            bundle.addfile(info, io.BytesIO(data))


def build(args: argparse.Namespace) -> int:
    snapshot = Path(args.snapshot).read_bytes()
    digest = hashlib.sha256(snapshot).hexdigest()
    loaded = device_advisories._load_pinned_snapshot(args.snapshot, digest)
    if loaded.get("status") != "available" or not loaded.get("record_count"):
        raise SystemExit(f"snapshot is not loadable by the engine: {loaded.get('status')}")
    seed = _read_private_key(args.private_key)
    public = intel_bundle.public_key_for(seed)
    key_id = intel_bundle.key_id_for(public)
    manifest = intel_bundle.build_manifest(
        snapshot, key_id=key_id, bundle_version=args.bundle_version,
        generated_at=loaded.get("generated_at") or None, record_count=loaded.get("record_count"),
        source=args.source,
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    (out / intel_bundle.SNAPSHOT_NAME).write_bytes(snapshot)
    (out / intel_bundle.MANIFEST_NAME).write_bytes(manifest)
    (out / intel_bundle.SIGNATURE_NAME).write_bytes(intel_bundle.sign_manifest(seed, manifest))
    verified = intel_bundle.verify_bundle(str(out), keys={key_id: public})
    if args.archive:
        _archive(out, Path(args.archive))
    print(json.dumps({**{k: verified[k] for k in ("bundle_version", "generated_at", "key_id",
                                                     "snapshot_sha256", "record_count")},
                      "directory": str(out), "archive": args.archive}, indent=2))
    return 0


def verify(args: argparse.Namespace) -> int:
    keys = intel_bundle.trusted_keys(",".join(args.trusted_key)) if args.trusted_key else None
    source = Path(args.bundle)
    with tempfile.TemporaryDirectory() as scratch:
        directory = source
        if not source.is_dir():
            directory = Path(scratch) / "bundle"
            directory.mkdir()
            intel_bundle._extract_archive(str(source), str(directory))
        try:
            result = intel_bundle.verify_bundle(str(directory), keys=keys)
        except intel_bundle.BundleError as exc:
            print(json.dumps({"status": "refused", "reason": exc.reason}))
            return 2
        loaded = device_advisories._load_pinned_snapshot(result["snapshot_path"], result["snapshot_sha256"])
        if loaded.get("status") != "available":
            print(json.dumps({"status": "refused", "reason": f"snapshot_{loaded.get('status')}"}))
            return 2
    print(json.dumps({k: result[k] for k in ("status", "bundle_version", "generated_at", "key_id",
                                             "snapshot_sha256")}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen", help="create the vendor signing key (outside the checkout)")
    generate.add_argument("--private-key", required=True)
    make = commands.add_parser("build", help="build and sign a bundle from a generated snapshot")
    make.add_argument("--snapshot", required=True, help="output of scripts/generate_device_advisories.py")
    make.add_argument("--private-key", required=True)
    make.add_argument("--bundle-version", required=True, type=int,
                      help="monotonic; installations refuse a lower version than the one installed")
    make.add_argument("--out", required=True, help="new directory for the bundle files")
    make.add_argument("--archive", default=None, help="also write a .tar.gz for publication")
    make.add_argument("--source", default="NVD CPE configurations, CISA KEV, FIRST EPSS")
    check = commands.add_parser("verify", help="verify a bundle directory or archive")
    check.add_argument("--bundle", required=True)
    check.add_argument("--trusted-key", action="append", default=[],
                       help="id=base64 public key; default: the keys the engine trusts")
    args = parser.parse_args(argv)
    return {"keygen": keygen, "build": build, "verify": verify}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
