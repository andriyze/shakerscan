#!/usr/bin/env python3
"""Serve a build-captured pip-audit result for one exact runtime profile.

Model Intake never asks pip-audit to resolve or install model-authored input.
The release image audits the hash-locked Firecracker runtime while it is built,
then this wrapper verifies that scan-time component evidence is byte-for-byte
the same package/version set before returning the captured pip-audit JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path


def _normal_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip()).lower()


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _url_version(name: str, url: str) -> str | None:
    filename = urllib.parse.unquote(Path(urllib.parse.urlsplit(url).path).name)
    match = re.match(rf"{re.escape(name)}-(?P<version>.+?)-(?:cp|py)\d", filename, re.IGNORECASE)
    return match.group("version") if match else None


def _components_from_lock(path: Path) -> list[dict[str, str]]:
    components: dict[str, dict[str, str]] = {}
    for raw in path.read_text("utf-8").splitlines():
        if not raw or raw[:1].isspace() or raw.lstrip().startswith("#"):
            continue
        line = raw.strip().rstrip(" \\")
        direct = re.match(r"(?P<name>[A-Za-z0-9._-]+)\s+@\s+(?P<url>\S+)", line)
        exact = re.match(r"(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;]+)", line)
        if direct:
            name = direct.group("name")
            version = _url_version(name, direct.group("url"))
            if not version:
                raise ValueError(f"cannot derive version for direct URL requirement: {name}")
        elif exact:
            name, version = exact.group("name"), exact.group("version")
        else:
            raise ValueError(f"unparsed runtime lock entry: {line[:120]}")
        components[_normal_name(name)] = {"name": _normal_name(name), "version": version}
    if not components:
        raise ValueError("runtime lock has no exact components")
    return [components[key] for key in sorted(components)]


def _components_from_inventory(path: Path) -> list[dict[str, str]]:
    parsed = json.loads(path.read_text("utf-8"))
    raw_components = parsed.get("components") if isinstance(parsed, dict) else None
    if not isinstance(raw_components, list):
        raise ValueError("runtime component inventory is missing components")
    components: dict[str, dict[str, str]] = {}
    for item in raw_components:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise ValueError("runtime component inventory contains an unversioned component")
        name = _normal_name(str(item["name"]))
        components[name] = {"name": name, "version": str(item["version"])}
    return [components[key] for key in sorted(components)]


def build_cache(lock: Path, pip_audit: Path, output: Path, metadata: Path) -> None:
    components = _components_from_lock(lock)
    audit_components = [
        {"name": item["name"], "version": item["version"].split("+", 1)[0]}
        for item in components
    ]
    requirements = "".join(f"{item['name']}=={item['version']}\n" for item in audit_components)
    with tempfile.TemporaryDirectory(prefix="pip-audit-runtime-cache-") as raw:
        requirement_path = Path(raw) / "requirements.txt"
        requirement_path.write_text(requirements, encoding="utf-8")
        completed = subprocess.run(
            [
                str(pip_audit), "--requirement", str(requirement_path), "--no-deps",
                "--disable-pip", "--aliases=on", "--desc=off",
                "--progress-spinner=off", "--format=json",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"pip-audit cache build failed: {completed.stderr[-1000:]}")
    audited = json.loads(completed.stdout)
    dependencies = audited.get("dependencies") if isinstance(audited, dict) else None
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit cache output is missing dependencies")
    skipped = [item for item in dependencies if isinstance(item, dict) and item.get("skip_reason")]
    observed = {
        (_normal_name(str(item.get("name"))), str(item.get("version")))
        for item in dependencies if isinstance(item, dict) and item.get("name") and item.get("version")
    }
    expected = {(item["name"], item["version"]) for item in audit_components}
    if skipped or observed != expected:
        raise ValueError(
            f"pip-audit did not cover the exact runtime: skipped={skipped!r} "
            f"missing={sorted(expected - observed)!r} unexpected={sorted(observed - expected)!r}"
        )
    generated_at = datetime.now(timezone.utc).isoformat()
    envelope = {
        "schema_version": "shakerscan.pip-audit-offline-cache/v1",
        "profile_id": "shakerscan-firecracker-python312-cpu/v1",
        "generated_at": generated_at,
        "runtime_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "component_set_sha256": _sha256_json(components),
        "components": components,
        "pip_audit_result": audited,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    metadata.write_text(json.dumps({
        "UpdatedAt": generated_at,
        "Profile": envelope["profile_id"],
        "RuntimeLockSHA256": envelope["runtime_lock_sha256"],
        "ComponentSetSHA256": envelope["component_set_sha256"],
        "CacheSHA256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def serve_cache(inventory: Path, cache: Path) -> None:
    components = _components_from_inventory(inventory)
    envelope = json.loads(cache.read_text("utf-8"))
    expected = str(envelope.get("component_set_sha256") or "")
    actual = _sha256_json(components)
    if not expected or actual != expected:
        raise ValueError(
            "runtime component set does not match the build-audited Firecracker profile "
            f"(expected {expected or 'missing'}, observed {actual})"
        )
    result = envelope.get("pip_audit_result")
    if not isinstance(result, dict):
        raise ValueError("cached pip-audit result is invalid")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--build-cache", action="store_true")
    parser.add_argument("--lock")
    parser.add_argument("--pip-audit")
    parser.add_argument("--output")
    parser.add_argument("--metadata")
    parser.add_argument("--input")
    parser.add_argument("--cache", default="/opt/pip-audit-cache/runtime-audit.json")
    parser.add_argument("--format", default="json")
    args = parser.parse_args()
    if args.version:
        print("pip-audit-offline 1 (pip-audit 2.10.1 build-captured)")
        return 0
    if args.build_cache:
        if not all((args.lock, args.pip_audit, args.output, args.metadata)):
            parser.error("--build-cache requires --lock, --pip-audit, --output, and --metadata")
        build_cache(Path(args.lock), Path(args.pip_audit), Path(args.output), Path(args.metadata))
        return 0
    if not args.input or args.format != "json":
        parser.error("scan mode requires --input and --format json")
    serve_cache(Path(args.input), Path(args.cache))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
