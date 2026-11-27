#!/usr/bin/env python3
"""Pinned release-only SBOM tooling. Never installed in product runtime images."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

SYFT_VERSION = "1.52.0"
SYFT_ARCHIVES = {
    "amd64": "caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d",
    "arm64": "c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706",
}
# Git blob identities independently read from the upstream repositories. Tag mutation
# cannot change the accepted bytes. Resolved SHA-256s are also recorded in the tool receipt.
SCHEMAS = {
    "spdx-2.2.json": ("spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json", "9abf467472aff22ffe75cff75f6421527df98942"),
    "spdx-2.3.json": ("spdx/spdx-spec/v2.3/schemas/spdx-schema.json", "ee61e6686e885f8139c132647fd0b4f483b8fb81"),
    "bom-1.6.schema.json": ("CycloneDX/specification/1.6/schema/bom-1.6.schema.json", "d52d4631b42c3c6370bc545e369611327ff6e1c8"),
    # License identifiers evolve independently of the BOM format; pin the official
    # SPDX 3.29 enumeration, not the stale license list shipped with the 1.6 tag.
    "spdx.schema.json": ("CycloneDX/specification/db25df607d029f886f1006496392e7b2c7f28f05/schema/spdx.schema.json", "566c4a32518c60778e55a56ccf71bf781320b279"),
    "jsf-0.82.schema.json": ("CycloneDX/specification/1.6/schema/jsf-0.82.schema.json", "f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_digest(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()


def fetch(url: str, limit: int = 100 * 1024 * 1024) -> bytes:
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                if urllib.parse.urlsplit(response.url).scheme != "https":
                    raise ValueError("non-HTTPS tool download redirect")
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("tool download too large")
            return data
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def bootstrap(directory: Path) -> None:
    if directory.exists():
        raise ValueError("tool directory already exists; use a fresh directory")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch not in SYFT_ARCHIVES:
        raise ValueError("SBOM bootstrap supports Linux amd64/arm64 runners")
    directory.mkdir(parents=True)
    (directory / "schemas").mkdir()
    name = f"syft_{SYFT_VERSION}_linux_{arch}.tar.gz"
    data = fetch(f"https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}/{name}")
    if digest(data) != SYFT_ARCHIVES[arch]:
        raise ValueError("Syft archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.name == "syft"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 256 * 1024 * 1024:
            raise ValueError("invalid Syft archive binary")
        binary = archive.extractfile(members[0]).read()
    (directory / "syft").write_bytes(binary)
    (directory / "syft").chmod(0o755)
    files = {"syft": digest(binary)}
    for name, (source, expected) in SCHEMAS.items():
        data = fetch("https://raw.githubusercontent.com/" + source, 2 * 1024 * 1024)
        if blob_digest(data) != expected:
            raise ValueError(f"schema checksum mismatch: {name}")
        json.loads(data)
        (directory / "schemas" / name).write_bytes(data)
        files["schemas/" + name] = digest(data)
    # Explicit config prevents accidental local ~/.syft.yaml discovery. No skip lists.
    (directory / "syft.yaml").write_text("check-for-app-update: false\n")
    files["syft.yaml"] = digest((directory / "syft.yaml").read_bytes())
    receipt = {"syft_version": SYFT_VERSION, "archive_sha256": SYFT_ARCHIVES[arch], "architecture": arch,
               "files": files, "schema_git_blobs": {n: v[1] for n, v in SCHEMAS.items()}}
    (directory / "toolchain.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def bind_container_identity(native: dict, spdx: dict, cdx: dict) -> dict:
    """Fill Syft's omitted CycloneDX image PURL only after matching source evidence.

    Syft 1.52 emits an OCI PURL for the SPDX document root but omits it from
    CycloneDX metadata.component. Do not discard that identity to make the
    format-parity check pass, or copy arbitrary missing dependency identities.
    """
    if native.get("source", {}).get("type") != "image":
        return cdx
    described = {r.get("relatedSpdxElement") for r in spdx.get("relationships", [])
                 if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"}
    roots = [p for p in spdx.get("packages", []) if p.get("SPDXID") in described]
    if len(roots) != 1 or roots[0].get("primaryPackagePurpose") != "CONTAINER":
        raise ValueError("expected exactly one described SPDX container root")
    root = roots[0]
    component = cdx.get("metadata", {}).get("component", {})
    image_id = native["source"].get("metadata", {}).get("manifestDigest")
    if (component.get("type") != "container" or component.get("name") != root.get("name")
            or not image_id or root.get("versionInfo") != image_id or component.get("version") != image_id):
        raise ValueError("SPDX/CycloneDX container identity differs from scanned image")
    purls = {r.get("referenceLocator") for r in root.get("externalRefs", []) if r.get("referenceType") == "purl"}
    if len(purls) != 1 or not isinstance(next(iter(purls)), str) or not next(iter(purls)).startswith("pkg:oci/"):
        raise ValueError("missing/unexpected SPDX container PURL")
    purl = next(iter(purls))
    if component.get("purl") not in (None, purl):
        raise ValueError("conflicting CycloneDX container PURL")
    result = copy.deepcopy(cdx)
    result["metadata"]["component"]["purl"] = purl
    result["metadata"]["component"].setdefault("properties", []).append({
        "name": "shakerscan:container-purl-source", "value": "matched SPDX document root and Syft manifest digest"})
    return result


class Toolchain:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        self.receipt = json.loads((directory / "toolchain.json").read_text())
        expected_names = {"syft", "syft.yaml"} | {"schemas/" + name for name in SCHEMAS}
        if set(self.receipt["files"]) != expected_names or self.receipt["syft_version"] != SYFT_VERSION:
            raise ValueError("invalid SBOM toolchain receipt")
        for name, expected in self.receipt["files"].items():
            path = directory / name
            if path.is_symlink() or digest(path.read_bytes()) != expected:
                raise ValueError(f"SBOM toolchain changed: {name}")
        for name, (_, expected) in SCHEMAS.items():
            if blob_digest((directory / "schemas" / name).read_bytes()) != expected:
                raise ValueError(f"untrusted schema: {name}")
        if self.receipt["archive_sha256"] != SYFT_ARCHIVES.get(self.receipt["architecture"]):
            raise ValueError("untrusted Syft release")
        version = json.loads(self.run(["version", "-o", "json"], timeout=30))
        if version.get("version") != SYFT_VERSION:
            raise ValueError("unexpected Syft binary version")

    def run(self, arguments: list[str], timeout: int = 900) -> bytes:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SYFT_")}
        env.update(SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_JAVA_USE_NETWORK="false",
                   SYFT_GOLANG_SEARCH_REMOTE_LICENSES="false")
        command = [str(self.directory / "syft"), *arguments, "--config", str(self.directory / "syft.yaml")]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
        if result.returncode:
            # Do not print registry credentials, configuration, or untrusted image metadata.
            raise ValueError(f"Syft {arguments[0]} failed with exit code {result.returncode}")
        return result.stdout

    def scan(self, source: str, work: Path) -> tuple[dict, dict, dict]:
        work.mkdir()
        self.run(["scan", source, "--scope", "squashed",
                  "-o", f"syft-json={work / 'native.json'}",
                  "-o", f"spdx-json@2.3={work / 'spdx.json'}",
                  "-o", f"cyclonedx-json@1.6={work / 'cdx.json'}"])
        native, spdx, cdx = (json.loads((work / name).read_bytes()) for name in ("native.json", "spdx.json", "cdx.json"))
        return native, spdx, bind_container_identity(native, spdx, cdx)

    def convert(self, source: Path) -> dict:
        return json.loads(self.run(["convert", str(source), "-o", "cyclonedx-json@1.6"]))

    def validate(self, document: dict) -> None:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
        schemas = {name: json.loads((self.directory / "schemas" / name).read_bytes()) for name in SCHEMAS}
        resources = []
        for name, schema in schemas.items():
            resource = Resource.from_contents(schema, default_specification=DRAFT7)
            resources.extend([(schema["$id"], resource), ("http://cyclonedx.org/schema/" + name, resource)])
        # Registry has no retrieval callback: unknown external references fail, never fetch.
        registry = Registry().with_resources(resources)
        if document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == "1.6":
            schema = schemas["bom-1.6.schema.json"]
        elif document.get("spdxVersion") in ("SPDX-2.2", "SPDX-2.3"):
            schema = schemas["spdx-" + document["spdxVersion"][5:] + ".json"]
        else:
            raise ValueError("unsupported SBOM schema")
        Draft7Validator(schema, registry=registry).validate(document)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bootstrap(args.output)
