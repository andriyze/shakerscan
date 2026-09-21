#!/usr/bin/env python3
"""Stage-one release SBOMs, generated from immutable images or built client archives.

Python standard library only. No artifact is installed, imported, or executed. Engine
export needs Docker Buildx; image provenance is verified by release.yml before export.
This is an intentionally scoped inventory, not a completeness or vulnerability claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

SCHEMA = "shakerscan-release-sbom/v1"
PLATFORMS = ("linux/amd64", "linux/arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?\Z")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 10000
INDEX = "sbom-index.json"
SUMS = "sbom-SHA256SUMS"
README = "sbom-README.md"
BUNDLE = "sbom-index.sigstore.json"
ENGINE_LIMITS = [
    "Existing BuildKit final-image SPDX catalogs only; no rebuild or new filesystem scan.",
    "Build-only dependencies, bundled/minified JavaScript, vendored/native code, templates and data may be incomplete.",
    "Supporting-service images (PostgreSQL, Redis, MinIO, Caddy), the Firecracker guest and host software are not inventoried in stage one.",
    "Package presence is not vulnerability applicability; no components are filtered by severity or waiver.",
]
CLIENT_LIMITS = [
    "File-level inventory of the actual wheel and sdist, including packaged CLI/MCP modules and agent kit.",
    "No third-party runtime dependencies are declared; generation fails if Requires-Dist becomes nonempty.",
    "Host Python, its standard library, pip/uv/pipx/Homebrew, build tools and externally launched agents are not bundled and are excluded.",
    "File hashes do not establish transitive composition of vendored code or absence of vulnerabilities.",
]


class SBOMError(ValueError):
    """Invalid or incomplete release evidence; publication must stop."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise SBOMError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"expected JSON object: {path.name}")
    return value


def safe_name(name: str) -> str:
    require(isinstance(name, str) and bool(name), "empty/non-string path")
    require(not any(ord(c) < 32 for c in name) and "\\" not in name, "unsafe path characters")
    path = PurePosixPath(name)
    require(not path.is_absolute() and all(p not in ("", ".", "..") for p in name.split("/")), "unsafe archive/bundle path")
    return name


def validate_spdx(document: dict) -> None:
    """Validate release-critical structure, not every optional SPDX schema property."""
    require(isinstance(document, dict), "missing SPDX object")
    require(document.get("spdxVersion") in ("SPDX-2.2", "SPDX-2.3"), "unsupported SPDX version")
    require(document.get("SPDXID") == "SPDXRef-DOCUMENT", "missing SPDX document ID")
    require(document.get("dataLicense") == "CC0-1.0", "invalid SPDX data license")
    require(bool(document.get("name")) and bool(document.get("documentNamespace")), "missing SPDX identity")
    creation = document.get("creationInfo", {})
    require(isinstance(creation, dict) and bool(creation.get("created")), "missing SPDX creation time")
    creators = creation.get("creators")
    require(isinstance(creators, list) and creators and all(isinstance(c, str) and c for c in creators), "missing SPDX creators")
    packages = document.get("packages")
    require(isinstance(packages, list) and packages, "empty SPDX package inventory")
    ids = {"SPDXRef-DOCUMENT"}
    for collection in (packages, document.get("files", [])):
        require(isinstance(collection, list), "invalid SPDX elements")
        for element in collection:
            require(isinstance(element, dict), "invalid SPDX element")
            ident = element.get("SPDXID", "")
            require(isinstance(ident, str) and re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", ident), "invalid SPDX element ID")
            require(ident not in ids, "duplicate SPDX element ID")
            ids.add(ident)
    for package in packages:
        require(isinstance(package.get("name"), str) and package["name"], "unnamed SPDX package")
        require(bool(package.get("downloadLocation")), "missing SPDX download location")
        # A catalog can legitimately report an unknown version. Preserve it and count it.
    relationships = document.get("relationships")
    require(isinstance(relationships, list) and relationships, "missing SPDX relationships")
    external = {d.get("externalDocumentId") for d in document.get("externalDocumentRefs", [])}
    for relation in relationships:
        require(isinstance(relation, dict) and bool(relation.get("relationshipType")), "invalid SPDX relationship")
        for key in ("spdxElementId", "relatedSpdxElement"):
            ref = relation.get(key, "")
            require(isinstance(ref, str) and (ref in ids or ref in ("NONE", "NOASSERTION") or (":" in ref and ref.split(":", 1)[0] in external)), "dangling SPDX relationship")
    require(any(r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES" for r in relationships), "SPDX document does not describe a subject")


def run_json(args: list[str]) -> dict:
    for attempt in range(3):
        try:
            result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            value = json.loads(result.stdout)
            require(isinstance(value, dict), "tool returned no JSON object")
            return value
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise SBOMError(f"command failed after three attempts: {' '.join(args[:4])}") from None
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def canonical_platform(value: str) -> str:
    aliases = {"linux/amd64": "linux/amd64", "linux/amd64/v1": "linux/amd64",
               "linux/arm64": "linux/arm64", "linux/arm64/v8": "linux/arm64"}
    require(value in aliases, f"unexpected image platform: {value}")
    return aliases[value]


def platform_digests(index: dict) -> dict[str, str]:
    require(index.get("schemaVersion") == 2 and isinstance(index.get("manifests"), list), "image is not a multi-platform index")
    result = {}
    attestations = set()
    for entry in index["manifests"]:
        annotations = entry.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            attestations.add(annotations.get("vnd.docker.reference.digest"))
            continue
        platform = entry.get("platform", {})
        key = f"{platform.get('os')}/{platform.get('architecture')}"
        if platform.get("variant"):
            key += "/" + platform["variant"]
        key = canonical_platform(key)
        require(key not in result, f"duplicate image platform: {key}")
        digest = entry.get("digest", "")
        require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid platform digest")
        result[key] = digest
    require(set(result) == set(PLATFORMS), "missing amd64 or arm64 image")
    require(set(result.values()) <= attestations, "missing platform-bound BuildKit attestations")
    return result


def engine_documents(receipt: dict, inventory: dict, version: str, source_sha: str, inspect=run_json) -> tuple[dict, list]:
    require(receipt.get("schema_version") == "shakerscan-release-candidate/v2", "expected certified v2 receipt")
    require(receipt.get("version") == version and receipt.get("candidate_sha") == source_sha, "receipt version/source mismatch")
    certification = receipt.get("certification", {})
    require(certification.get("status") == "pass", "uncertified receipt")
    require(certification.get("source_sha") == source_sha and certification.get("images") == receipt.get("images"), "certification binding mismatch")
    require(receipt.get("provenance", {}).get("verified") is True, "receipt has no verified build provenance")
    require(inventory.get("schema_version") == "shakerscan-release-images/v1", "invalid image inventory")
    images = inventory.get("images")
    require(isinstance(images, list) and images, "empty image inventory")
    keys = [image.get("key") for image in images]
    require(all(isinstance(k, str) and re.fullmatch(r"[a-z][a-z0-9_]*", k) for k in keys), "invalid image key")
    require(len(keys) == len(set(keys)) and set(keys) == set(receipt.get("images", {})), "receipt/image inventory mismatch")
    documents, artifacts = {}, []
    for image in images:
        key, repository = image["key"], image.get("repository", "")
        require(isinstance(repository, str) and re.fullmatch(r"shakerscan/[a-z0-9][a-z0-9-]*", repository), "unexpected image repository")
        digest = receipt["images"][key]
        require(isinstance(digest, str) and DIGEST.fullmatch(digest), "mutable/invalid image digest")
        reference = f"docker.io/{repository}@{digest}"
        command = ["docker", "buildx", "imagetools", "inspect", reference]
        platforms = platform_digests(inspect(command + ["--raw"]))
        # Buildx selects the SPDX predicate via its attestation descriptor and platform.
        # Both queries use the immutable index, never :latest or a mutable version tag.
        catalogs = inspect(command + ["--format", "{{ json .SBOM }}"])
        normalized = {}
        for label, catalog in catalogs.items():
            platform = canonical_platform(label)
            require(platform not in normalized, "duplicate platform SBOM")
            normalized[platform] = catalog
        require(set(normalized) == set(PLATFORMS), "missing/unexpected platform SBOM")
        for platform in PLATFORMS:
            catalog = normalized[platform]
            require(isinstance(catalog, dict), "missing platform SBOM object")
            document = catalog.get("SPDX")
            validate_spdx(document)
            name = f"shakerscan-{version}-{key.replace('_', '-')}-{platform.replace('/', '-')}.spdx.json"
            documents[name] = json_bytes(document)
            artifacts.append({
                "image": key, "image_reference": reference, "index_digest": digest,
                "platform": platform, "platform_digest": platforms[platform],
                "sbom": name, "sbom_sha256": sha256(documents[name]),
                "sbom_generators": document["creationInfo"]["creators"],
                "package_count": len(document["packages"]),
                "packages_without_version": sum(not p.get("versionInfo") for p in document["packages"]),
                "scope": "buildkit-final-image-catalog",
            })
    return documents, artifacts


def archive_files(path: Path) -> dict[str, bytes]:
    """Read bounded archive members without extracting or executing any of them."""
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_ARCHIVE_BYTES, "invalid/oversized client archive")
    files, total = {}, 0

    def add(name: str, size: int, read) -> None:
        nonlocal total
        safe_name(name)
        require(name not in files and len(files) < MAX_MEMBERS, "duplicate/too many archive files")
        total += size
        require(0 <= size <= MAX_ARCHIVE_BYTES and total <= MAX_ARCHIVE_BYTES, "oversized archive contents")
        data = read()
        require(len(data) == size, "archive member size mismatch")
        files[name] = data

    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            require(len(archive.infolist()) <= MAX_MEMBERS, "too many archive members")
            for member in archive.infolist():
                safe_name(member.filename.rstrip("/"))
                require(not stat.S_ISLNK(member.external_attr >> 16), "archive symlink is not permitted")
                if not member.is_dir():
                    add(member.filename, member.file_size, lambda m=member: archive.read(m))
    else:
        with tarfile.open(path, "r:gz") as archive:
            count = 0
            for member in archive:
                count += 1
                require(count <= MAX_MEMBERS, "too many archive members")
                safe_name(member.name.rstrip("/"))
                require(member.isdir() or member.isfile(), "archive links/devices are not permitted")
                if member.isfile():
                    def read(m=member):
                        with archive.extractfile(m) as stream:
                            return stream.read(MAX_ARCHIVE_BYTES + 1)
                    add(member.name, member.size, read)
    require(bool(files), "empty client archive")
    return files


def client_document(path: Path, version: str, source_sha: str, repository: str, created: str) -> tuple[dict, dict, dict]:
    files = archive_files(path)
    wheel = path.name.endswith(".whl")
    metadata_path = f"shakerscan-{version}.dist-info/METADATA" if wheel else f"shakerscan-{version}/PKG-INFO"
    require(metadata_path in files, "missing expected client package metadata")
    metadata = BytesParser().parsebytes(files[metadata_path])
    require(metadata.get("Name") == "shakerscan" and metadata.get("Version") == version, "client package identity mismatch")
    require(not metadata.get_all("Requires-Dist"), "client now declares runtime dependencies: extend stage-one SBOM resolution before publishing")
    require(bool(metadata.get("Requires-Python")), "missing client Python requirement")
    prefix = "shakerscan/" if wheel else f"shakerscan-{version}/src/shakerscan/"
    packaged = {name[len(prefix):]: sha256(data) for name, data in files.items() if name.startswith(prefix)}
    for name in ("__init__.py", "_mcp.py", "_v2_cli.py", "_api_cli.py", "_scan_cli.py", "_kit/AGENTS.md", "_kit/CLAUDE.md"):
        require(name in packaged, f"client is missing packaged {name}")
    for directory in ("_kit/skills/", "_kit/claude/"):
        require(any(n.startswith(directory) for n in packaged), f"client is missing {directory}")
    digest = sha256(path.read_bytes())
    root = "SPDXRef-ShakerScanClient"
    entries, relationships, file_sha1s = [], [], []
    for name, data in sorted(files.items()):
        ident = "SPDXRef-File-" + sha256(name.encode())[:32]
        file_sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        file_sha1s.append(file_sha1)
        entries.append({"SPDXID": ident, "fileName": "./" + name,
                        "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(data)}, {"algorithm": "SHA1", "checksumValue": file_sha1}],
                        "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION"})
        relationships.append({"spdxElementId": root, "relationshipType": "CONTAINS", "relatedSpdxElement": ident})
    document = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
        "name": path.name, "documentNamespace": f"https://github.com/{repository}/sbom/{source_sha}/{digest}",
        "creationInfo": {"created": created, "creators": ["Organization: ShakerScan", "Tool: shakerscan-release-sbom-1"]},
        "packages": [{"SPDXID": root, "name": "shakerscan", "versionInfo": version,
                      "downloadLocation": f"https://github.com/{repository}/releases/download/client-v{version}/{path.name}",
                      "filesAnalyzed": True, "licenseConcluded": "NOASSERTION", "licenseInfoFromFiles": ["NOASSERTION"],
                      "licenseDeclared": metadata.get("License-Expression", "NOASSERTION"),
                      "copyrightText": "NOASSERTION", "supplier": "Organization: ShakerScan",
                      "sourceInfo": f"Source commit {source_sha}; Requires-Python: {metadata['Requires-Python']}; host interpreter is not bundled.",
                      "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                      "packageVerificationCode": {"packageVerificationCodeValue": hashlib.sha1("".join(sorted(file_sha1s)).encode(), usedforsecurity=False).hexdigest()},
                      "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:pypi/shakerscan@{version}"}]}],
        "files": entries,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}] + relationships,
    }
    validate_spdx(document)
    artifact = {"file": path.name, "sha256": digest, "distribution": "wheel" if wheel else "sdist",
                "requires_python": metadata["Requires-Python"], "declared_runtime_dependencies": [],
                "file_count": len(files), "scope": "client-archive-files"}
    return document, artifact, packaged


def client_documents(dist: Path, version: str, source_sha: str, repository: str, created: str) -> tuple[dict, list]:
    wheels, sdists = sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))
    require(len(wheels) == 1 and len(sdists) == 1, "expected exactly one wheel and one sdist")
    documents, artifacts, package_trees = {}, [], []
    for path in wheels + sdists:
        require(path.name == (f"shakerscan-{version}-py3-none-any.whl" if path.suffix == ".whl" else f"shakerscan-{version}.tar.gz"), "unexpected client archive name")
        document, artifact, packaged = client_document(path, version, source_sha, repository, created)
        name = path.name + ".spdx.json"
        documents[name] = json_bytes(document)
        artifact.update(sbom=name, sbom_sha256=sha256(documents[name]), sbom_generators=document["creationInfo"]["creators"])
        artifacts.append(artifact)
        package_trees.append(packaged)
    require(package_trees[0] == package_trees[1], "wheel/sdist packaged modules or agent kit differ")
    return documents, artifacts


def write_bundle(output: Path, documents: dict[str, bytes], artifacts: list, *, kind: str, version: str,
                 source_sha: str, repository: str, created: str, generator_source_sha: str) -> None:
    require(not output.exists(), "output directory already exists; use a fresh directory")
    limits = ENGINE_LIMITS if kind == "engine" else CLIENT_LIMITS
    prefix = "v" if kind == "engine" else "client-v"
    files = dict(documents)
    files[README] = ("# ShakerScan release SBOMs - stage one\n\n" + "\n".join("- " + s for s in limits) +
                    "\n\nThe signed sbom-index.json binds source/artifact identities to SBOM hashes. "
                    "Verify its GitHub attestation first, then run scripts/release_sbom.py verify. "
                    "Checksums alone are not authenticity. sbom-index.sigstore.json is the detached "
                    "attestation bundle and is not included in sbom-SHA256SUMS.\n\n"
                    "See docs/sbom.md for coverage, verification and backfill instructions.\n").encode()
    index = {"schema_version": SCHEMA, "kind": kind, "version": version, "release_tag": prefix + version,
             "repository": repository, "source_sha": source_sha, "generated_at": created,
             "generator": {"name": "shakerscan-release-sbom", "version": "1", "source_sha": generator_source_sha},
             "coverage": {"stage": 1, "completeness": "partial", "limitations": limits}, "artifacts": artifacts,
             "files": {name: sha256(data) for name, data in sorted(files.items())}}
    files[INDEX] = json_bytes(index)
    files[SUMS] = "".join(f"{sha256(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        for name, data in files.items():
            require(safe_name(name) == Path(name).name, "nested output filename")
            (stage / name).write_bytes(data)
        verify_bundle(stage)
        stage.rename(output)


def verify_bundle(directory: Path, dist: Path | None = None) -> dict:
    """Check inventory integrity. Signature policy remains explicit in the caller/docs."""
    require(not (directory / INDEX).is_symlink(), "index must not be a symlink")
    index = load_json(directory / INDEX)
    require(index.get("schema_version") == SCHEMA, "unsupported SBOM index schema")
    require(index.get("kind") in ("engine", "client"), "invalid SBOM kind")
    require(isinstance(index.get("source_sha"), str) and SHA.fullmatch(index["source_sha"]), "invalid source commit")
    require(isinstance(index.get("version"), str) and VERSION.fullmatch(index["version"]), "invalid indexed version")
    prefix = "v" if index["kind"] == "engine" else "client-v"
    require(index.get("release_tag") == prefix + index["version"], "release tag/version mismatch")
    files = index.get("files")
    require(isinstance(files, dict) and files, "empty SBOM bundle")
    require(README in files and INDEX not in files and SUMS not in files and BUNDLE not in files, "invalid bundle file set")
    for name, expected in files.items():
        require(safe_name(name) == Path(name).name, "unsafe bundle filename")
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "missing/symlink bundle file")
        require(sha256(path.read_bytes()) == expected, f"bundle hash mismatch: {name}")
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "empty artifact inventory")
    sboms = set()
    subjects = set()
    for artifact in artifacts:
        name = artifact.get("sbom")
        require(name in files and name.endswith(".spdx.json") and name not in sboms, "missing/duplicate artifact SBOM")
        require(artifact.get("sbom_sha256") == files[name], "artifact/SBOM hash mismatch")
        sboms.add(name)
        validate_spdx(load_json(directory / name))
        if index["kind"] == "engine":
            subject = (artifact.get("image"), artifact.get("platform"))
            require(subject[1] in PLATFORMS, "invalid artifact platform")
            for key in ("index_digest", "platform_digest"):
                require(isinstance(artifact.get(key), str) and DIGEST.fullmatch(artifact[key]), "invalid artifact digest")
            require(artifact.get("image_reference", "").endswith("@" + artifact["index_digest"]), "artifact digest mismatch")
        else:
            subject = artifact.get("distribution")
            require(subject in ("wheel", "sdist"), "invalid client distribution")
            name = safe_name(artifact.get("file", ""))
            require(name == Path(name).name, "unsafe client filename")
            if dist is not None:
                path = dist / name
                require(path.is_file() and not path.is_symlink(), "missing client artifact")
                require(sha256(path.read_bytes()) == artifact.get("sha256"), "client artifact hash mismatch")
        require(subject not in subjects, "duplicate artifact subject")
        subjects.add(subject)
    require(sboms == {n for n in files if n.endswith(".spdx.json")}, "unindexed SBOM")
    if index["kind"] == "client":
        require(subjects == {"wheel", "sdist"}, "missing client distribution")
    else:
        for image, _ in subjects:
            require(all((image, p) in subjects for p in PLATFORMS), "incomplete image platform inventory")
    hashes = {**files, INDEX: sha256((directory / INDEX).read_bytes())}
    expected_sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items()))
    require(not (directory / SUMS).is_symlink() and (directory / SUMS).read_text() == expected_sums, "checksum manifest mismatch")
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for kind in ("engine", "client"):
        sub = commands.add_parser(kind)
        sub.add_argument("--version", required=True)
        sub.add_argument("--source-sha", required=True)
        sub.add_argument("--generator-source-sha", required=True)
        sub.add_argument("--repository", default="andriyze/shakerscan")
        sub.add_argument("--created", default=None)
        sub.add_argument("--output", type=Path, required=True)
        if kind == "engine":
            sub.add_argument("--receipt", type=Path, required=True)
            sub.add_argument("--inventory", type=Path, default=Path("install/release-images.json"))
        else:
            sub.add_argument("--dist", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--dist", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            verify_bundle(args.directory, args.dist)
            print("SBOM integrity verified; verify the index signature separately (docs/sbom.md).")
            return 0
        require(VERSION.fullmatch(args.version), "invalid release version")
        require(SHA.fullmatch(args.source_sha) and SHA.fullmatch(args.generator_source_sha), "expected exact source commits")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository), "invalid repository")
        created = args.created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        require(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created), "creation time must be UTC RFC3339")
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
        if args.command == "engine":
            documents, artifacts = engine_documents(load_json(args.receipt), load_json(args.inventory), args.version, args.source_sha)
        else:
            documents, artifacts = client_documents(args.dist, args.version, args.source_sha, args.repository, created)
        write_bundle(args.output, documents, artifacts, kind=args.command, version=args.version, source_sha=args.source_sha,
                     repository=args.repository, created=created, generator_source_sha=args.generator_source_sha)
        print(f"Wrote {len(artifacts)} artifact SBOMs to {args.output}")
        return 0
    except (SBOMError, OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"release SBOM: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
