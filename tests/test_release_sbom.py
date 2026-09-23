"""Offline SBOM contracts. Run with unittest; no Docker, registry or PyPI needed."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_sbom", ROOT / "scripts/release_sbom.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
CREATED = "2026-09-21T16:00:00Z"
VERSION = "0.6.0"


def spdx():
    return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
            "name": "fixture", "documentNamespace": "https://example.test/sbom/fixture",
            "creationInfo": {"created": CREATED, "creators": ["Tool: syft-fixture"]},
            "packages": [{"SPDXID": "SPDXRef-package", "name": "example", "versionInfo": "1.0", "downloadLocation": "NOASSERTION"}],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-package"}]}


def image_index():
    result = {"schemaVersion": 2, "manifests": []}
    for arch, char in (("amd64", "c"), ("arm64", "d")):
        digest = "sha256:" + char * 64
        result["manifests"].append({"platform": {"os": "linux", "architecture": arch}, "digest": digest})
        result["manifests"].append({"platform": {"os": "unknown", "architecture": "unknown"},
                                    "digest": "sha256:" + "e" * 64,
                                    "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": digest}})
    return result


def inputs():
    keys = ("scanner", "api", "ui", "signer", "model_intake")
    images = {key: DIGEST for key in keys}
    receipt = {"schema_version": "shakerscan-release-candidate/v2", "version": "2.4.0", "candidate_sha": SHA,
               "images": images, "provenance": {"verified": True},
               "certification": {"status": "pass", "source_sha": SHA, "images": images.copy()}}
    inventory = {"schema_version": "shakerscan-release-images/v1", "images": [
        {"key": key, "repository": "shakerscan/shakerscan-" + key.replace("_", "-")} for key in keys]}
    return receipt, inventory


def inspect(args):
    return image_index() if args[-1] == "--raw" else {p: {"SPDX": spdx()} for p in sbom.PLATFORMS}


def make_client(directory, *, requires_dist="", mutate=None, omit=None):
    directory.mkdir(exist_ok=True)
    metadata = (f"Metadata-Version: 2.4\nName: shakerscan\nVersion: {VERSION}\nRequires-Python: >=3.10\n"
                f"License-Expression: AGPL-3.0-only\n{requires_dist}\n").encode()
    names = ["__init__.py", "_mcp.py", "_v2_cli.py", "_api_cli.py", "_scan_cli.py", "_kit/AGENTS.md",
             "_kit/skills/example.md", "_kit/claude/settings.json"]
    package = {name: f"fixture: {name}\n".encode() for name in names if name != omit}
    wheel = directory / f"shakerscan-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"shakerscan-{VERSION}.dist-info/METADATA", metadata)
        for name, data in package.items():
            archive.writestr("shakerscan/" + name, data)
    sdist = directory / f"shakerscan-{VERSION}.tar.gz"
    files = {f"shakerscan-{VERSION}/PKG-INFO": metadata}
    files.update({f"shakerscan-{VERSION}/src/shakerscan/{n}": d for n, d in package.items()})
    if mutate:
        files[f"shakerscan-{VERSION}/src/shakerscan/{mutate}"] = b"different sdist content"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return wheel, sdist


class EngineTests(unittest.TestCase):
    def export(self, mock=inspect):
        return sbom.engine_documents(*inputs(), "2.4.0", SHA, inspect=mock)

    def test_all_five_images_and_two_architectures_are_digest_bound(self):
        calls = []
        def capture(args):
            calls.append(args)
            return inspect(args)
        docs, artifacts = self.export(capture)
        self.assertEqual(len(docs), 10)
        self.assertEqual(len(artifacts), 10)
        self.assertEqual(len(calls), 10)
        for call in calls:
            self.assertTrue(call[4].endswith("@" + DIGEST))
            self.assertNotIn(":latest", call[4])
        for artifact in artifacts:
            self.assertEqual(artifact["sbom_sha256"], sbom.sha256(docs[artifact["sbom"]]))
            self.assertIn(artifact["platform"], sbom.PLATFORMS)
            self.assertEqual(artifact["sbom_generators"], ["Tool: syft-fixture"])

    def test_missing_platform_stops_export(self):
        index = image_index()
        index["manifests"] = index["manifests"][:2]
        with self.assertRaisesRegex(sbom.SBOMError, "missing amd64 or arm64"):
            sbom.platform_digests(index)

    def test_duplicate_platform_stops_export(self):
        index = image_index()
        index["manifests"].append(index["manifests"][0])
        with self.assertRaisesRegex(sbom.SBOMError, "duplicate"):
            sbom.platform_digests(index)

    def test_wrong_attestation_binding_stops_export(self):
        index = image_index()
        index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = DIGEST
        with self.assertRaisesRegex(sbom.SBOMError, "platform-bound"):
            sbom.platform_digests(index)

    def test_missing_or_null_sbom_stops_export(self):
        for value in (None, {}):
            with self.subTest(value=value), self.assertRaises(sbom.SBOMError):
                self.export(lambda args: image_index() if args[-1] == "--raw" else {p: {"SPDX": value} for p in sbom.PLATFORMS})

    def test_mutable_or_wrong_release_receipt_rejected(self):
        for key, value in (("candidate_sha", "f" * 40), ("version", "2.3.9"), ("images", {"scanner": "latest"})):
            receipt, inventory = inputs()
            receipt[key] = value
            with self.subTest(key=key), self.assertRaises(sbom.SBOMError):
                sbom.engine_documents(receipt, inventory, "2.4.0", SHA, inspect=inspect)

    def test_missing_inventory_image_rejected(self):
        receipt, inventory = inputs()
        inventory["images"].pop()
        with self.assertRaisesRegex(sbom.SBOMError, "inventory mismatch"):
            sbom.engine_documents(receipt, inventory, "2.4.0", SHA, inspect=inspect)

    def test_repository_injection_rejected(self):
        receipt, inventory = inputs()
        inventory["images"][0]["repository"] = "--output=/tmp/anything"
        with self.assertRaisesRegex(sbom.SBOMError, "repository"):
            sbom.engine_documents(receipt, inventory, "2.4.0", SHA, inspect=inspect)

    def test_arm64_v8_spelling_supported(self):
        def variant(args):
            if args[-1] == "--raw":
                value = image_index()
                value["manifests"][2]["platform"]["variant"] = "v8"
                return value
            return {"linux/amd64": {"SPDX": spdx()}, "linux/arm64/v8": {"SPDX": spdx()}}
        self.assertEqual(len(self.export(variant)[0]), 10)

    def test_unknown_package_versions_are_retained_not_filtered(self):
        def unknown(args):
            value = inspect(args)
            if args[-1] != "--raw":
                for catalog in value.values():
                    catalog["SPDX"]["packages"][0].pop("versionInfo")
            return value
        docs, artifacts = self.export(unknown)
        self.assertTrue(all(a["packages_without_version"] == 1 for a in artifacts))
        self.assertTrue(all(json.loads(d)["packages"][0]["name"] == "example" for d in docs.values()))

    def test_registry_command_has_timeout_and_bounded_retry(self):
        failure = subprocess.CalledProcessError(1, ["docker"])
        with patch.object(sbom.subprocess, "run", side_effect=failure) as run, patch.object(sbom.time, "sleep"):
            with self.assertRaisesRegex(sbom.SBOMError, "three attempts"):
                sbom.run_json(["docker", "buildx", "imagetools", "inspect", "example"])
            self.assertEqual(run.call_count, 3)
            self.assertEqual(run.call_args.kwargs["timeout"], 180)
            self.assertNotIn("shell", run.call_args.kwargs)


class SPDXTests(unittest.TestCase):
    def test_empty_inventory_rejected(self):
        value = spdx()
        value["packages"] = []
        with self.assertRaisesRegex(sbom.SBOMError, "empty"):
            sbom.validate_spdx(value)

    def test_duplicate_ids_rejected(self):
        value = spdx()
        value["packages"].append(value["packages"][0].copy())
        with self.assertRaisesRegex(sbom.SBOMError, "duplicate"):
            sbom.validate_spdx(value)

    def test_dangling_relationship_rejected(self):
        value = spdx()
        value["relationships"][0]["relatedSpdxElement"] = "SPDXRef-missing"
        with self.assertRaisesRegex(sbom.SBOMError, "dangling"):
            sbom.validate_spdx(value)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"

    def export(self):
        return sbom.client_documents(self.dist, VERSION, SHA, "andriyze/shakerscan", CREATED)

    def bundle(self):
        docs, artifacts = self.export()
        output = self.root / "sbom"
        sbom.write_bundle(output, docs, artifacts, kind="client", version=VERSION, source_sha=SHA,
                          repository="andriyze/shakerscan", created=CREATED, generator_source_sha=SHA)
        return output

    def test_archive_inventory_includes_vendored_modules_and_kit(self):
        wheel, _ = make_client(self.dist)
        docs, artifacts = self.export()
        doc = json.loads(docs[wheel.name + ".spdx.json"])
        names = {f["fileName"] for f in doc["files"]}
        self.assertIn("./shakerscan/_mcp.py", names)
        self.assertIn("./shakerscan/_kit/skills/example.md", names)
        self.assertEqual(artifacts[0]["sha256"], sbom.sha256(wheel.read_bytes()))
        self.assertEqual(len(doc["packages"]), 1)
        self.assertEqual(artifacts[0]["requires_python"], ">=3.10")
        self.assertEqual(artifacts[0]["declared_runtime_dependencies"], [])
        sha1s = sorted(next(h["checksumValue"] for h in f["checksums"] if h["algorithm"] == "SHA1") for f in doc["files"])
        expected = hashlib.sha1("".join(sha1s).encode(), usedforsecurity=False).hexdigest()
        self.assertEqual(doc["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"], expected)

    def test_future_runtime_dependencies_fail_closed(self):
        make_client(self.dist, requires_dist="Requires-Dist: requests>=2\n")
        with self.assertRaisesRegex(sbom.SBOMError, "runtime dependencies"):
            self.export()

    def test_missing_vendored_module_rejected(self):
        make_client(self.dist, omit="_api_cli.py")
        with self.assertRaisesRegex(sbom.SBOMError, "missing packaged"):
            self.export()

    def test_wheel_sdist_kit_drift_rejected(self):
        make_client(self.dist, mutate="_kit/skills/example.md")
        with self.assertRaisesRegex(sbom.SBOMError, "differ"):
            self.export()

    def test_multiple_wheels_rejected(self):
        wheel, _ = make_client(self.dist)
        (self.dist / "extra.whl").write_bytes(wheel.read_bytes())
        with self.assertRaisesRegex(sbom.SBOMError, "exactly one"):
            self.export()

    def test_path_traversal_rejected_without_extraction(self):
        wheel, _ = make_client(self.dist)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("../outside", b"no")
        with self.assertRaisesRegex(sbom.SBOMError, "unsafe"):
            self.export()
        self.assertFalse((self.root / "outside").exists())

    def test_symlink_rejected(self):
        path = self.root / "bad.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        with self.assertRaisesRegex(sbom.SBOMError, "links/devices"):
            sbom.archive_files(path)

    def test_oversized_archive_rejected(self):
        make_client(self.dist)
        with patch.object(sbom, "MAX_ARCHIVE_BYTES", 10), self.assertRaisesRegex(sbom.SBOMError, "oversized"):
            self.export()

    def test_valid_bundle_and_distribution_hashes(self):
        make_client(self.dist)
        output = self.bundle()
        index = sbom.verify_bundle(output, self.dist)
        self.assertEqual(index["release_tag"], "client-v" + VERSION)
        self.assertEqual(index["coverage"]["completeness"], "partial")
        self.assertEqual(len(index["artifacts"]), 2)
        self.assertEqual({p.suffix for p in self.dist.iterdir()}, {".whl", ".gz"})
        # Signature bundle is produced only by the trusted publishing job, not fabricated here.
        self.assertFalse((output / sbom.BUNDLE).exists())

    def test_modified_sbom_rejected(self):
        make_client(self.dist)
        output = self.bundle()
        next(output.glob("*.spdx.json")).write_text("{}")
        with self.assertRaisesRegex(sbom.SBOMError, "hash mismatch"):
            sbom.verify_bundle(output)

    def test_modified_distribution_rejected(self):
        wheel, _ = make_client(self.dist)
        output = self.bundle()
        wheel.write_bytes(wheel.read_bytes() + b"changed")
        with self.assertRaisesRegex(sbom.SBOMError, "artifact hash mismatch"):
            sbom.verify_bundle(output, self.dist)

    def test_checksum_manifest_cannot_override_signed_index(self):
        make_client(self.dist)
        output = self.bundle()
        (output / sbom.SUMS).write_text("fake\n")
        with self.assertRaisesRegex(sbom.SBOMError, "checksum manifest"):
            sbom.verify_bundle(output)

    def test_existing_output_is_not_overwritten(self):
        make_client(self.dist)
        self.bundle()
        with self.assertRaisesRegex(sbom.SBOMError, "already exists"):
            self.bundle()


class WorkflowTests(unittest.TestCase):
    def test_engine_gate_precedes_promotion_and_release(self):
        text = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertLess(text.index("Export and validate release SBOMs"), text.index("Verify registry digests and publish immutable version tags"))
        self.assertLess(text.index("Attest release SBOM index"), text.index("gh release create"))
        self.assertIn("release-image-lock.env release-candidate-receipt.json release-sbom/*", text)
        self.assertIn('--source-digest "$CANDIDATE_SHA"', text)
        self.assertIn("attestations: write", text)
        self.assertIn("id-token: write", text)

    def test_client_sboms_are_separate_from_pypi_distributions(self):
        text = (ROOT / ".github/workflows/publish-client.yml").read_text()
        self.assertIn("name: client-sbom\n          path: release-sbom/", text)
        self.assertIn("packages-dir: dist/", text)
        self.assertIn("dist/* release-sbom/* --repo", text)
        self.assertIn("verify --directory release-sbom --dist dist", text)
        self.assertLess(text.index("Attest client SBOM index"), text.index("- name: Publish to PyPI"))
        self.assertIn("--latest=false", text)


if __name__ == "__main__":
    unittest.main()
