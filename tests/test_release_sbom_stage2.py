"""Stage-two regression tests. Optional pinned-tool tests also run in release CI."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_sbom as sbom
from scripts import release_sbom_coverage as coverage
from scripts import release_sbom_stage2 as stage2
from scripts import release_sbom_toolchain as tooling

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
INDEX = {"version": "2.4.0", "repository": "andriyze/shakerscan", "source_sha": SHA, "generated_at": "2026-09-21T00:00:00Z"}


def cdx():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "bom-ref": "p", "name": "example", "version": "1.0"}],
            "dependencies": [{"ref": "p", "dependsOn": []}]}


def platform_index():
    return {"schemaVersion": 2, "manifests": [
        {"platform": {"os": "linux", "architecture": "amd64"}, "digest": DIGEST},
        {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "digest": "sha256:" + "c" * 64},
        {"platform": {"os": "linux", "architecture": "arm", "variant": "v7"}, "digest": "sha256:" + "d" * 64},
        {"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "sha256:" + "e" * 64}]}



class Services(unittest.TestCase):
    def test_real_compose_defaults_deduplicate_postgres_keep_profiles(self):
        services = coverage.supporting_images(ROOT / "docker-compose.release.yml", sbom.load_json(ROOT / "install/release-images.json"))
        self.assertEqual(len(services), 5)
        self.assertEqual(sum(len(x["deployments"]) for x in services), 6)
        postgres = next(x for x in services if x["image"] == "service-postgres")
        self.assertEqual(len(postgres["deployments"]), 2)
        minio = next(x for x in services if x["image"] == "service-minio")
        self.assertEqual(minio["deployments"][0]["profiles"], ["artifacts"])

    def test_defaults_ignore_environment(self):
        with patch.dict(os.environ, {"POSTGRES_IMAGE": "evil:latest"}):
            self.assertEqual(coverage.default_image("${POSTGRES_IMAGE:-postgres@" + DIGEST + "}")[0], "postgres@" + DIGEST)

    def test_unsupported_interpolation_fails(self):
        for text in ("${IMAGE}", "${IMAGE:-${OTHER}}", "repo:$TAG"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                coverage.default_image(text)

    def test_mutable_services_fail(self):
        for text in ("postgres:16", "quay.io/minio/minio:latest", "repo@sha256:bad"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                coverage.canonical_image(text)

    def test_canonical_digest_removes_tag(self):
        self.assertEqual(coverage.canonical_image("redis:7@" + DIGEST), ("docker.io/library/redis", DIGEST))

    def test_duplicate_compose_keys_fail(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "compose.yml"
            path.write_text("services:\n  redis:\n    image: redis@" + DIGEST + "\n    image: redis@" + DIGEST + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                coverage.supporting_images(path, {"images": []})

    def test_upstream_extra_architectures_allowed(self):
        self.assertEqual(set(coverage.service_platforms(platform_index())), set(coverage.PLATFORMS))

    def test_missing_arch_fails(self):
        data = platform_index(); data["manifests"].pop(1)
        with self.assertRaisesRegex(ValueError, "amd64 and arm64"):
            coverage.service_platforms(data)

    def test_duplicate_arch_fails(self):
        data = platform_index(); data["manifests"].append(data["manifests"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            coverage.service_platforms(data)


class Coverage(unittest.TestCase):
    def test_real_build_lock_inputs_have_separate_scope(self):
        spdx, document, inputs = stage2.build_input_documents(ROOT, INDEX)
        sbom.validate_spdx(spdx); coverage.validate_cdx(document)
        self.assertGreater(len(spdx["packages"]), 100)
        self.assertEqual(len(inputs), 9)
        self.assertIn("not-runtime", document["metadata"]["component"]["properties"][0]["value"])
        self.assertTrue(all("checksums" not in p for p in spdx["packages"]))
        self.assertEqual(coverage.spdx_purls(spdx), coverage.cdx_purls(document))

    def test_direct_hashed_guest_wheel_has_exact_version(self):
        self.assertEqual(coverage.python_pins(ROOT / "runner/guest/requirements.lock")["torch"], "2.13.0+cpu")

    def test_unpinned_python_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "requirements.lock"; path.write_text("requests>=2\n")
            with self.assertRaisesRegex(ValueError, "unpinned"):
                coverage.python_pins(path)

    def test_direct_wheel_without_hash_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "requirements.lock"; path.write_text("thing @ https://example.test/thing-1-py3-none-any.whl\n")
            with self.assertRaisesRegex(ValueError, "pin"):
                coverage.python_pins(path)

    def test_npm_scoped_and_duplicate_versions_retained(self):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/@a/b": {"version": "1"},
                "node_modules/a/node_modules/@a/b": {"version": "2"}}}
        self.assertEqual(coverage.npm_pins(lock), {"@a/b": {"1", "2"}})

    def test_npm_workspace_not_silently_resolved(self):
        with self.assertRaises(ValueError):
            coverage.npm_pins({"lockfileVersion": 3, "packages": {"node_modules/a": {"link": True}}})

    def test_native_subject_binding(self):
        native = {"source": {"type": "image", "metadata": {"manifestDigest": DIGEST, "architecture": "amd64", "os": "linux"}}, "artifacts": [{"name": "p"}]}
        coverage.validate_native_source(native, "repo@" + DIGEST, "linux/amd64")
        with self.assertRaisesRegex(ValueError, "platform"):
            coverage.validate_native_source(native, "repo@" + DIGEST, "linux/arm64")
        with self.assertRaisesRegex(ValueError, "manifest"):
            coverage.validate_native_source(native, "repo@sha256:" + "e" * 64, "linux/amd64")

    def test_missing_os_packages_is_not_success(self):
        with self.assertRaisesRegex(ValueError, "OS-package"):
            coverage.coverage_report("service-redis", {"artifacts": [{"type": "go-module"}]}, ROOT)

    def test_lock_metadata_not_treated_as_installed(self):
        packages = [{"type": "deb"}] + [{"type": "python", "name": n, "version": v, "locations": [{"path": "/app/requirements.lock"}]} for n, v in coverage.python_pins(ROOT / "scanner/requirements.lock").items()]
        with self.assertRaisesRegex(ValueError, "installed Python"):
            coverage.coverage_report("scanner", {"artifacts": packages}, ROOT)

    def test_python_complete_but_go_missing_fails(self):
        packages = [{"type": "deb"}] + [{"type": "python", "name": n, "version": v, "locations": [{"path": "/usr/local/lib/python3.12/site-packages/" + n + ".dist-info/METADATA"}]} for n, v in coverage.python_pins(ROOT / "scanner/requirements.lock").items()]
        with self.assertRaisesRegex(ValueError, "Go dependency"):
            coverage.coverage_report("scanner", {"artifacts": packages}, ROOT)

    def test_ui_minified_uncertainty_is_preserved(self):
        pins = coverage.npm_pins(sbom.load_json(ROOT / "ui/package-lock.json"))
        packages = [{"type": "apk"}] + [{"type": "npm", "name": n, "version": sorted(pins[n])[0], "locations": [{"path": "/app/node_modules/" + n + "/package.json"}]} for n in ("next", "react", "react-dom")]
        report = coverage.coverage_report("ui", {"artifacts": packages}, ROOT)
        self.assertTrue(report["unattributed_lock_components"])
        self.assertIn("not classified as absent", report["limitations"][-1])

    def test_cyclonedx_bad_references_fail(self):
        data = cdx(); data["dependencies"][0]["dependsOn"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "dangling"):
            coverage.validate_cdx(data)

    def test_cyclonedx_duplicate_refs_fail(self):
        data = cdx(); data["components"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            coverage.validate_cdx(data)


class ExtensionIntegrity(unittest.TestCase):
    def fixture(self, directory):
        index = {**INDEX, "kind": "client", "coverage": {"stage": 2}, "files": {}, "artifacts": [],
                 "extension": {"schema_version": stage2.EXTENSION, "source_inputs": stage2.PLAN,
                               "coverage_report": stage2.REPORT, "toolchain": {"syft_version": "1.52.0", "schema_git_blobs": {"a": "b"}}, "catalogs": []}}
        values = {stage2.PLAN: {"kind": "client", "source_sha": SHA},
                  stage2.REPORT: {"schema_version": stage2.EXTENSION, "status": "pass"}}
        for distribution in ("wheel", "sdist"):
            name = distribution + ".cdx.json"
            values[name] = cdx()
            index["extension"]["catalogs"].append({"scope": "client-archive-files", "distribution": distribution,
                "cyclonedx": name, "cyclonedx_sha256": sbom.sha256(sbom.json_bytes(values[name]))})
        for name, value in values.items():
            (directory / name).write_bytes(sbom.json_bytes(value))
            index["files"][name] = sbom.sha256(sbom.json_bytes(value))
        return index

    def test_complete_extension(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t); index = self.fixture(directory)
            self.assertEqual(stage2.verify_extension(directory, index), set())

    def test_missing_conversion_fails(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t); index = self.fixture(directory)
            index["extension"]["catalogs"].pop()
            with self.assertRaisesRegex(ValueError, "unindexed"):
                stage2.verify_extension(directory, index)

    def test_wrong_source_fails(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t); index = self.fixture(directory)
            index["source_sha"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "source mismatch"):
                stage2.verify_extension(directory, index)

    def test_conversion_hash_binding_fails(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t); index = self.fixture(directory)
            index["extension"]["catalogs"][0]["cyclonedx_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash binding"):
                stage2.verify_extension(directory, index)

    def test_source_checkout_must_be_clean_and_exact(self):
        with patch.object(stage2.subprocess, "check_output", side_effect=["b" * 40]):
            with self.assertRaisesRegex(ValueError, "differs"):
                stage2.source_identity(ROOT, SHA)
        with patch.object(stage2.subprocess, "check_output", side_effect=[SHA, " M scanner/Dockerfile"]):
            with self.assertRaisesRegex(ValueError, "modified"):
                stage2.source_identity(ROOT, SHA)


class Pipeline(unittest.TestCase):
    def test_stage_two_precedes_attestation(self):
        for name, attestation in (("release.yml", "Attest release SBOM index"), ("publish-client.yml", "Attest client SBOM index")):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertLess(text.index("release_sbom_stage2.py"), text.index(attestation))
            self.assertIn("./.github/actions/sbom-tools", text)

    def test_expansion_does_not_rebuild_images(self):
        text = (ROOT / "scripts/release_sbom_stage2.py").read_text()
        self.assertNotIn('"docker", "run"', text)
        self.assertNotIn('"docker", "build"', text)
        self.assertIn('"registry:" + reference', text)

    def test_signed_bundle_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); (root / sbom.BUNDLE).write_text("signed")
            with self.assertRaisesRegex(ValueError, "signed"):
                stage2.enhance(root, ROOT, root, root / "new")


@unittest.skipUnless(os.environ.get("SHAKERSCAN_SBOM_TOOLS"), "pinned schemas/cataloger available in release CI")
class OfficialSchemas(unittest.TestCase):
    def test_client_mapping_keeps_duplicate_content_file_names(self):
        tool = tooling.Toolchain(Path(os.environ["SHAKERSCAN_SBOM_TOOLS"]))
        with tempfile.TemporaryDirectory() as t:
            # Same contents in distinct paths must not cause hash-based identity collapse.
            root = Path(t)
            sys.path.insert(0, str(ROOT / "tests"))
            from test_release_sbom import make_client, VERSION, CREATED
            make_client(root)
            document, _, _ = sbom.client_document(next(root.glob("*.whl")), VERSION, SHA, "andriyze/shakerscan", CREATED)
            cdx_doc = stage2.client_cdx(document)
            self.assertEqual({f["fileName"] for f in document["files"]}, {c["name"] for c in cdx_doc["components"]})
            self.assertEqual(len(document["files"]), len(cdx_doc["components"]))
            tool.validate(cdx_doc)

    def test_build_inputs_validate_offline(self):
        tool = tooling.Toolchain(Path(os.environ["SHAKERSCAN_SBOM_TOOLS"]))
        spdx, document, _ = stage2.build_input_documents(ROOT, INDEX)
        tool.validate(spdx); tool.validate(document)
        document = cdx(); document["components"][0]["type"] = "not-a-schema-type"
        with self.assertRaises(Exception):
            tool.validate(document)


if __name__ == "__main__":
    unittest.main()
