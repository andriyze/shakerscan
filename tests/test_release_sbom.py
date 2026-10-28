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
        docs, artifacts, extras = sbom.client_documents(self.dist, VERSION, SHA, "andriyze/shakerscan", CREATED)
        self.assertEqual(extras, [])
        return docs, artifacts

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


RECORD_EXTRA = 'Provides-Extra: record\nRequires-Dist: playwright>=1.44; extra == "record"\n'
HASH = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("playwright-a", "playwright-b", "greenlet", "pyee-13", "pyee-14")}
RECORD_LOCK = f"""# This file was autogenerated by uv via the following command:
#    uv pip compile client/requirements/record.txt --python-version 3.10 --universal --generate-hashes --output-file client/requirements/record.lock
greenlet==3.5.6 \\
    --hash=sha256:{HASH['greenlet']}
    # via playwright
playwright==1.64.0 \\
    --hash=sha256:{HASH['playwright-a']} \\
    --hash=sha256:{HASH['playwright-b']}
    # via -r client/requirements/record.txt
pyee==13.0.1 ; python_full_version < '3.12' \\
    --hash=sha256:{HASH['pyee-13']}
    # via playwright
pyee==14.0.0 ; python_full_version >= '3.12' \\
    --hash=sha256:{HASH['pyee-14']}
    # via playwright
"""


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()


class ClientExtraTests(unittest.TestCase):
    """An optional extra is inventoried from its hash-locked resolution at the exact source commit."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.source, "init", "-q")
        self.write_locks()
        self.sha = self.commit()

    def write_locks(self, txt="# the record extra\nplaywright>=1.44\n", lock=RECORD_LOCK):
        directory = self.source / "client/requirements"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "record.txt").write_text(txt)
        (directory / "record.lock").write_text(lock)

    def commit(self):
        git(self.source, "add", "-A")
        git(self.source, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-q", "-m", "fixture")
        return git(self.source, "rev-parse", "HEAD")

    def export(self, requires_dist=RECORD_EXTRA, sha=None):
        make_client(self.dist, requires_dist=requires_dist)
        return sbom.client_documents(self.dist, VERSION, sha or self.sha, "andriyze/shakerscan", CREATED,
                                     source_root=self.source)

    def test_the_extra_resolution_lists_every_locked_package_with_its_hashes(self):
        docs, artifacts, extras = self.export()
        self.assertEqual([a["optional_extras"] for a in artifacts], [{"record": ["playwright>=1.44"]}] * 2)
        self.assertEqual(artifacts[0]["declared_runtime_dependencies"], [])
        [entry] = extras
        self.assertEqual(entry["extra"], "record")
        self.assertEqual(entry["lock"], "client/requirements/record.lock")
        self.assertEqual(entry["lock_sha256"], sbom.sha256(RECORD_LOCK.encode()))
        self.assertEqual(entry["package_count"], 4)
        document = json.loads(docs[entry["sbom"]])
        sbom.validate_spdx(document)
        packages = {(p["name"], p["versionInfo"]): p for p in document["packages"]}
        playwright = packages[("playwright", "1.64.0")]
        self.assertEqual({c["checksumValue"] for c in playwright["checksums"]}, {HASH["playwright-a"], HASH["playwright-b"]})
        self.assertIn("not bundled", playwright["sourceInfo"])
        # A universal lock pins pyee per interpreter; both resolutions are kept with their markers.
        self.assertIn("python_full_version < '3.12'", packages[("pyee", "13.0.1")]["sourceInfo"])
        self.assertIn(("pyee", "14.0.0"), packages)
        optional = [r for r in document["relationships"] if r["relationshipType"] == "OPTIONAL_DEPENDENCY_OF"]
        self.assertEqual(len(optional), 4)

    def test_a_bundle_with_an_extra_verifies_and_binds_its_resolution(self):
        docs, artifacts, extras = self.export()
        output = self.root / "sbom"
        sbom.write_bundle(output, docs, artifacts, kind="client", version=VERSION, source_sha=self.sha,
                          repository="andriyze/shakerscan", created=CREATED, generator_source_sha=self.sha, extras=extras)
        index = sbom.verify_bundle(output, self.dist)
        self.assertEqual([e["extra"] for e in index["extras"]], ["record"])
        self.assertTrue(any("optional extra" in line for line in index["coverage"]["limitations"]))
        # An index that drops the extra no longer matches the archives' declared extras.
        index["extras"] = []
        (output / sbom.INDEX).write_text(json.dumps(index))
        with self.assertRaisesRegex(sbom.SBOMError, "unindexed SBOM|extras differ"):
            sbom.verify_bundle(output)

    def test_a_requirement_not_scoped_to_an_extra_is_still_refused(self):
        for requires in ("Requires-Dist: requests>=2\n",
                         'Provides-Extra: record\nRequires-Dist: playwright>=1.44; python_version < "3.11"\n',
                         'Provides-Extra: record\nRequires-Dist: playwright>=1.44; extra == "record" or python_version < "4"\n'):
            with self.subTest(requires=requires), self.assertRaisesRegex(sbom.SBOMError, "runtime dependencies"):
                self.export(requires)

    def test_an_extra_needs_its_lock_at_the_exact_source(self):
        (self.source / "client/requirements/record.lock").unlink()
        sha = self.commit()
        with self.assertRaisesRegex(sbom.SBOMError, "missing record.lock"):
            self.export(sha=sha)

    def test_an_uncommitted_lock_or_another_commit_is_refused(self):
        with self.assertRaisesRegex(sbom.SBOMError, "differs from the client source commit"):
            self.export(sha="c" * 40)
        self.write_locks(lock=RECORD_LOCK.replace("1.64.0", "1.65.0"))
        with self.assertRaisesRegex(sbom.SBOMError, "differ from the source commit"):
            self.export()

    def test_the_lock_input_must_be_what_the_extra_declares(self):
        self.write_locks(txt="playwright>=1.40\n")
        with self.assertRaisesRegex(sbom.SBOMError, "differs from the declared Requires-Dist"):
            self.export(sha=self.commit())

    def test_an_unhashed_or_missing_pin_is_refused(self):
        self.write_locks(lock="playwright==1.64.0\n")
        with self.assertRaisesRegex(sbom.SBOMError, "unhashed"):
            self.export(sha=self.commit())
        self.write_locks(lock=f"greenlet==3.5.6 --hash=sha256:{HASH['greenlet']}\n")
        with self.assertRaisesRegex(sbom.SBOMError, "declared but not locked"):
            self.export(sha=self.commit())

    def test_the_client_source_locks_every_extra_it_declares(self):
        import tomllib
        project = tomllib.loads((ROOT / "client/pyproject.toml").read_text())["project"]
        # The base install's runtime dependencies have their own resolution (runtime.txt/.lock).
        resolutions = {**({sbom.RUNTIME: project["dependencies"]} if project["dependencies"] else {}),
                       **project.get("optional-dependencies", {})}
        for extra, requirements in resolutions.items():
            with self.subTest(extra=extra):
                text = (ROOT / f"client/requirements/{extra}.txt").read_text()
                declared = sorted(sbom.requirement_key(line.split("#", 1)[0]) for line in text.splitlines()
                                  if line.split("#", 1)[0].strip())
                self.assertEqual(declared, sorted(sbom.requirement_key(r) for r in requirements))
                lock = (ROOT / f"client/requirements/{extra}.lock").read_text()
                self.assertIn(f"uv pip compile client/requirements/{extra}.txt --python-version 3.10 --universal "
                              f"--generate-hashes --output-file client/requirements/{extra}.lock", lock)
                pins = sbom.lock_pins(lock)
                self.assertTrue(all(pin["sha256"] for pin in pins))


FIDO2_HASH = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("fido2", "cryptography", "cffi")}
RUNTIME_LOCK = f"""# This file was autogenerated by uv via the following command:
#    uv pip compile client/requirements/runtime.txt --python-version 3.10 --universal --generate-hashes --output-file client/requirements/runtime.lock
cffi==2.1.1 ; platform_python_implementation != 'PyPy' \\
    --hash=sha256:{FIDO2_HASH['cffi']}
    # via cryptography
cryptography==50.0.2 \\
    --hash=sha256:{FIDO2_HASH['cryptography']}
    # via fido2
fido2==2.2.1 \\
    --hash=sha256:{FIDO2_HASH['fido2']}
    # via -r client/requirements/runtime.txt
"""
FIDO2_RUNTIME = "Requires-Dist: fido2<3,>=2.0\n"


class ClientRuntimeDependencyTests(unittest.TestCase):
    """The base install's own dependencies (client 0.11.2: python-fido2) are inventoried from their
    hash-locked resolution at the exact source commit, as required, not optional, dependencies."""

    setUp = ClientExtraTests.setUp
    commit = ClientExtraTests.commit
    export = ClientExtraTests.export

    def write_locks(self, txt="# the base install\nfido2>=2.0,<3\n", lock=RUNTIME_LOCK):
        ClientExtraTests.write_locks(self)
        directory = self.source / "client/requirements"
        (directory / "runtime.txt").write_text(txt)
        (directory / "runtime.lock").write_text(lock)

    def test_the_runtime_resolution_lists_every_locked_package_as_required(self):
        docs, artifacts, entries = self.export(FIDO2_RUNTIME + RECORD_EXTRA)
        self.assertEqual([a["declared_runtime_dependencies"] for a in artifacts], [["fido2<3,>=2.0"]] * 2)
        runtime = next(e for e in entries if e["scope"] == sbom.RUNTIME_SCOPE)
        self.assertEqual(runtime["lock"], "client/requirements/runtime.lock")
        self.assertEqual(runtime["package_count"], 3)
        self.assertNotIn("extra", runtime)
        document = json.loads(docs[runtime["sbom"]])
        self.assertEqual(document["name"], f"shakerscan-{VERSION}-runtime")
        required = [r for r in document["relationships"] if r["relationshipType"] == "DEPENDENCY_OF"]
        self.assertEqual(len(required), 3)
        packages = {p["name"]: p for p in document["packages"]}
        self.assertIn("installed with shakerscan, not bundled", packages["fido2"]["sourceInfo"])
        self.assertEqual({c["checksumValue"] for c in packages["fido2"]["checksums"]}, {FIDO2_HASH["fido2"]})

    def test_a_bundle_binds_the_runtime_resolution_and_refuses_one_that_drops_it(self):
        docs, artifacts, entries = self.export(FIDO2_RUNTIME + RECORD_EXTRA)
        output = self.root / "sbom"
        sbom.write_bundle(output, docs, artifacts, kind="client", version=VERSION, source_sha=self.sha,
                          repository="andriyze/shakerscan", created=CREATED, generator_source_sha=self.sha, extras=entries)
        index = sbom.verify_bundle(output, self.dist)
        self.assertEqual(index["runtime"]["requires"], ["fido2<3,>=2.0"])
        self.assertEqual([e["extra"] for e in index["extras"]], ["record"])
        dropped = {k: v for k, v in index.items() if k != "runtime"}
        (output / sbom.INDEX).write_text(json.dumps(dropped))
        with self.assertRaisesRegex(sbom.SBOMError, "unindexed SBOM|runtime dependencies differ|checksum"):
            sbom.verify_bundle(output)

    def test_a_runtime_dependency_needs_its_lock_and_the_lock_its_declaration(self):
        (self.source / "client/requirements/runtime.lock").unlink()
        sha = self.commit()
        with self.assertRaisesRegex(sbom.SBOMError, "runtime dependencies: missing runtime.lock"):
            self.export(FIDO2_RUNTIME, sha=sha)
        self.write_locks(txt="fido2>=1\n")
        with self.assertRaisesRegex(sbom.SBOMError, "runtime dependencies: client/requirements/runtime.txt differs"):
            self.export(FIDO2_RUNTIME, sha=self.commit())

    def test_a_runtime_dependency_keeps_its_platform_marker(self):
        """Client 0.11.2: python-fido2 only where its cryptography dependency ships wheels, and an
        Intel Mac's cryptography capped below 49 (the last line with an Intel macOS wheel). The
        source spells the marker with single quotes, the built metadata with double ones; one key."""
        txt = ("fido2>=2.2,<2.3; sys_platform == 'darwin' or (sys_platform == 'linux' and platform_machine == 'x86_64')\n"
               "cryptography<49; sys_platform == 'darwin' and platform_machine == 'x86_64'\n")
        lock = RUNTIME_LOCK.replace(
            "cryptography==50.0.2 \\",
            "cryptography==48.0.1 ; sys_platform == 'darwin' \\\n"
            f"    --hash=sha256:{FIDO2_HASH['cffi']}\n"
            "cryptography==50.0.2 ; sys_platform == 'linux' \\",
        )
        self.write_locks(txt=txt, lock=lock)
        requires = ('Requires-Dist: fido2<2.3,>=2.2; sys_platform == "darwin" or (sys_platform == "linux" and '
                    'platform_machine == "x86_64")\n'
                    'Requires-Dist: cryptography<49; sys_platform == "darwin" and platform_machine == "x86_64"\n')
        docs, artifacts, entries = self.export(requires, sha=self.commit())
        declared = artifacts[0]["declared_runtime_dependencies"]
        self.assertEqual(declared, [
            'cryptography<49;sys_platform=="darwin"andplatform_machine=="x86_64"',
            'fido2<2.3,>=2.2;sys_platform=="darwin"or(sys_platform=="linux"andplatform_machine=="x86_64")',
        ])
        runtime = next(e for e in entries if e["scope"] == sbom.RUNTIME_SCOPE)
        self.assertEqual(runtime["package_count"], 4)
        document = json.loads(docs[runtime["sbom"]])
        versions = sorted(p["versionInfo"] for p in document["packages"] if p["name"] == "cryptography")
        self.assertEqual(versions, ["48.0.1", "50.0.2"])
        # A source whose marker differs from the package's is refused.
        self.write_locks(txt=txt.replace("x86_64')", "aarch64')"), lock=lock)
        with self.assertRaisesRegex(sbom.SBOMError, "runtime.txt differs"):
            self.export(requires, sha=self.commit())

    def test_runtime_is_never_an_extra_name(self):
        with self.assertRaisesRegex(sbom.SBOMError, "reserved"):
            self.export('Provides-Extra: runtime\nRequires-Dist: fido2>=2; extra == "runtime"\n')


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
