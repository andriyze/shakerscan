"""Container identity parity must not be confused with dependency loss."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_sbom_coverage as coverage
from scripts import release_sbom_stage2 as stage2
from scripts.release_sbom_toolchain import Toolchain, bind_container_identity

IMAGE_ID = "sha256:" + "a" * 64
PURL = "pkg:oci/scanner@" + IMAGE_ID


def fixture():
    native = {"source": {"type": "image", "metadata": {"manifestDigest": IMAGE_ID}}}
    spdx = {"packages": [{"SPDXID": "SPDXRef-Root", "primaryPackagePurpose": "CONTAINER",
                          "name": "scanner", "versionInfo": IMAGE_ID,
                          "externalRefs": [{"referenceType": "purl", "referenceLocator": PURL}]}],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-Root"}]}
    cdx = {"metadata": {"component": {"type": "container", "name": "scanner", "version": IMAGE_ID}}}
    return native, spdx, cdx


def archive_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


class ContainerIdentity(unittest.TestCase):
    def test_only_matched_root_is_enriched_without_mutating_input(self):
        native, spdx, cdx = fixture()
        original = copy.deepcopy(cdx)
        result = bind_container_identity(native, spdx, cdx)
        self.assertEqual(result["metadata"]["component"]["purl"], PURL)
        self.assertEqual(cdx, original)

    def test_wrong_image_is_rejected(self):
        for key, value in (("name", "other"), ("version", "sha256:" + "b" * 64), ("type", "application")):
            with self.subTest(key=key):
                native, spdx, cdx = fixture()
                cdx["metadata"]["component"][key] = value
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    bind_container_identity(native, spdx, cdx)

    def test_wrong_native_manifest_digest_is_rejected(self):
        native, spdx, cdx = fixture()
        native["source"]["metadata"]["manifestDigest"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "identity differs"):
            bind_container_identity(native, spdx, cdx)

    def test_conflicting_purl_is_not_overwritten(self):
        native, spdx, cdx = fixture()
        cdx["metadata"]["component"]["purl"] = "pkg:oci/other@1"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            bind_container_identity(native, spdx, cdx)

    def test_dependency_cannot_be_used_as_root(self):
        native, spdx, cdx = fixture()
        spdx["packages"][0]["primaryPackagePurpose"] = "LIBRARY"
        with self.assertRaisesRegex(ValueError, "container root"):
            bind_container_identity(native, spdx, cdx)

    def test_multiple_root_purls_fail(self):
        native, spdx, cdx = fixture()
        spdx["packages"][0]["externalRefs"].append({"referenceType": "purl", "referenceLocator": "pkg:oci/other@1"})
        with self.assertRaisesRegex(ValueError, "PURL"):
            bind_container_identity(native, spdx, cdx)

    def test_non_image_inventory_unchanged(self):
        native, spdx, cdx = fixture()
        native["source"]["type"] = "directory"
        self.assertEqual(bind_container_identity(native, spdx, cdx), cdx)


@unittest.skipUnless(os.environ.get("SHAKERSCAN_SBOM_TOOLS"), "pinned Syft available in SBOM CI")
class RealCatalogParity(unittest.TestCase):
    def test_local_container_archive_and_real_cataloger(self):
        # No registry, Docker daemon, image execution or package installation required.
        layer = archive_bytes({
            "etc/os-release": b"ID=alpine\nVERSION_ID=3.21.3\n",
            "lib/apk/db/installed": b"P:zlib\nV:1.3.1-r0\nA:x86_64\nL:Zlib\nS:123\nI:456\nT:Compression library\nU:https://zlib.net\n\n",
        })
        config = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                             "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}}).encode()
        name = hashlib.sha256(config).hexdigest() + ".json"
        manifest = json.dumps([{"Config": name, "RepoTags": ["shakerscan/scanner:test"], "Layers": ["layer.tar"]}]).encode()
        tool = Toolchain(Path(os.environ["SHAKERSCAN_SBOM_TOOLS"]))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "image.tar"
            path.write_bytes(archive_bytes({name: config, "manifest.json": manifest, "layer.tar": layer}))
            _, spdx, cdx = tool.scan("docker-archive:" + str(path), root / "scan")
            self.assertEqual(coverage.spdx_purls(spdx), coverage.cdx_purls(cdx))
            stage2.document_pair({}, "image", spdx, cdx, tool)
            # Still fail on a genuinely missing dependency, not just the image root.
            cdx["components"] = [c for c in cdx["components"] if c.get("name") != "zlib"]
            cdx["dependencies"] = []
            with self.assertRaisesRegex(ValueError, "lost package identities"):
                stage2.document_pair({}, "image", spdx, cdx, tool)


if __name__ == "__main__":
    unittest.main()
