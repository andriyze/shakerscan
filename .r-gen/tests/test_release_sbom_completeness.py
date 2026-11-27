"""Completeness is defined by the release source, not whichever catalogs survive."""
import copy
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_sbom as sbom, release_sbom_stage2 as stage2
from scripts.release_sbom_stage2 import validate_release_image_inventory

DIGEST = "sha256:" + "a" * 64


def fixture():
    images = [{"key": k, "repository": "shakerscan/shakerscan-" + k} for k in ("scanner", "api", "ui")]
    plan = {"first_party": {"schema_version": "shakerscan-release-images/v1", "images": images}}
    index = {"artifacts": [{"image": image["key"], "platform": platform, "index_digest": DIGEST,
                            "image_reference": "docker.io/" + image["repository"] + "@" + DIGEST}
                           for image in images for platform in ("linux/amd64", "linux/arm64")]}
    return index, plan


class ReleaseCompleteness(unittest.TestCase):
    def test_complete_inventory(self):
        index, plan = fixture()
        validate_release_image_inventory(index, plan)

    def test_whole_image_removal_is_rejected(self):
        index, plan = fixture()
        index["artifacts"] = [a for a in index["artifacts"] if a["image"] != "scanner"]
        with self.assertRaisesRegex(ValueError, "incomplete first-party"):
            validate_release_image_inventory(index, plan)

    def test_extension_verifier_enforces_source_inventory(self):
        index, plan = fixture()
        index.update(kind="engine", source_sha="a" * 40, coverage={"stage": 2},
                     files={stage2.PLAN: "unused", stage2.REPORT: "unused"},
                     extension={"schema_version": stage2.EXTENSION, "source_inputs": stage2.PLAN,
                                "coverage_report": stage2.REPORT})
        plan.update(kind="engine", source_sha=index["source_sha"])
        index["artifacts"] = [a for a in index["artifacts"] if a["image"] != "scanner"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / stage2.PLAN).write_bytes(sbom.json_bytes(plan))
            (root / stage2.REPORT).write_bytes(sbom.json_bytes({"schema_version": stage2.EXTENSION, "status": "pass"}))
            with self.assertRaisesRegex(ValueError, "incomplete first-party"):
                stage2.verify_extension(root, index)

    def test_one_platform_removal_is_rejected(self):
        index, plan = fixture()
        index["artifacts"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete first-party"):
            validate_release_image_inventory(index, plan)

    def test_wrong_repository_is_rejected(self):
        index, plan = fixture()
        index["artifacts"][0]["image_reference"] = "docker.io/other/scanner@" + DIGEST
        with self.assertRaisesRegex(ValueError, "repository/digest"):
            validate_release_image_inventory(index, plan)

    def test_repeated_source_identity_is_rejected(self):
        index, plan = fixture()
        plan["first_party"]["images"].append(copy.deepcopy(plan["first_party"]["images"][0]))
        with self.assertRaisesRegex(ValueError, "source image key"):
            validate_release_image_inventory(index, plan)

    def test_missing_source_inventory_is_rejected(self):
        index, _ = fixture()
        with self.assertRaisesRegex(ValueError, "source image inventory"):
            validate_release_image_inventory(index, {})


if __name__ == "__main__":
    unittest.main()
