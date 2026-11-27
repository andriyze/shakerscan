"""Target-environment and evolving-license-schema regressions."""
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_sbom_coverage as coverage
from scripts.release_sbom_toolchain import Toolchain


class TargetMarkers(unittest.TestCase):
    def test_windows_inputs_remain_in_source_bom_not_linux_expectations(self):
        lock = ROOT / "scanner/model_intake_tools/semgrep.lock"
        excluded = {}
        pins = coverage.python_pins(lock, coverage.marker_environment({}), excluded)
        self.assertIn("pywin32", coverage.python_pins(lock))
        self.assertNotIn("pywin32", pins)
        self.assertIn("pywin32==311", excluded)
        self.assertIn("uvicorn", pins)

    def test_python_marker_uses_observed_family_not_ci_interpreter(self):
        native = {"artifacts": [{"type": "python", "locations": [{"path": "/opt/model-intake-tools/pip-audit/lib/python3.12/site-packages/x.dist-info/METADATA"}]}]}
        env = coverage.marker_environment(native, "/opt/model-intake-tools/pip-audit/")
        self.assertTrue(coverage.applies_to_image("python_full_version < '3.13'", env))
        self.assertFalse(coverage.applies_to_image("python_full_version >= '3.13'", env))
        with self.assertRaisesRegex(ValueError, "patch-sensitive"):
            coverage.applies_to_image("python_full_version < '3.12.7'", env)
        with self.assertRaisesRegex(ValueError, "complex"):
            coverage.applies_to_image("python_full_version < '3.12.2' or python_full_version >= '3.12.8'", env)

    def test_unknown_environment_fact_never_inherits_host(self):
        with self.assertRaisesRegex(ValueError, "unknown target"):
            coverage.applies_to_image("platform_release == '6.1.0'", coverage.marker_environment({}))

    def test_nonapplicable_marker_does_not_delete_inventory_packages(self):
        env = coverage.marker_environment({})
        self.assertFalse(coverage.applies_to_image("sys_platform == 'win32'", env))
        self.assertTrue(coverage.applies_to_image("implementation_name != 'PyPy' and platform_python_implementation != 'PyPy'", env))


@unittest.skipUnless(os.environ.get("SHAKERSCAN_SBOM_TOOLS"), "pinned schemas available in release CI")
class LicenseEnumeration(unittest.TestCase):
    def test_new_spdx_license_keeps_identifier_without_weakening_schema(self):
        tool = Toolchain(Path(os.environ["SHAKERSCAN_SBOM_TOOLS"]))
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "components": [{"type": "library", "name": "example", "bom-ref": "p",
                               "licenses": [{"license": {"id": "SMAIL-GPL"}}]}]}
        tool.validate(doc)
        doc["components"][0]["licenses"][0]["license"]["id"] = "INVENTED-NOT-A-LICENSE"
        with self.assertRaises(Exception):
            tool.validate(doc)


if __name__ == "__main__":
    unittest.main()
