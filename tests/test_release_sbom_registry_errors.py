"""Registry failures stay blocking, with useful identity and no raw secret-bearing output."""
import subprocess
import unittest
from unittest.mock import patch

from scripts import release_sbom as sbom
from scripts import release_sbom_stage2 as stage2


REFERENCE = "quay.io/minio/minio@sha256:" + "a" * 64
COMMAND = ["docker", "buildx", "imagetools", "inspect", REFERENCE, "--raw"]


class RegistryFailures(unittest.TestCase):
    def test_failure_reason_is_classified_without_exposing_stderr(self):
        for stderr, expected in (
            (b"401 Unauthorized", "authentication/access rejected"),
            ("unexpected status 403 Forbidden", "authentication/access rejected"),
            (b"insufficient_scope: authorization failed", "authentication/access rejected"),
            (b"pull access denied", "authentication/access rejected"),
            (b"429 Too Many Requests", "registry rate limit"),
            (b"TOOMANYREQUESTS", "registry rate limit"),
            (b"404 Not Found", "registry manifest unavailable"),
            (b"MANIFEST_UNKNOWN", "registry manifest unavailable"),
            (b"unsupported command", "command error"),
        ):
            with self.subTest(stderr=stderr):
                secret = " https://registry.example/object?token=hidden-token Bearer hidden-token\n::error::injected"
                raw = stderr + secret.encode() if isinstance(stderr, bytes) else stderr + secret
                failure = subprocess.CalledProcessError(1, COMMAND, stderr=raw)
                with patch.object(sbom.subprocess, "run", side_effect=failure) as run, patch.object(sbom.time, "sleep") as sleep:
                    with self.assertRaises(sbom.SBOMError) as error:
                        sbom.run_json(COMMAND)
                message = str(error.exception)
                self.assertIn(expected, message)
                self.assertIn("three attempts", message)
                for value in ("hidden-token", "registry.example", "injected"):
                    self.assertNotIn(value, message)
                self.assertEqual(run.call_count, 3)
                self.assertEqual([call.args[0] for call in run.call_args_list], [COMMAND] * 3)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
                self.assertTrue(all(call.kwargs["timeout"] == 180 for call in run.call_args_list))

    def test_timeout_is_not_replaced_by_untrusted_authentication_text(self):
        failure = subprocess.TimeoutExpired(COMMAND, 180, stderr=b"401 Unauthorized hidden-token")
        with patch.object(sbom.subprocess, "run", side_effect=failure), patch.object(sbom.time, "sleep"):
            with self.assertRaisesRegex(sbom.SBOMError, r"\(timeout\)") as error:
                sbom.run_json(COMMAND)
        self.assertNotIn("hidden-token", str(error.exception))

    def test_exact_dependency_is_named_and_not_substituted(self):
        failure = sbom.SBOMError("command failed after three attempts (registry authentication/access rejected)")
        with patch.object(sbom, "run_json", side_effect=failure) as run:
            with self.assertRaisesRegex(sbom.SBOMError, "Cannot inventory supporting image") as error:
                stage2.supporting_service_platforms({"image_reference": REFERENCE})
        self.assertIn(REFERENCE, str(error.exception))
        self.assertIn("authentication/access rejected", str(error.exception))
        run.assert_called_once_with(COMMAND)

    def test_success_keeps_both_architectures_and_exact_digest(self):
        document = {"schemaVersion": 2, "manifests": [
            {"platform": {"os": "linux", "architecture": arch}, "digest": "sha256:" + digit * 64}
            for arch, digit in (("amd64", "b"), ("arm64", "c"))
        ]}
        with patch.object(sbom, "run_json", return_value=document) as run:
            result = stage2.supporting_service_platforms({"image_reference": REFERENCE})
        self.assertEqual(result, {"linux/amd64": "sha256:" + "b" * 64,
                                  "linux/arm64": "sha256:" + "c" * 64})
        run.assert_called_once_with(COMMAND)

    def test_missing_architecture_still_fails(self):
        document = {"schemaVersion": 2, "manifests": []}
        with patch.object(sbom, "run_json", return_value=document):
            with self.assertRaisesRegex(ValueError, "amd64 and arm64"):
                stage2.supporting_service_platforms({"image_reference": REFERENCE})

    def test_unpinned_or_unsafe_identity_is_not_logged_or_requested(self):
        for reference in ("quay.io/minio/minio:latest", "https://user:secret@example.test/a", "quay.io/minio/minio@sha256:bad"):
            with self.subTest(reference=reference):
                with patch.object(sbom, "run_json") as run, patch("builtins.print") as output:
                    with self.assertRaises(ValueError):
                        stage2.supporting_service_platforms({"image_reference": reference})
                run.assert_not_called()
                output.assert_not_called()


if __name__ == "__main__":
    unittest.main()
