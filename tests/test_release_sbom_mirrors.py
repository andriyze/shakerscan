"""Known identical-content mirrors repair retrieval, never the SBOM's artifact identity."""
from copy import deepcopy
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from scripts import release_sbom as sbom
from scripts import release_sbom_stage2 as stage2


PRIMARY, MIRROR = next(iter(stage2.SUPPORTING_MIRRORS.items()))
DIGEST = PRIMARY.rsplit('@', 1)[1]


def index_document():
    return {'schemaVersion': 2, 'manifests': [
        {'platform': {'os': 'linux', 'architecture': arch}, 'digest': 'sha256:' + char * 64}
        for arch, char in [('amd64', 'b'), ('arm64', 'c')]
    ]}


def command(reference):
    return ['docker', 'buildx', 'imagetools', 'inspect', reference, '--raw']


class MirrorRecoveryTests(unittest.TestCase):
    """Keep every scenario discoverable by the release-only unittest job and pytest.

    The lightweight SBOM job intentionally has no pytest/runtime dependency set.
    Merely making that import optional would silently omit function-style tests.
    """

    def test_successful_original_does_not_use_or_record_a_mirror(self):
        service = {'image_reference': PRIMARY}
        with patch.object(sbom, 'run_json', return_value=index_document()) as run:
            self.assertEqual(set(stage2.supporting_service_platforms(service)), {'linux/amd64', 'linux/arm64'})
        run.assert_called_once_with(command(PRIMARY), expected_digest=DIGEST)
        self.assertEqual(service, {'image_reference': PRIMARY})

    def assert_access_recovery(self, primary):
        mirror = stage2.SUPPORTING_MIRRORS[primary]
        digest = primary.rsplit('@', 1)[1]
        service = {'image_reference': primary, 'index_digest': digest}
        failure = sbom.SBOMCommandError('registry authentication/access rejected')
        with patch.object(sbom, 'run_json', side_effect=[failure, index_document()]) as run:
            platforms = stage2.supporting_service_platforms(service)
        self.assertEqual(len(platforms), 2)
        self.assertEqual(service, {'image_reference': primary, 'index_digest': digest, 'retrieval_reference': mirror})
        self.assertEqual([c.args[0] for c in run.call_args_list], [command(primary), command(mirror)])
        self.assertTrue(all(c.kwargs == {'expected_digest': digest} for c in run.call_args_list))
        self.assertEqual(stage2.validate_retrieval_reference(service), mirror)

    def test_server_access_failure_records_mirror_without_changing_original(self):
        primary = next(ref for ref in stage2.SUPPORTING_MIRRORS if ref.startswith('quay.io/minio/minio@'))
        self.assert_access_recovery(primary)

    def test_client_access_failure_records_mirror_without_changing_original(self):
        primary = next(ref for ref in stage2.SUPPORTING_MIRRORS if ref.startswith('quay.io/minio/mc@'))
        self.assert_access_recovery(primary)

    def assert_integrity_failure(self, failure):
        with patch.object(sbom, 'run_json', side_effect=failure) as run:
            with self.assertRaises(ValueError):
                stage2.supporting_service_platforms({'image_reference': PRIMARY})
        self.assertEqual(run.call_count, 1)

    def test_digest_failure_never_triggers_a_mirror(self):
        self.assert_integrity_failure(sbom.SBOMError('manifest digest mismatch'))

    def test_invalid_json_never_triggers_a_mirror(self):
        self.assert_integrity_failure(ValueError('invalid JSON'))

    def test_unknown_content_never_uses_a_fallback(self):
        unknown = 'quay.io/minio/minio@sha256:' + 'e' * 64
        with patch.object(sbom, 'run_json', side_effect=sbom.SBOMCommandError('unavailable')) as run:
            with self.assertRaisesRegex(sbom.SBOMError, 'Cannot inventory'):
                stage2.supporting_service_platforms({'image_reference': unknown})
        run.assert_called_once_with(command(unknown))

    def test_failed_mirror_does_not_omit_the_service_or_return_empty_success(self):
        with patch.object(sbom, 'run_json', side_effect=sbom.SBOMCommandError('unavailable')) as run:
            with self.assertRaisesRegex(sbom.SBOMError, 'Cannot inventory'):
                stage2.supporting_service_platforms({'image_reference': PRIMARY})
        self.assertEqual(run.call_count, 2)

    def test_missing_platform_still_blocks_the_mirrored_inventory(self):
        index = index_document()
        index['manifests'].pop()
        with patch.object(sbom, 'run_json', side_effect=[sbom.SBOMCommandError('unavailable'), index]):
            with self.assertRaisesRegex(ValueError, 'amd64 and arm64'):
                stage2.supporting_service_platforms({'image_reference': PRIMARY})

    def assert_retrieval_rejected(self, retrieval):
        with self.assertRaisesRegex(sbom.SBOMError, 'unapproved'):
            stage2.validate_retrieval_reference({'image_reference': PRIMARY, 'retrieval_reference': retrieval})

    def test_offline_verifier_rejects_changed_digest(self):
        self.assert_retrieval_rejected(MIRROR.replace(DIGEST, 'sha256:' + 'd' * 64))

    def test_offline_verifier_rejects_unapproved_owner(self):
        self.assert_retrieval_rejected(MIRROR.replace('teableio', 'another-owner'))

    def test_offline_verifier_rejects_mutable_tag(self):
        self.assert_retrieval_rejected(MIRROR.split('@')[0] + ':latest')

    def test_offline_verifier_rejects_credential_bearing_url(self):
        self.assert_retrieval_rejected('https://user:secret@example.test/private')

    def test_first_party_cannot_claim_the_supporting_mirror_exception(self):
        with self.assertRaisesRegex(sbom.SBOMError, 'first-party'):
            stage2.validate_retrieval_reference({'image_reference': PRIMARY, 'retrieval_reference': MIRROR,
                                                'scope': 'first-party-runtime'})

    def test_raw_manifest_bytes_are_verified_not_reserialized_or_trusted(self):
        raw = b'{ "schemaVersion": 2, "manifests": [] }\n'
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        response = subprocess.CompletedProcess([], 0, stdout=raw)
        with patch.object(sbom.subprocess, 'run', return_value=response) as run:
            self.assertEqual(sbom.run_json(command(PRIMARY), expected_digest=digest), json.loads(raw))
        self.assertEqual(run.call_count, 1)
        different_bytes = subprocess.CompletedProcess([], 0, stdout=json.dumps(json.loads(raw)).encode())
        with patch.object(sbom.subprocess, 'run', return_value=different_bytes) as run:
            with self.assertRaisesRegex(sbom.SBOMError, 'pinned digest') as error:
                sbom.run_json(command(PRIMARY), expected_digest=digest)
        self.assertNotIsInstance(error.exception, sbom.SBOMCommandError)
        self.assertEqual(run.call_count, 1)

    def test_malformed_expected_digest_is_rejected_before_any_request(self):
        with patch.object(sbom.subprocess, 'run') as run:
            with self.assertRaisesRegex(sbom.SBOMError, 'invalid expected'):
                sbom.run_json(command(PRIMARY), expected_digest='sha256:bad')
        run.assert_not_called()

    def test_legacy_unmirrored_subject_keeps_its_identity(self):
        original = 'docker.io/library/redis@sha256:' + 'a' * 64
        subject = {'image_reference': original, 'scope': 'supporting-service-runtime'}
        before = deepcopy(subject)
        self.assertEqual(stage2.validate_retrieval_reference(subject), original)
        self.assertEqual(subject, before)
