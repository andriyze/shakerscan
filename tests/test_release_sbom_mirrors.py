"""Known identical-content mirrors repair retrieval, never the SBOM's artifact identity."""
from copy import deepcopy
import hashlib
import json
import subprocess
from unittest.mock import patch

import pytest

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


def test_successful_original_does_not_use_or_record_a_mirror():
    service = {'image_reference': PRIMARY}
    with patch.object(sbom, 'run_json', return_value=index_document()) as run:
        assert set(stage2.supporting_service_platforms(service)) == {'linux/amd64', 'linux/arm64'}
    run.assert_called_once_with(command(PRIMARY), expected_digest=DIGEST)
    assert service == {'image_reference': PRIMARY}


@pytest.mark.parametrize('primary,mirror', stage2.SUPPORTING_MIRRORS.items())
def test_access_failure_records_the_actual_mirror_without_changing_original(primary, mirror):
    digest = primary.rsplit('@', 1)[1]
    service = {'image_reference': primary, 'index_digest': digest}
    failure = sbom.SBOMCommandError('registry authentication/access rejected')
    with patch.object(sbom, 'run_json', side_effect=[failure, index_document()]) as run:
        platforms = stage2.supporting_service_platforms(service)
    assert len(platforms) == 2
    assert service == {'image_reference': primary, 'index_digest': digest, 'retrieval_reference': mirror}
    assert [c.args[0] for c in run.call_args_list] == [command(primary), command(mirror)]
    assert all(c.kwargs == {'expected_digest': digest} for c in run.call_args_list)
    assert stage2.validate_retrieval_reference(service) == mirror


@pytest.mark.parametrize('failure', [sbom.SBOMError('manifest digest mismatch'), ValueError('invalid JSON')])
def test_integrity_failures_never_trigger_a_mirror(failure):
    with patch.object(sbom, 'run_json', side_effect=failure) as run:
        with pytest.raises(ValueError):
            stage2.supporting_service_platforms({'image_reference': PRIMARY})
    assert run.call_count == 1


def test_unknown_content_never_uses_a_fallback():
    unknown = 'quay.io/minio/minio@sha256:' + 'e' * 64
    with patch.object(sbom, 'run_json', side_effect=sbom.SBOMCommandError('unavailable')) as run:
        with pytest.raises(sbom.SBOMError, match='Cannot inventory'):
            stage2.supporting_service_platforms({'image_reference': unknown})
    run.assert_called_once_with(command(unknown))


def test_failed_mirror_does_not_omit_the_service_or_return_empty_success():
    with patch.object(sbom, 'run_json', side_effect=sbom.SBOMCommandError('unavailable')) as run:
        with pytest.raises(sbom.SBOMError, match='Cannot inventory'):
            stage2.supporting_service_platforms({'image_reference': PRIMARY})
    assert run.call_count == 2


def test_missing_platform_still_blocks_the_mirrored_inventory():
    index = index_document()
    index['manifests'].pop()
    with patch.object(sbom, 'run_json', side_effect=[sbom.SBOMCommandError('unavailable'), index]):
        with pytest.raises(ValueError, match='amd64 and arm64'):
            stage2.supporting_service_platforms({'image_reference': PRIMARY})


@pytest.mark.parametrize('retrieval', [
    MIRROR.replace(DIGEST, 'sha256:' + 'd' * 64),
    MIRROR.replace('teableio', 'another-owner'),
    MIRROR.split('@')[0] + ':latest',
    'https://user:secret@example.test/private',
])
def test_offline_verifier_rejects_unapproved_or_mutable_retrieval(retrieval):
    with pytest.raises(sbom.SBOMError, match='unapproved'):
        stage2.validate_retrieval_reference({'image_reference': PRIMARY, 'retrieval_reference': retrieval})


def test_first_party_cannot_claim_the_supporting_mirror_exception():
    with pytest.raises(sbom.SBOMError, match='first-party'):
        stage2.validate_retrieval_reference({'image_reference': PRIMARY, 'retrieval_reference': MIRROR,
                                            'scope': 'first-party-runtime'})


def test_raw_manifest_bytes_are_verified_not_reserialized_or_trusted():
    raw = b'{ "schemaVersion": 2, "manifests": [] }\n'
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    response = subprocess.CompletedProcess([], 0, stdout=raw)
    with patch.object(sbom.subprocess, 'run', return_value=response) as run:
        assert sbom.run_json(command(PRIMARY), expected_digest=digest) == json.loads(raw)
    assert run.call_count == 1
    different_bytes = subprocess.CompletedProcess([], 0, stdout=json.dumps(json.loads(raw)).encode())
    with patch.object(sbom.subprocess, 'run', return_value=different_bytes) as run:
        with pytest.raises(sbom.SBOMError, match='pinned digest') as error:
            sbom.run_json(command(PRIMARY), expected_digest=digest)
    assert not isinstance(error.value, sbom.SBOMCommandError)
    assert run.call_count == 1


def test_malformed_expected_digest_is_rejected_before_any_request():
    with patch.object(sbom.subprocess, 'run') as run:
        with pytest.raises(sbom.SBOMError, match='invalid expected'):
            sbom.run_json(command(PRIMARY), expected_digest='sha256:bad')
    run.assert_not_called()


def test_legacy_unmirrored_subject_keeps_its_identity():
    original = 'docker.io/library/redis@sha256:' + 'a' * 64
    subject = {'image_reference': original, 'scope': 'supporting-service-runtime'}
    before = deepcopy(subject)
    assert stage2.validate_retrieval_reference(subject) == original
    assert subject == before
