"""Behavioral contracts for record deletion (no network or scanner execution)."""
import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from api.data_lifecycle.inventory import cascade_plan, digest, ident
from api.data_lifecycle.router import DeletionSelection, DeletionExecution
from api.data_lifecycle.service import check_expected, validate_approval, execute


def edge(parent, child, action='c', child_key=None):
    return {'parent': parent, 'child': child, 'action': action,
            'child_keys': [child_key or parent.rstrip('s') + '_id'], 'parent_keys': ['id']}


def test_cascade_preserves_sibling_targets_scans_and_external_storage_index():
    edges = [edge('targets', 'targets', 'n', 'parent_target_id'),
             edge('targets', 'scans', 'n'), edge('targets', 'findings'),
             edge('findings', 'evidence_objects'), edge('findings', 'finding_verifications'),
             edge('targets', 'schedules'), edge('credential_profiles', 'auth_sessions', child_key='profile_id')]
    deleted, detached, retained, restricted = cascade_plan('target', edges, {'credential_profiles': set()})
    assert set(deleted) == {'targets', 'findings', 'finding_verifications', 'schedules', 'credential_profiles', 'auth_sessions'}
    assert set(detached) == {'evidence_objects'}
    assert set(retained) == {'targets', 'scans'}
    assert not restricted
    assert 'ANY($1::uuid[])' in deleted['findings']
    assert 'target_kind' in deleted['credential_profiles']


def test_finding_deletion_never_expands_to_target_or_scans():
    deleted, _, _, _ = cascade_plan('findings', [edge('targets', 'findings'), edge('findings', 'finding_verifications')], {})
    assert set(deleted) == {'findings', 'finding_verifications'}


def test_cycles_fail_closed():
    with pytest.raises(HTTPException, match='Cyclic'):
        cascade_plan('findings', [edge('findings', 'child'), edge('child', 'findings')], {})


def test_identifiers_are_quoted_and_never_operator_sql():
    assert ident('findings') == '"findings"'
    for value in ['public.findings', 'findings;DROP TABLE targets', 'a"b', '']:
        with pytest.raises(HTTPException):
            ident(value)


def test_digest_is_order_independent_and_binds_exact_candidate_set():
    assert digest({'a': 1, 'b': 2}) == digest({'b': 2, 'a': 1})
    assert digest({'ids': ['a']}) != digest({'ids': ['b']})


def test_selection_deduplicates_and_sorts_explicit_ids():
    a, b = str(uuid4()), str(uuid4())
    selection = DeletionSelection(kind='findings', finding_ids=[b, a, b]).selection()
    assert selection == {'kind': 'findings', 'finding_ids': sorted([a, b])}


@pytest.mark.parametrize('payload', [
    {'kind': 'target'}, {'kind': 'findings'},
    {'kind': 'target', 'target_id': str(uuid4()), 'finding_ids': [str(uuid4())]},
    {'kind': 'findings', 'finding_ids': [str(uuid4())], 'older_than_days': 1},
    {'kind': 'findings', 'finding_ids': [str(uuid4())], 'status': 'active'},
    {'kind': 'findings', 'older_than_days': 1, 'scan_id': str(uuid4())},
    {'kind': 'findings', 'older_than_days': 0},
    {'kind': 'findings', 'older_than_days': 1, 'status': 'nonsense'},
    {'kind': 'findings', 'finding_ids': ['not-a-uuid']},
    {'kind': 'findings', 'finding_ids': [str(uuid4())] * 501},
    {'kind': 'findings', 'older_than_days': 1, 'extra': True},
])
def test_invalid_selection_is_rejected(payload):
    with pytest.raises(ValidationError):
        DeletionSelection(**payload)


def approval_fixture():
    now = datetime.now(timezone.utc)
    preview_id, approval_id = uuid4(), uuid4()
    preview = {'id': preview_id, 'created_at': now - timedelta(seconds=3), 'scope_receipt_id': 'test-scope'}
    payload = {'preview_hash': 'a' * 64, 'expires_at': (now + timedelta(minutes=10)).isoformat()}
    approval = {'id': approval_id, 'scope_receipt_id': 'test-scope', 'risk_tier': 'dangerous',
        'action_name': 'data.records.delete', 'status': 'active', 'approved_by': 'operator',
        'denial_reason': None, 'created_at': now - timedelta(seconds=1),
        'expires_at': now + timedelta(minutes=5),
        'confirmations': ['confirm_authorized', 'confirm_scope_reviewed', 'confirm_delete_records'],
        'action_context': {'preview_id': str(preview_id), 'preview_hash': 'a' * 64}}
    return now, preview, payload, approval


def test_valid_exact_dangerous_approval():
    now, preview, payload, approval = approval_fixture()
    validate_approval(approval, preview, payload, approval['id'], now)


@pytest.mark.parametrize('field,value', [
    ('scope_receipt_id', 'wrong-scope'), ('risk_tier', 'active'), ('status', 'revoked'),
    ('action_name', 'evidence.retention_sweep'), ('approved_by', None), ('denial_reason', 'denied'),
    ('confirmations', ['confirm_authorized']), ('action_context', {}),
    ('expires_at', None), ('expires_at', datetime(2000, 1, 1, tzinfo=timezone.utc)),
    ('expires_at', datetime(2100, 1, 1, tzinfo=timezone.utc)),
    ('created_at', datetime(2000, 1, 1, tzinfo=timezone.utc)),
])
def test_wrong_revoked_unbound_or_expired_approval_is_rejected(field, value):
    now, preview, payload, approval = approval_fixture()
    approval[field] = value
    with pytest.raises(HTTPException) as exc:
        validate_approval(approval, preview, payload, approval['id'], now)
    assert exc.value.status_code == 409


def test_missing_approval_cannot_reach_database():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(execute(None, uuid4(), None))
    assert exc.value.status_code == 428


def test_legacy_route_cannot_consume_another_entity_preview():
    a, b = str(uuid4()), str(uuid4())
    payload = {'manifest': {'kind': 'findings', 'root_ids': [a]}, 'selection': {'kind': 'findings', 'finding_ids': [a]}}
    check_expected(payload, 'findings', a)
    for kwargs in ({'kind': 'target'}, {'entity_id': b}, {'selection': {'kind': 'findings', 'finding_ids': [b]}}):
        with pytest.raises(HTTPException):
            check_expected(payload, **kwargs)


def test_execute_request_requires_hash_and_approval():
    with pytest.raises(ValidationError):
        DeletionExecution(preview_id=uuid4(), preview_hash='not-a-digest')


def test_preserving_sensitive_is_not_permission_to_erase_or_detach_holds():
    from api.data_lifecycle.inventory import hold_predicate
    destructive = hold_predicate()
    preserving = hold_predicate(preserving=True)
    assert "'sensitive'" in destructive and "'sensitive'" not in preserving
    for predicate in (destructive, preserving):
        assert "'legal_hold'" in predicate and "'audit'" in predicate
        assert "'operational_hold'" in predicate
        assert "->'metadata_json'" in predicate
        assert "->>'retention_policy'" in predicate
