"""Immutable preview/approval/execution using the existing Arsenal receipt ledger."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import secrets
from uuid import UUID, uuid4
from fastapi import HTTPException

from .inventory import catalog, cascade_plan, decoded, digest, find_roots, inventory, lock_inventory

COMMAND = 'data.records.delete'
CONFIRMATIONS = {'confirm_authorized', 'confirm_scope_reviewed', 'confirm_delete_records'}


def public_preview(preview_id, payload, scope_id):
    manifest = payload['manifest']
    return {**manifest, 'preview_id': str(preview_id), 'preview_hash': payload['preview_hash'],
            'scope_receipt_id': scope_id, 'expires_at': payload['expires_at'],
            'would_delete': manifest['records']['delete'].get('findings', {}).get('count', 0),
            'dry_run': True}


async def preview(pool, selection):
    async with pool.acquire() as conn:
        async with conn.transaction(isolation='repeatable_read'):
            await conn.execute("SET LOCAL statement_timeout='20s'")
            columns, edges = await catalog(conn)
            roots = await find_roots(conn, selection)
            manifest, _ = await inventory(conn, selection, roots, columns, edges)
            preview_id = uuid4()
            scope_id = 'record-delete:' + str(preview_id)
            expires = datetime.now(timezone.utc) + timedelta(minutes=10)
            payload = {'selection': selection, 'manifest': manifest,
                       'expires_at': expires.isoformat(), 'preview_hash': digest(manifest)}
            targets = manifest['owners']['target_id']
            await conn.execute("""INSERT INTO scope_receipts
                (id,target_id,input_scope,normalized_scope,verdict,warnings)
                VALUES ($1,$2,$3::jsonb,$3::jsonb,'needs_approval',$4::jsonb)""",
                scope_id, UUID(targets[0]) if len(targets) == 1 else None,
                json.dumps({'kind': 'record_deletion', 'preview_id': str(preview_id),
                            'preview_hash': payload['preview_hash'], 'owners': manifest['owners']}),
                json.dumps(manifest['retained']))
            await conn.execute("""INSERT INTO command_results
                (id,command,status,dry_run,risk_tier,scope_receipt_id,operator_message,result_json,created_by)
                VALUES ($1,$2,'approval_required',true,'dangerous',$3,
                        'Record deletion preview; no records deleted',$4::jsonb,'record_deletion_api')""",
                preview_id, COMMAND, scope_id, json.dumps(payload))
    return public_preview(preview_id, payload, scope_id)


def validate_approval(row, preview_row, payload, approval_id, now):
    if row is None:
        raise HTTPException(404, 'Approval receipt not found')
    confirmations = set(decoded(row['confirmations']) or [])
    expected = {'preview_id': str(preview_row['id']), 'preview_hash': payload['preview_hash']}
    context = decoded(row['action_context']) or {}
    expires = row['expires_at']
    preview_expires = datetime.fromisoformat(payload['expires_at'])
    if (row['status'] != 'active' or not row['approved_by'] or row['denial_reason']
        or row['risk_tier'] != 'dangerous' or row['action_name'] != COMMAND
        or row['scope_receipt_id'] != preview_row['scope_receipt_id']
        or not CONFIRMATIONS.issubset(confirmations) or context != expected
        or not expires or not now < expires <= preview_expires
        or row['created_at'] < preview_row['created_at']):
        raise HTTPException(409, 'Approval must be active, dangerous, unexpired, and bound to this exact preview')


def check_expected(payload, kind=None, entity_id=None, selection=None):
    manifest = payload['manifest']
    if kind and manifest['kind'] != kind:
        raise HTTPException(409, 'Deletion preview is for a different record kind')
    if entity_id and manifest['root_ids'] != [str(entity_id)]:
        raise HTTPException(409, 'Deletion preview does not match this exact record')
    if selection is not None and payload['selection'] != selection:
        raise HTTPException(409, 'Cleanup filters changed; inspect a new preview')


async def execute(pool, preview_id, approval_id, *, preview_hash=None, kind=None, entity_id=None, selection=None):
    if not preview_id or not approval_id:
        raise HTTPException(428, 'Inspect POST /data-deletion/preview and approve its exact manifest before deleting')
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow('SELECT * FROM command_results WHERE id=$1 AND command=$2', UUID(str(preview_id)), COMMAND)
                if not row:
                    raise HTTPException(404, 'Deletion preview not found')
                payload = decoded(row['result_json'])
                columns, edges = await catalog(conn)
                plan = cascade_plan(payload['selection']['kind'], edges, columns)
                await lock_inventory(conn, columns, plan)
                row = await conn.fetchrow('SELECT * FROM command_results WHERE id=$1 AND command=$2 FOR UPDATE', UUID(str(preview_id)), COMMAND)
                if not row:
                    raise HTTPException(404, 'Deletion preview not found')
                payload = decoded(row['result_json'])
                check_expected(payload, kind, entity_id, selection)
                if preview_hash and not secrets.compare_digest(preview_hash, payload['preview_hash']):
                    raise HTTPException(409, 'Preview hash does not match')
                if row['status'] == 'completed':
                    if str(row['approval_receipt_id']) != str(approval_id):
                        raise HTTPException(409, 'Preview was consumed by another approval')
                    return {**payload['result'], 'idempotent_replay': True}
                if row['status'] != 'approval_required':
                    raise HTTPException(409, 'Deletion preview is not executable')
                now = datetime.now(timezone.utc)
                if now >= datetime.fromisoformat(payload['expires_at']):
                    raise HTTPException(409, 'Deletion preview expired; inspect a new preview')
                approval = await conn.fetchrow('SELECT * FROM approval_receipts WHERE id=$1 FOR UPDATE', UUID(str(approval_id)))
                validate_approval(approval, row, payload, approval_id, now)
                roots = [UUID(v) for v in payload['manifest']['root_ids']]
                # Repeat the complete inventory AFTER all writer/hold locks are held.
                current, plan = await inventory(conn, payload['selection'], roots, columns, edges)
                if current['blockers']:
                    raise HTTPException(409, {'message': 'Deletion is blocked', 'blockers': current['blockers']})
                if not secrets.compare_digest(digest(current), payload['preview_hash']):
                    raise HTTPException(409, 'Records or ownership changed; inspect a new preview')
                # Preserve the storage index: removing a finding must not silently orphan
                # blobs or delete shared content. External deletion uses evidence retention.
                if plan[1].get('evidence_objects'):
                    await conn.execute(f"UPDATE evidence_objects r SET finding_id=NULL WHERE {plan[1]['evidence_objects']}", roots)
                if current['kind'] == 'target':
                    if 'credential_profiles' in columns:
                        await conn.execute("DELETE FROM credential_profiles WHERE target_id=ANY($1::uuid[]) AND target_kind IN ('web','api','network')", roots)
                    removed = await conn.fetch('DELETE FROM targets WHERE id=ANY($1::uuid[]) RETURNING id', roots)
                else:
                    removed = await conn.fetch('DELETE FROM findings WHERE id=ANY($1::uuid[]) RETURNING id', roots)
                if len(removed) != len(roots):
                    raise HTTPException(409, 'Records changed during deletion; no changes committed')
                for owner, table in (('target_id', 'targets'), ('device_target_id', 'device_targets'), ('ai_target_id', 'ai_targets')):
                    ids = [UUID(v) for v in current['owners'][owner]]
                    if ids and 'active_findings_count' in columns.get(table, set()):
                        await conn.execute(f"""UPDATE {table} t SET active_findings_count=(
                            SELECT COUNT(*) FROM findings f WHERE f.{owner}=t.id AND f.status='active'), updated_at=NOW()
                            WHERE t.id=ANY($1::uuid[])""", ids)
                result = {'status': 'deleted', 'operation_id': str(preview_id), 'preview_id': str(preview_id),
                          'approval_receipt_id': str(approval_id), 'kind': current['kind'],
                          'deleted_ids': current['root_ids'], 'deleted': len(removed),
                          'deleted_records': {k: v['count'] for k, v in current['records']['delete'].items()},
                          'detached_records': {k: v['count'] for k, v in current['records']['detach'].items()},
                          'retained': current['retained'], 'external_files_deleted': False,
                          'dry_run': False, 'idempotent_replay': False}
                payload['result'] = result
                await conn.execute("""UPDATE command_results SET status='completed', dry_run=false,
                    approval_receipt_id=$2, operator_message='Record deletion completed; external files retained',
                    result_json=$3::jsonb WHERE id=$1""", UUID(str(preview_id)), UUID(str(approval_id)), json.dumps(payload))
                return result
    except Exception as exc:
        if getattr(exc, 'sqlstate', '') in {'55P03', '57014', '40001', '40P01', '23503', '23514'}:
            raise HTTPException(409, 'Deletion conflicted with active work or ownership; no changes committed. Retry or inspect a new preview.') from exc
        raise
