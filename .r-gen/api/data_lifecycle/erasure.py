"""Complete erasure for record deletion: owned rows the FK graph cannot reach, and files.

A deleted target takes its scans, Hunts, credentials, sessions and collection bindings with it,
and a deleted finding takes its evidence. Evidence blobs and scan artifacts are content-addressed
and can be shared, so a row is erased only once nothing that survives still points at it, and a
file only once no surviving row names it. Files are erased after the database commit; what could
not be erased is recorded in the deletion receipt rather than silently kept.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

# Credential kinds are all homed on a targets row; 'device' is a host's SSH or device identity.
CREDENTIAL_KINDS = "('web','api','network','device')"
# Rows an owned credential or collection carries onto other targets. Deleting the owner deletes
# them too, so they are not a cascade that "crosses target ownership".
OWNED_ACROSS_TARGETS = frozenset({
    'auth_sessions', 'credential_profile_bindings',
    'request_collection_bindings', 'request_collection_selections',
})
EVIDENCE_REFERENCES = (
    ('http_transactions', ('request_headers_object_id', 'request_body_object_id',
                           'response_headers_object_id', 'response_body_object_id')),
    ('tool_receipts', ('stdout_evidence_object_id', 'stderr_evidence_object_id', 'output_artifact_id')),
    ('evidence_instances', ('evidence_object_id',)),
)
RESULT_FILE_LIMIT = 5000


def results_dir() -> Path:
    return Path(os.environ.get('RESULTS_DIR', '/results'))


def owned_by_targets(columns: dict, kind: str = 'target') -> dict[str, str]:
    """Rows a target owns without a cascading FK to it, keyed by table, as `r.` predicates on $1."""
    owned: dict[str, str] = {}
    if {'target_id', 'normalized_scope'} <= columns.get('scope_receipts', set()):
        # The target's authorization scope records name its URL and hosts. A deletion's own
        # receipts hold only IDs and keep its replay working, so they stay.
        owned['scope_receipts'] = ("r.target_id = ANY($1::uuid[]) "
                                   "AND COALESCE(r.normalized_scope->>'kind', '') <> 'record_deletion'")
    if kind == 'domain' and 'root_domain' in columns.get('discovery_runs', set()):
        owned['discovery_runs'] = ('lower(r.root_domain) IN (SELECT lower(t.root_domain) FROM targets t '
                                   'WHERE t.id = ANY($1::uuid[]) AND t.root_domain IS NOT NULL)')
    if 'credential_profiles' in columns:
        owned['credential_profiles'] = f"r.target_id = ANY($1::uuid[]) AND r.target_kind IN {CREDENTIAL_KINDS}"
    scans = columns.get('scans', set())
    scan_owners = [f'r.{column} = ANY($1::uuid[])' for column in ('target_id', 'device_target_id') if column in scans]
    if scan_owners:
        # Scans used to be retained with a detached link; their reports, artifacts, recorded raw
        # traffic and sealed session state now go with the target.
        owned['scans'] = ' OR '.join(scan_owners)
    if {'binding_kind', 'binding_id'} <= columns.get('credential_profile_bindings', set()):
        owned['credential_profile_bindings'] = (
            "r.binding_kind='target' AND r.binding_id = ANY(ARRAY(SELECT x::text FROM unnest($1::uuid[]) x))")
    if 'target_id' in columns.get('auth_sessions', set()):
        owned['auth_sessions'] = 'r.target_id = ANY($1::uuid[])'
    if 'target_id' in columns.get('request_collection_bindings', set()):
        owned['request_collection_bindings'] = 'r.target_id = ANY($1::uuid[])'
    return owned


def _rows(table: str, clause: str, alias: str) -> str:
    return f'SELECT {alias}.id FROM public."{table}" {alias} WHERE {clause.replace("r.", alias + ".")}'


def evidence_clause(deleted: dict[str, str], columns: dict) -> str | None:
    """Evidence rows the deleted records own or reference, as an `r.` predicate on $1."""
    if 'evidence_objects' not in columns:
        return None
    parts = []
    evidence = columns['evidence_objects']
    for column, table in (('scan_id', 'scans'), ('finding_id', 'findings')):
        if column in evidence and table in deleted:
            parts.append(f'r.{column} IN ({_rows(table, deleted[table], "o" + table[0])})')
    for table, references in EVIDENCE_REFERENCES:
        if table not in deleted or not set(references) <= columns.get(table, set()):
            continue
        refs = ', '.join(f'x.{column}' for column in references)
        parts.append(f'r.id IN (SELECT unnest(ARRAY[{refs}]) FROM public."{table}" x '
                     f'WHERE {deleted[table].replace("r.", "x.")})')
    return ' OR '.join(f'({part})' for part in parts) if parts else None


def _unreferenced(columns: dict) -> str:
    """Evidence no surviving row points at (run after the owning rows are deleted)."""
    checks = []
    for table, references in EVIDENCE_REFERENCES:
        if set(references) <= columns.get(table, set()):
            refs = ', '.join(f'x.{column}' for column in references)
            checks.append(f'NOT EXISTS (SELECT 1 FROM public."{table}" x WHERE e.id IN ({refs}))')
    evidence = columns.get('evidence_objects', set())
    if 'scan_id' in evidence:
        checks.append('(e.scan_id IS NULL OR NOT EXISTS (SELECT 1 FROM scans s WHERE s.id=e.scan_id))')
    if 'finding_id' in evidence:
        checks.append('(e.finding_id IS NULL OR NOT EXISTS (SELECT 1 FROM findings f WHERE f.id=e.finding_id))')
    return ' AND '.join(checks) or 'true'


async def capture(conn, deleted: dict[str, str], columns: dict, roots: list) -> dict[str, Any]:
    """Before deleting: the evidence, artifacts and scan files the operation must erase."""
    clause = evidence_clause(deleted, columns)
    evidence = []
    if clause:
        evidence = [dict(row) for row in await conn.fetch(
            f'SELECT r.id, r.storage_uri FROM evidence_objects r WHERE {clause}', roots)]
    artifacts: list[str] = []
    scans: list[dict[str, Any]] = []
    if 'scans' in deleted:
        scan_rows = _rows('scans', deleted['scans'], 's')
        if 'scan_artifacts' in columns:
            artifacts = sorted({row['storage_uri'] for row in await conn.fetch(
                f'SELECT DISTINCT storage_uri FROM scan_artifacts WHERE (scan_id IN ({scan_rows}) '
                f'OR parent_scan_id IN ({scan_rows})) AND storage_uri IS NOT NULL', roots)})
        job = 'job_id' if 'job_id' in columns.get('scans', set()) else 'NULL::text'
        scans = [{'id': str(row['id']), 'job_id': row['job_id']} for row in await conn.fetch(
            f'SELECT s.id, s.{job} AS job_id FROM scans s WHERE s.id IN ({scan_rows})', roots)]
    return {'evidence': evidence, 'artifacts': artifacts, 'scans': scans}


async def delete_evidence(conn, captured: dict[str, Any], columns: dict) -> list[str]:
    """After the owners are gone: delete captured evidence nothing survives to reference.

    Finding evidence cascades away with its finding before this runs, so the storage of every
    captured row that no longer exists is returned, however it was removed.
    """
    ids = [row['id'] for row in captured['evidence']]
    if not ids:
        return []
    await conn.execute(
        f'DELETE FROM evidence_objects e WHERE e.id = ANY($1::uuid[]) AND {_unreferenced(columns)}', ids)
    kept = {row['id'] for row in await conn.fetch(
        'SELECT id FROM evidence_objects WHERE id = ANY($1::uuid[])', ids)}
    return sorted({row['storage_uri'] for row in captured['evidence']
                   if row['id'] not in kept and row['storage_uri']})


async def delete_owner_stats(conn, columns: dict, scan_ids: list[str], hunt_ids: list[str]) -> None:
    # Traffic statistics and settled budget reservations are keyed by owner, without an FK.
    for table in ('http_archive_stats', 'budget_reservations'):
        if not {'owner_kind', 'owner_id'} <= columns.get(table, set()):
            continue
        for kind, ids in (('scan', scan_ids), ('hunt', hunt_ids)):
            if ids:
                await conn.execute(f'DELETE FROM {table} WHERE owner_kind=$1 AND owner_id::text=ANY($2::text[])',
                                   kind, ids)


def _result_owner(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open() as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    nested = data.get('result') if isinstance(data.get('result'), dict) else {}
    scan = data.get('scan_id') or nested.get('scan_id')
    job = data.get('job_id') or nested.get('job_id')
    return (str(scan) if scan else None), (str(job) if job else None)


def _scan_files(base: Path, scans: list[dict[str, Any]]) -> tuple[list[Path], list[str]]:
    """Result files that provably belong to the deleted scans; unprovable matches are reported."""
    scan_ids = {scan['id'] for scan in scans}
    job_ids = {str(scan['job_id']) for scan in scans if scan.get('job_id')}
    files: list[Path] = []
    unverified: list[str] = []
    for scan_id in scan_ids:
        for name in (f'{scan_id}_checkpoint.json', f'{scan_id}_checkpoint.json.endpoint-manifest.json'):
            if (base / name).is_file():
                files.append(base / name)
    candidates: list[Path] = []
    for job in job_ids:
        candidates.extend(base.glob(f'*/*_{job[:8]}.json'))
        if len(candidates) > RESULT_FILE_LIMIT:
            break
    for path in sorted(set(candidates))[:RESULT_FILE_LIMIT]:
        scan, job = _result_owner(path)
        if scan in scan_ids or job in job_ids:
            files.append(path)
            latest = path.parent / 'latest.json'
            if latest.is_file() and _result_owner(latest) in ((scan, job),) and latest not in files:
                files.append(latest)
        else:
            unverified.append(str(path))
    return files, unverified


def _prune_artifact_dirs(base: Path, scans: list[dict[str, Any]]) -> None:
    """Remove a deleted scan's now-empty artifact directories, whose names are its ID.

    Only empty directories are removed, deepest first; a file that could not be erased keeps its
    directory and is already reported by the caller.
    """
    root = base / 'scan-artifacts'
    for scan in scans:
        try:
            scan_dir = root / str(uuid.UUID(str(scan['id'])))
        except (KeyError, ValueError):
            continue
        if not scan_dir.is_dir() or scan_dir.is_symlink():
            continue
        nested = [p for p in scan_dir.rglob('*') if p.is_dir() and not p.is_symlink()]
        for directory in sorted(nested, key=lambda p: len(p.parts), reverse=True) + [scan_dir]:
            try:
                directory.rmdir()
            except OSError:
                pass


async def erase_files(conn, captured: dict[str, Any], evidence_uris: list[str]) -> dict[str, Any]:
    """Erase files only deleted rows named. Runs after commit; never raises."""
    from artifact_storage import delete_object as delete_artifact
    from evidence_storage import delete_remote_evidence_object, local_evidence_path

    base = results_dir()
    erased, missing, errors = [], [], []
    for uri in evidence_uris:
        if await conn.fetchval('SELECT EXISTS(SELECT 1 FROM evidence_objects WHERE storage_uri=$1)', uri):
            continue
        local = local_evidence_path(base, uri)
        try:
            if local is not None:
                local.unlink()
                erased.append(uri)
            elif uri.startswith('s3:'):
                outcome = await asyncio.to_thread(delete_remote_evidence_object, uri)
                (erased if outcome.get('deleted') else errors).append(
                    uri if outcome.get('deleted') else {'uri': uri, 'error': str(outcome.get('error') or 'delete_failed')})
        except FileNotFoundError:
            missing.append(uri)
        except OSError as exc:
            errors.append({'uri': uri, 'error': type(exc).__name__})
    for uri in captured['artifacts']:
        if await conn.fetchval('SELECT EXISTS(SELECT 1 FROM scan_artifacts WHERE storage_uri=$1)', uri):
            continue
        try:
            (erased if await asyncio.to_thread(delete_artifact, uri, results_dir=base) else missing).append(uri)
        except Exception as exc:  # storage errors are reported, not raised after commit
            errors.append({'uri': uri, 'error': type(exc).__name__})
    await asyncio.to_thread(_prune_artifact_dirs, base, captured['scans'])
    files, unverified = await asyncio.to_thread(_scan_files, base, captured['scans'])
    for path in files:
        try:
            path.unlink()
            erased.append(str(path))
        except FileNotFoundError:
            missing.append(str(path))
        except OSError as exc:
            errors.append({'uri': str(path), 'error': type(exc).__name__})
    return {'files_erased': len(erased), 'files_missing': len(missing), 'file_errors': errors[:50],
            'unverified_result_files': unverified[:50], 'complete': not errors}
