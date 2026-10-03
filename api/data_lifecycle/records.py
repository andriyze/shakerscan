"""Permanent deletion of one scan, Hunt, AI target or Model Intake submission, with what it owns.

Each kind deletes exactly the selected record and what belongs to it, never the rest of its
target:
- a scan takes its shard scans, the findings it last observed, its recorded traffic, artifacts,
  sessions and files;
- a Hunt takes its actions, traffic, sessions, candidates and the findings only it produced;
- an AI target takes its surfaces, credentials (and their mirrors in the credential store),
  findings and AI Gate scans;
- a Model Intake submission takes its evidence, runner jobs, reviews, admissions and evidence scan.
Only work still running on the selected record blocks; abandoned work on it is cancelled.
"""
from __future__ import annotations

from uuid import UUID

from .statuses import TERMINAL_BY_TABLE

ANY_ROOT = 'ANY($1::uuid[])'
RECORD_KINDS = {'scan': 'scans', 'hunt': 'hunt_runs', 'ai_target': 'ai_targets',
                'model_intake_submission': 'model_intake_submissions'}
LABELS = {'scan': 'Scan', 'hunt': 'Hunt', 'ai_target': 'AI target',
          'model_intake_submission': 'Model Intake submission'}
SUBMISSION_SCAN = f'r.id IN (SELECT s.scan_id FROM model_intake_submissions s WHERE s.id = {ANY_ROOT})'
# Execution rows that belong to the selected record: (table, status column, predicate on $1).
WORK = {
    'scan': (('scans', 'status', f'r.id = {ANY_ROOT}'),),
    'hunt': (('hunt_runs', 'status', f'r.id = {ANY_ROOT}'),),
    'ai_target': (('scans', 'status', f'r.ai_target_id = {ANY_ROOT}'),),
    'model_intake_submission': (('scans', 'status', SUBMISSION_SCAN),
                                ('model_intake_runner_jobs', 'state', f'r.submission_id = {ANY_ROOT}')),
}
TERMINAL = {**TERMINAL_BY_TABLE, 'model_intake_runner_jobs': frozenset({'completed', 'failed'})}
QUEUED = ('pending', 'queued', 'created', 'scheduled')
ABANDONED_MINUTES = 15
# Rows without a cascading FK to the record, deleted before it in this order.
DELETE_ORDER = ('tool_receipts', 'auth_sessions', 'investigation_candidates', 'findings',
                'model_intake_admissions', 'model_intake_automatic_reviews', 'scans', 'credential_profiles')


async def find(conn, kind: str, root: UUID) -> list[UUID]:
    table = RECORD_KINDS[kind]
    if not await conn.fetchval(f'SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1)', root):
        raise LookupError(f'{LABELS[kind]} not found')
    if kind != 'scan':
        return [root]
    # A parallel or discovery scan executes through child scans; they are part of the same run.
    rows = await conn.fetch("""WITH RECURSIVE tree AS (
            SELECT id, 0 AS depth, ARRAY[id] AS path FROM scans WHERE id=$1
            UNION ALL
            SELECT child.id, tree.depth + 1, tree.path || child.id FROM scans child
            JOIN tree ON child.parent_scan_id=tree.id
            WHERE tree.depth < 16 AND NOT child.id=ANY(tree.path))
        SELECT id FROM tree ORDER BY depth, id""", root)
    return [row['id'] for row in rows]


def owned(kind: str, columns: dict) -> dict[str, str]:
    """Rows the record owns without a cascading FK to it, as `r.` predicates on $1."""
    def has(table: str, *names: str) -> bool:
        return set(names) <= columns.get(table, set())

    result: dict[str, str] = {}
    if kind in ('scan', 'hunt') and has('auth_sessions', 'owner_kind', 'owner_id'):
        result['auth_sessions'] = f"r.owner_kind='{kind}' AND r.owner_id = {ANY_ROOT}"
    if kind == 'hunt':
        if has('investigation_candidates', 'hunt_run_id'):
            result['investigation_candidates'] = f'r.hunt_run_id = {ANY_ROOT}'
        if has('findings', 'hunt_run_id', 'scan_id'):
            # Findings only this Hunt produced; one a scan also observed stays with that scan.
            result['findings'] = f'r.hunt_run_id = {ANY_ROOT} AND r.scan_id IS NULL'
    if kind == 'ai_target':
        if has('scans', 'ai_target_id'):
            result['scans'] = f'r.ai_target_id = {ANY_ROOT}'
        if has('credential_profiles', 'target_kind', 'target_id'):
            # AI credentials are mirrored into the credential store homed on the AI target's id;
            # left behind, a later sync would re-create them.
            result['credential_profiles'] = f"r.target_kind = 'api' AND r.target_id = {ANY_ROOT}"
    if kind == 'model_intake_submission':
        for table in ('model_intake_admissions', 'model_intake_automatic_reviews'):
            if has(table, 'submission_id'):
                result[table] = f'r.submission_id = {ANY_ROOT}'
        if has('model_intake_submissions', 'scan_id'):
            result['scans'] = SUBMISSION_SCAN
    return result


async def owners(conn, kind: str, roots: list) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {key: [] for key in
                                    ('target_id', 'device_target_id', 'ai_target_id', 'scan_id', 'finding_id')}
    if kind == 'model_intake_submission':
        return result
    if kind == 'ai_target':
        rows = await conn.fetch('SELECT id FROM findings WHERE ai_target_id=ANY($1::uuid[])', roots)
        return {**result, 'ai_target_id': sorted(str(r) for r in roots),
                'finding_id': sorted(str(r['id']) for r in rows)}
    table = RECORD_KINDS[kind]
    target_rows = await conn.fetch(
        f'SELECT DISTINCT target_id FROM {table} WHERE id=ANY($1::uuid[]) AND target_id IS NOT NULL', roots)
    result['target_id'] = sorted(str(r['target_id']) for r in target_rows)
    findings = ('SELECT id FROM findings WHERE scan_id=ANY($1::uuid[])' if kind == 'scan' else
                'SELECT id FROM findings WHERE hunt_run_id=ANY($1::uuid[]) AND scan_id IS NULL')
    result['finding_id'] = sorted(str(r['id']) for r in await conn.fetch(findings, roots))
    if kind == 'scan':
        result['scan_id'] = sorted(str(r) for r in roots)
    return result


def _abandoned(table: str, status: str, columns: dict) -> str:
    """Never picked up, or nothing has touched it for a while (a running scan keeps no clock)."""
    clock = next((c for c in ('updated_at', 'started_at', 'created_at') if c in columns.get(table, set())), None)
    parts = [f'r.{status} = ANY($3::text[])']
    if clock and table != 'scans':
        parts.append(f"r.{clock} < NOW() - INTERVAL '{ABANDONED_MINUTES} minutes'")
    return '(' + ' OR '.join(parts) + ')'


def _work(kind: str, columns: dict):
    for table, status, scope in WORK[kind]:
        if status in columns.get(table, set()):
            unfinished = f'(r.{status} IS NULL OR NOT r.{status} = ANY($2::text[]))'
            yield table, status, scope, unfinished


async def unfinished(conn, kind: str, roots: list, columns: dict) -> dict[str, dict]:
    state: dict[str, dict] = {}
    for table, status, scope, open_rows in _work(kind, columns):
        rows = await conn.fetch(
            f"""SELECT r.id::text AS id, {_abandoned(table, status, columns)} AS abandoned FROM {table} r
                WHERE {scope} AND {open_rows}""", roots, sorted(TERMINAL.get(table, ())), list(QUEUED))
        state[table] = {'live': [r['id'] for r in rows if not r['abandoned']],
                        'abandoned': sum(1 for r in rows if r['abandoned'])}
    return state


async def blockers(conn, kind: str, roots: list, columns: dict) -> list[str]:
    issues = []
    for table, state in (await unfinished(conn, kind, roots, columns)).items():
        if not state['live']:
            continue
        shown = ', '.join(state['live'][:5]) + (', …' if len(state['live']) > 5 else '')
        how = {'scans': 'cancel them (POST /scans/{id}/cancel) or wait for them to finish',
               'hunt_runs': 'cancel it (POST /hunts/{id}/cancel) or wait for it to finish'}.get(
                   table, 'wait for them to finish')
        issues.append(f'{table}: {len(state["live"])} running record(s) ({shown}); {how}')
    return issues


async def cancel_abandoned(conn, kind: str, roots: list, columns: dict) -> dict[str, int]:
    cancelled = {}
    for table, status, scope, open_rows in _work(kind, columns):
        if table not in ('scans', 'hunt_runs'):
            continue  # other execution rows are deleted with the record
        touches = [f"{status}='cancelled'"] + [f'{c}=NOW()' for c in ('updated_at', 'completed_at')
                                               if c in columns[table]]
        rows = await conn.fetch(
            f"""UPDATE {table} r SET {', '.join(touches)}
                WHERE {scope} AND {open_rows} AND {_abandoned(table, status, columns)} RETURNING r.id""",
            roots, sorted(TERMINAL.get(table, ())), list(QUEUED))
        if rows:
            cancelled[table] = len(rows)
    return cancelled
