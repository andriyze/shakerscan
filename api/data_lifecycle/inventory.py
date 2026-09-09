"""Build a content-free, exact FK-cascade inventory before deleting database records.

Historical scans and external evidence are deliberately retained. Never infer ownership
from host suffixes, URL substrings, or age. Catalog identifiers are validated and quoted;
all operator inputs are parameters. Unknown/cyclic cascades fail closed.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from .statuses import TERMINAL_BY_TABLE

MAX_RECORDS = 10000
EXECUTION_TABLES = ('scans', 'hunt_runs', 'agent_hunt_runs', 'device_agent_runs',
                    'research_episodes', 'campaigns', 'scan_campaigns', 'finding_verifications')
PROTECTED = ('legal_hold', 'audit', 'sensitive')
RETAINED = [
    'Historical scan reports and scan artifacts are retained; their target link is detached.',
    'External evidence files and their storage index are retained, not erased.',
    'Exports, backups, detached audit records, and other targets are retained.',
    'Later scans or discovery may create a new target or finding record.',
    'Original links of retained and detached rows are recorded in this deletion receipt.',
]


def ident(value: str) -> str:
    if not re.fullmatch(r'[a-z_][a-z0-9_]*', value):
        raise HTTPException(409, 'Unsupported database identifier in deletion inventory')
    return '"' + value + '"'


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def decoded(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def catalog(conn):
    columns = defaultdict(set)
    for row in await conn.fetch("""SELECT table_name, column_name FROM information_schema.columns
                                  WHERE table_schema='public'"""):
        columns[row['table_name']].add(row['column_name'])
    edges = [dict(r) for r in await conn.fetch("""
        SELECT child.relname AS child, parent.relname AS parent, c.confdeltype::text AS action,
               ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n,i)
                     JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.i) AS child_keys,
               ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n,i)
                     JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY k.i) AS parent_keys
        FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
        JOIN pg_class parent ON parent.oid=c.confrelid
        JOIN pg_namespace ns ON ns.oid=child.relnamespace
        JOIN pg_namespace pn ON pn.oid=parent.relnamespace
        WHERE c.contype='f' AND ns.nspname='public' AND pn.nspname='public'
        ORDER BY parent.relname, child.relname, c.conname
    """)]
    return dict(columns), edges


def cascade_plan(kind: str, edges: list[dict], columns: dict):
    root = 'targets' if kind == 'target' else 'findings'
    deleted, detached, retained, restricted = (defaultdict(list) for _ in range(4))
    predicate = 'r.id = ANY($1::uuid[])'
    deleted[root].append(predicate)
    queue = [(root, predicate, (root,))]
    if kind == 'target' and 'credential_profiles' in columns:
        clause = "r.target_id = ANY($1::uuid[]) AND r.target_kind IN ('web','api','network')"
        deleted['credential_profiles'].append(clause)
        queue.append(('credential_profiles', clause, ('credential_profiles',)))
    serial = 0
    while queue:
        parent, predicate, path = queue.pop(0)
        for edge in edges:
            if edge['parent'] != parent:
                continue
            serial += 1
            if serial > 500:
                raise HTTPException(409, 'Deletion dependency graph is too complex; no records deleted')
            child = edge['child']
            alias = f'p{serial}'
            join = ' AND '.join(f'r.{ident(a)}={alias}.{ident(b)}'
                                for a, b in zip(edge['child_keys'], edge['parent_keys']))
            clause = (f'EXISTS (SELECT 1 FROM public.{ident(parent)} {alias} '
                      f'WHERE ({predicate.replace("r.", alias + ".")}) AND {join})')
            if child == 'evidence_objects' and edge['child_keys'] == ['finding_id']:
                detached[child].append(clause)
            elif edge['action'] == 'c':
                if child in path:
                    raise HTTPException(409, 'Cyclic ownership requires a separately reviewed deletion')
                deleted[child].append(clause)
                queue.append((child, clause, (*path, child)))
            elif edge['action'] == 'n':
                retained[child].append(clause)
            else:
                restricted[child].append(clause)
    return tuple({table: ' OR '.join(f'({p})' for p in clauses)
                  for table, clauses in group.items()} for group in (deleted, detached, retained, restricted))


def hold_predicate(alias='r', *, preserving=False) -> str:
    j = f'to_jsonb({alias})'
    # Sensitive is a content classification, not itself a legal hold. It still
    # blocks erasure, but not preservation with an exact ownership snapshot.
    # Audit/legal holds block both erasure and detachment of original links.
    classes = "'legal_hold','audit'" if preserving else "'legal_hold','audit','sensitive'"
    checks = [f"COALESCE({j}->>'{field}', '') IN ({classes})"
              for field in ('retention_class', 'retention_policy')]
    for key in ('legal_hold', 'operational_hold'):
        for obj in (j, f"{j}->'metadata_json'", f"{j}->'metadata'"):
            checks.append(f"lower(COALESCE(({obj})->>'{key}', 'false')) IN ('true','1','yes')")
    return '(' + ' OR '.join(checks) + ')'


async def summarize(conn, table, clause, roots, *, preserving=False):
    # UUID/reference columns only: no request/response content or credentials.
    # Preserve these exact original links in the preview hash and durable result
    # before ON DELETE SET NULL or an explicit evidence detachment changes them.
    fields = ('id', 'target_id', 'device_target_id', 'ai_target_id', 'scan_id',
              'finding_id', 'hunt_run_id', 'parent_target_id')
    links = 'jsonb_strip_nulls(jsonb_build_object(' + ','.join(
        f"'{field}',to_jsonb(r)->'{field}'" for field in fields) + '))'
    ownership = ", COALESCE(jsonb_agg(links ORDER BY links::text), '[]'::jsonb) AS ownership" if preserving else ''
    return dict(await conn.fetchrow(f"""
        SELECT COUNT(*)::int AS count,
               md5(COALESCE(string_agg(row_hash, '' ORDER BY row_hash), '')) AS state,
               COALESCE(bool_or(held), false) AS held {ownership}
        FROM (SELECT md5(to_jsonb(r)::text) AS row_hash,
                     {hold_predicate(preserving=preserving)} AS held, {links} AS links
              FROM public.{ident(table)} r WHERE {clause} LIMIT {MAX_RECORDS + 1}) bounded
    """, roots))


async def find_roots(conn, selection):
    if selection['kind'] == 'target':
        roots = [UUID(selection['target_id'])]
        rows = await conn.fetch('SELECT id, discovery_source FROM targets WHERE id=ANY($1::uuid[])', roots)
        if not rows:
            raise HTTPException(404, 'Target not found')
        if rows[0]['discovery_source'] == 'model-intake':
            raise HTTPException(409, 'Model Intake subjects require their product-specific lifecycle')
        return roots
    if selection.get('finding_ids'):
        ids = [UUID(v) for v in selection['finding_ids']]
        scan = UUID(selection['scan_id']) if selection.get('scan_id') else None
        found = await conn.fetch('SELECT id FROM findings WHERE id=ANY($1::uuid[]) AND ($2::uuid IS NULL OR scan_id=$2)', ids, scan)
        if len(found) != len(ids):
            raise HTTPException(404, 'One or more findings are missing or outside the selected scan')
        return sorted(ids, key=str)
    rows = await conn.fetch("""SELECT f.id FROM findings f LEFT JOIN targets t ON t.id=f.target_id
        WHERE f.last_seen_at < NOW() - INTERVAL '1 day' * $1
          AND ($2::text IS NULL OR f.status=$2) AND ($3::text IS NULL OR t.root_domain=$3)
        ORDER BY f.id LIMIT 501""", selection['older_than_days'], selection.get('status'), selection.get('root_domain'))
    if len(rows) > 500:
        raise HTTPException(413, 'More than 500 findings match; narrow the domain/status or select a smaller batch')
    return [r['id'] for r in rows]


async def owner_context(conn, kind, roots):
    column = 'target_id' if kind == 'target' else 'id'
    rows = await conn.fetch(f'SELECT id, target_id, device_target_id, ai_target_id, scan_id FROM findings WHERE {column}=ANY($1::uuid[])', roots)
    owners = {key: sorted({str(r[key]) for r in rows if r[key]}, key=str)
              for key in ('target_id', 'device_target_id', 'ai_target_id', 'scan_id')}
    if kind == 'target':
        owners['target_id'] = [str(r) for r in roots]
    owners['finding_id'] = sorted(str(r['id']) for r in rows)
    return owners


async def blockers(conn, columns, owners, kind, roots):
    issues = []
    for table in EXECUTION_TABLES:
        if table not in columns or 'status' not in columns[table]:
            continue
        clauses, params = [], []
        for column, values in owners.items():
            if values and column in columns[table]:
                params.append([UUID(v) for v in values])
                clauses.append(f'{ident(column)}=ANY(${len(params)}::uuid[])')
        if table == 'scans' and owners['scan_id']:
            params.append([UUID(v) for v in owners['scan_id']])
            clauses.append(f'id=ANY(${len(params)}::uuid[])')
        if clauses:
            params.append(sorted(TERMINAL_BY_TABLE.get(table, ())))
            active = await conn.fetchval(f'SELECT COUNT(*) FROM public.{ident(table)} WHERE '
                f'({" OR ".join(clauses)}) AND (status IS NULL OR NOT status=ANY(${len(params)}::text[]))', *params)
            if active:
                issues.append(f'{table}: {active} active or unfinished record(s); finish or cancel them first')
    for key, table in (('target_id', 'targets'), ('device_target_id', 'device_targets'), ('ai_target_id', 'ai_targets')):
        if owners[key] and table in columns:
            held = await conn.fetchval(f'SELECT COUNT(*) FROM public.{ident(table)} r WHERE id=ANY($1::uuid[]) AND {hold_predicate()}', [UUID(v) for v in owners[key]])
            if held:
                issues.append(f'{table}: an owner is on legal/operational hold')
    if kind == 'target' and (owners['device_target_id'] or owners['ai_target_id']):
        issues.append('Mixed product ownership: remove or resolve cross-product finding links first')
    if 'evidence_retention_previews' in columns and owners['target_id']:
        pending = await conn.fetchval("SELECT COUNT(*) FROM evidence_retention_previews WHERE target_id=ANY($1::uuid[]) AND status='executing'", [UUID(v) for v in owners['target_id']])
        if pending:
            issues.append('Evidence retention is executing; finish its retry/finalization first')
    return issues


async def inventory(conn, selection, roots, columns, edges):
    kind = selection['kind']
    plan = cascade_plan(kind, edges, columns)
    owners = await owner_context(conn, kind, roots)
    issues = await blockers(conn, columns, owners, kind, roots)
    groups = {}
    for name, predicates in zip(('delete', 'detach', 'retain', 'restrict'), plan):
        group = {}
        for table, clause in sorted(predicates.items()):
            summary = await summarize(conn, table, clause, roots, preserving=name in {'retain', 'detach'})
            if 'ownership' in summary:
                summary['ownership'] = decoded(summary['ownership'])
            if summary['count']:
                group[table] = summary
                if summary['count'] > MAX_RECORDS:
                    issues.append(f'{table}: deletion preview exceeds the {MAX_RECORDS}-record interactive limit')
                if summary['held']:
                    issues.append(f'{table}: legal hold or protected evidence blocks deletion; '
                                  'archive the target to keep its records and original ownership intact')
                # Do not delete a row belonging to a different owner through an indirect cascade.
                if name == 'delete' and 'target_id' in columns[table] and owners['target_id']:
                    foreign = await conn.fetchval(f'SELECT COUNT(*) FROM public.{ident(table)} r WHERE ({clause}) AND target_id IS NOT NULL AND NOT target_id=ANY($2::uuid[])', roots, [UUID(v) for v in owners['target_id']])
                    if foreign:
                        issues.append(f'{table}: cascade crosses target ownership')
        groups[name] = group
    for table, clause in plan[3].items():
        # A restrictive edge is harmless only when the referenced row itself is removed
        # by another declared cascade in this same operation.
        surviving = f'({clause}) AND NOT ({plan[0][table]})' if table in plan[0] else clause
        if await conn.fetchval(f'SELECT COUNT(*) FROM public.{ident(table)} r WHERE {surviving}', roots):
            issues.append(f'{table}: restrictive ownership reference blocks deletion')
    # Evidence with a plain scan_id has no target FK. Protect it even though scans survive.
    if owners['target_id'] and 'evidence_objects' in columns:
        held = await conn.fetchval(f"""SELECT COUNT(*) FROM evidence_objects r JOIN scans s ON s.id=r.scan_id
             WHERE s.target_id=ANY($1::uuid[]) AND ({hold_predicate(preserving=True)} OR r.retention_delete_pending_at IS NOT NULL)""", [UUID(v) for v in owners['target_id']])
        if held:
            issues.append('Scan evidence is protected or has pending retention deletion')
    if plan[1].get('evidence_objects'):
        pending = await conn.fetchval(f"SELECT COUNT(*) FROM evidence_objects r WHERE ({plan[1]['evidence_objects']}) AND retention_delete_pending_at IS NOT NULL", roots)
        if pending:
            issues.append('Finding evidence has pending retention deletion')
    return {'schema': 'shakerscan.record-deletion/v1', 'kind': kind,
            'root_ids': [str(v) for v in roots], 'owners': owners, 'records': groups,
            'blockers': sorted(set(issues)), 'retained': RETAINED, 'external_files_deleted': False}, plan


async def lock_inventory(conn, columns, plan):
    # No external I/O occurs while these short-lived locks are held. Table locks close
    # insert/hold/retest races without requiring every legacy writer to adopt a new lock.
    tables = set().union(*(set(p) for p in plan))
    tables.update(t for t in (*EXECUTION_TABLES, 'targets', 'findings', 'device_targets', 'ai_targets',
                             'evidence_objects', 'evidence_instances', 'evidence_retention_previews',
                             'approval_receipts', 'scope_receipts', 'command_results') if t in columns)
    await conn.execute("SET LOCAL lock_timeout='3s'")
    await conn.execute("SET LOCAL statement_timeout='20s'")
    await conn.execute('LOCK TABLE ' + ', '.join('public.' + ident(t) for t in sorted(tables)) + ' IN SHARE ROW EXCLUSIVE MODE')
