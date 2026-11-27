"""Permanent deletion of a credential profile or a request collection.

Deactivating keeps every encrypted version, grant and copy so the input can be restored. This
path removes the input completely: its versions, grants, sessions and environments by FK cascade,
the assurance history whose FKs would otherwise block, the legacy copies a later sync would use
to re-create it, and the references other targets and schedules hold to it.
"""
from __future__ import annotations

from .statuses import TERMINAL_BY_TABLE

INPUT_KINDS = {'credential_profile': 'credential_profiles', 'request_collection': 'request_collections'}
LABELS = {'credential_profile': 'credential', 'request_collection': 'request collection'}

# Rows owned by a credential with no cascading FK to it, in the order they must be deleted.
CREDENTIAL_OWNED = (
    ('authentication_validation_requests', 'r.profile_id = ANY($1::uuid[])'),
    ('authentication_validations', 'r.profile_id = ANY($1::uuid[])'),
    ('authenticated_profile_revisions', 'r.profile_id = ANY($1::uuid[])'),
    # Legacy mirrors share the profile id; left behind, a later sync re-creates the profile.
    ('target_credential_profiles', 'r.id = ANY($1::uuid[])'),
    ('ai_target_credentials', 'r.id = ANY($1::uuid[])'),
    ('ai_target_principals', 'r.id = ANY($1::uuid[])'),
)
# JSON arrays elsewhere that name the input: (table, column, path).
REFERENCES = {
    'credential_profile': (('targets', 'metadata_json', ('hunt_authority', 'credential_profile_ids')),
                           ('schedules', 'scan_options', ('credential_profile_ids',))),
    'request_collection': (('targets', 'metadata_json', ('hunt_authority', 'collection_ids')),
                           ('schedules', 'scan_options', ('request_collections',))),
}
# Where a running scan or Hunt records the inputs it uses.
USERS = (('scans', ('options', 'scan_job_payload')), ('hunt_runs', ('context_pack', 'policy')))


def owned(kind: str, columns: dict) -> dict[str, str]:
    if kind != 'credential_profile':
        return {}
    result = {}
    for table, clause in CREDENTIAL_OWNED:
        column = 'profile_id' if 'profile_id' in clause else 'id'
        if column in columns.get(table, set()):
            result[table] = clause
    return result


async def home_targets(conn, kind: str, roots: list) -> list[str]:
    table = INPUT_KINDS[kind]
    rows = await conn.fetch(f'SELECT DISTINCT target_id FROM {table} WHERE id = ANY($1::uuid[]) AND target_id IS NOT NULL', roots)
    return sorted(str(row['target_id']) for row in rows)


async def find(conn, kind: str, root):
    table = INPUT_KINDS[kind]
    if not await conn.fetchval(f'SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1)', root):
        raise LookupError(f'{LABELS[kind].capitalize()} not found')
    return [root]


async def running_users(conn, kind: str, roots: list, columns: dict) -> list[str]:
    """Non-terminal scans or Hunts that still use the input block its deletion."""
    ids = [str(root) for root in roots]
    issues = []
    for table, fields in USERS:
        present = [field for field in fields if field in columns.get(table, set())]
        if not present or 'status' not in columns.get(table, set()):
            continue
        uses = ' OR '.join(f"strpos(COALESCE(r.{field}::text, ''), ref.value) > 0" for field in present)
        count = await conn.fetchval(
            f'SELECT COUNT(DISTINCT r.id) FROM {table} r, unnest($1::text[]) AS ref(value) '
            f'WHERE ({uses}) AND (r.status IS NULL OR NOT r.status = ANY($2::text[]))',
            ids, sorted(TERMINAL_BY_TABLE.get(table, ())))
        if count:
            issues.append(f'{table}: {count} unfinished record(s) use this {LABELS[kind]}; '
                          'cancel them or wait for them to finish')
    return issues


async def detach_references(conn, kind: str, roots: list, columns: dict) -> dict[str, int]:
    """Remove the input from other targets' delegated authority and from schedules."""
    ids = [str(root) for root in roots]
    detached = {}
    for table, column, path in REFERENCES.get(kind, ()):
        if column not in columns.get(table, set()):
            continue
        pointer = '{' + ','.join(path) + '}'
        names = 'EXISTS (SELECT 1 FROM unnest($1::text[]) AS ref(value) WHERE strpos(x::text, ref.value) > 0)'
        rows = await conn.fetch(f"""UPDATE {table} t SET {column} = jsonb_set(t.{column}, '{pointer}', COALESCE(
                (SELECT jsonb_agg(x) FROM jsonb_array_elements(t.{column} #> '{pointer}') x WHERE NOT {names}),
                '[]'::jsonb))
            WHERE jsonb_typeof(t.{column} #> '{pointer}') = 'array'
              AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.{column} #> '{pointer}') x WHERE {names})
            RETURNING t.id""", ids)
        if rows:
            detached[f'{table}.{column}'] = len(rows)
    return detached
