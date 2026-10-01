"""Temporary anchored source changes; only the resulting source files are shipped."""
from pathlib import Path
import ast


def substitute(path, old, new, count=1):
    source = Path(path).read_text()
    if old not in source:
        if new in source:
            return
        raise RuntimeError(f'Patch context changed: {path}: {old[:100]}')
    if source.count(old) != count:
        raise RuntimeError(f'Ambiguous patch: {path}: {source.count(old)} != {count}')
    Path(path).write_text(source.replace(old, new, count))


def assignment(path, name, replacement):
    source = Path(path).read_text(); lines = source.splitlines(keepends=True)
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            lines[node.lineno-1:node.end_lineno] = [replacement + '\n']
            Path(path).write_text(''.join(lines))
            return
    raise RuntimeError(f'Missing assignment {path}:{name}')


store = 'api/runtime/credential_store.py'
assignment(store, '_KIND_COMPATIBLE_SQL', '''_KIND_COMPATIBLE_SQL = "(p.target_kind IN ('web','api','network','device') AND {kind} IN ('web','api','network','device'))"''')
substitute(store,
    "               LEFT JOIN credential_profile_bindings b\n                 ON b.profile_id=p.id AND b.binding_kind='target' AND b.binding_id=$2::text",
    "               LEFT JOIN LATERAL target_credential_grant(p.id,$3) b ON true")
substitute(store,
    "                 AND (p.target_id=$3 OR (b.id IS NOT NULL AND b.revoked_at IS NULL))",
    "                 AND b.id IS NOT NULL AND b.revoked_at IS NULL")
substitute(store,
    "               JOIN credential_profile_bindings b\n                 ON b.profile_id=p.id AND b.binding_kind='target'\n                AND b.binding_id=$3 AND b.is_active=true AND b.revoked_at IS NULL",
    "               JOIN LATERAL target_credential_grant(p.id,$3::uuid) b\n                 ON b.is_active=true AND b.revoked_at IS NULL", count=2)
substitute(store, "b.allowed_capabilities, b.binding_id AS granted_target_id",
           "b.allowed_capabilities, $3::text AS granted_target_id")
substitute(store, "    granted_target_id: str | None = None", "    granted_target_id: str | None = None\n    service_port: int | None = None")
substitute(store, "            granted_target_id=(", "            service_port=int(item['service_port']) if item.get('service_port') is not None else None,\n            granted_target_id=(")
substitute(store, '            "home_target_id": self.target_id,', '            "service_port": self.service_port,\n            "home_target_id": self.target_id,')
models = Path('api/runtime/models.py')
source = models.read_text()
for node in ast.parse(source).body:
    if isinstance(node, ast.FunctionDef) and node.name == 'target_kinds_share_asset':
        lines = source.splitlines(keepends=True)
        lines[node.lineno-1:node.end_lineno] = ['''def target_kinds_share_asset(left: str, right: str) -> bool:
    """Physical-target view kinds share a model; callers must still validate the target/grant."""
    physical = {"web", "api", "network", "device"}
    return left == right or (left in physical and right in physical)
''']
        models.write_text(''.join(lines)); break
else:
    raise RuntimeError('target_kinds_share_asset is missing')
substitute('tests/test_target_asset_migration_postgres.py',
    "INSERT INTO scans(target_url,device_target_id,run_kind) VALUES('device.example.test',$1,'device_posture') RETURNING id",
    "INSERT INTO scans(target_url,device_target_id,run_kind,status) VALUES('device.example.test',$1,'device_posture','completed') RETURNING id")
substitute('api/targets/asset_migration.py',
    '{"device_targets", "device_credential_profiles"}',
    '{"device_targets", "device_credential_profiles", "device_request_collections"}')
substitute('api/targets/asset_migration.py',
    '{"targets", "credential_profiles"}',
    '{"targets", "credential_profiles", "request_collections"}')
