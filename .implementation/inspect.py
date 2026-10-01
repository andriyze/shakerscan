"""Read-only inspection of public repository contracts for the requested migration."""
from pathlib import Path
import ast
import re

print('=== MODEL AND ROUTING FILES ===')
for path in sorted(Path('api').rglob('*.py')):
    if any(word in str(path) for word in ('credential', 'request_collection', 'target_identity', 'authorization', 'bootstrap', 'startup', 'schema', 'routes/target', 'targets/')):
        source = path.read_text()
        print(path, len(source.splitlines()))
        for match in re.finditer(r'^(?:async )?def (\w+)\(', source, re.M): print('  ', match.group(1))
print('=== OWNERSHIP SCHEMA ===')
source = Path('db/init.sql').read_text()
for name in ['device_targets', 'device_interfaces', 'device_locator_history', 'device_services', 'device_credential_profiles', 'device_credential_attempts', 'device_request_collections', 'credential_profiles', 'credential_profile_grants', 'request_collections', 'request_collection_grants', 'target_authorizations']:
    match = re.search(r'CREATE TABLE (?:IF NOT EXISTS )?' + name + r'\s*\(', source)
    if match:
        end = source.index('\n);', match.start()) + 3
        print(source[match.start():end])
print('=== MIGRATION ENTRY POINTS ===')
path = Path('api/retest_contract.py'); source = path.read_text(); lines = source.splitlines()
for node in ast.parse(source).body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and ('schema_migration' in node.name or 'migration' in node.name):
        print(node.name, node.lineno, node.end_lineno)
        if node.end_lineno - node.lineno < 100: print('\n'.join(lines[node.lineno-1:node.end_lineno]))
print('=== PUBLIC TARGET API IMPLEMENTATION LOCATIONS ===')
for path in Path('api').rglob('*.py'):
    source = path.read_text()
    if 'include_router(' in source or '@app.get("/targets' in source or '@router.get("/targets' in source:
        print(path)
        for i,line in enumerate(source.splitlines(),1):
            if 'include_router(' in line or '"/targets' in line: print(i, line)
