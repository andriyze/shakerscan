"""Update legacy fixtures to exercise canonical ownership without dropping guarantees."""
from pathlib import Path
import ast


def sub(path,old,new,count=1):
    p=Path(path);s=p.read_text()
    if new in s:return
    if s.count(old)!=count:raise RuntimeError((path,old[:100],s.count(old)))
    p.write_text(s.replace(old,new,count))

sub('tests/test_credential_api.py','    def transaction(self):', '''    async def fetchval(self, query, *args):
        if "app_schema_migrations" in query:
            return None  # This fixture exercises the pre-conversion compatibility writer.
        raise AssertionError(query)

    def transaction(self):''')
sub('tests/test_credential_refs.py','_profile("p", kind="ssh_password", slot="ssh", target_kind="device"),','_profile("p", kind="ssh_password", slot="ssh", target_kind="model"),')
p=Path('tests/test_credential_refs.py');s=p.read_text()
if 'test_device_profile_reference_is_available_through_the_same_asset_view' not in s:
    s+='''\n\n@pytest.mark.parametrize('view_kind',['web','api','network','device'])
def test_device_profile_reference_is_available_through_the_same_asset_view(view_kind):
    profile=_profile('device-profile',kind='ssh_password',slot='ssh',target_kind='device')
    refs,missing=validate_generic_credential_references(
        {'ssh_credential_profile_id':profile.profile_id},[profile],target_kind=view_kind,now=NOW)
    assert not missing and refs[0]['profile_id']==profile.profile_id
    assert refs[0]['secret_values_visible'] is False
'''
    p.write_text(s)
for path in ['tests/test_device_locator.py','tests/test_device_product_isolation.py']:
    sub(path,'import api as api_module  # noqa: E402', '''import importlib  # noqa: E402
import api as api_module  # noqa: E402
if hasattr(api_module, '__path__'):
    api_module = importlib.import_module('api.api')''')
p=Path('tests/test_device_review_regressions.py');s=p.read_text();lines=s.splitlines(keepends=True)
for n in reversed(ast.parse(s).body):
    if isinstance(n,ast.FunctionDef) and n.name in {'test_device_credentials_are_bound_encrypted_and_resolved_only_in_worker_memory','test_device_auth_requires_authenticated_safety_and_never_enters_agent_transcript','test_device_request_collections_are_encrypted_pinned_and_agent_bounded'}:
        body=''.join(lines[n.lineno-1:n.end_lineno])
        if '"worker_inputs.py"' not in body:
            body=body.replace('worker = (ROOT / "api" / "worker.py").read_text()', 'worker = (ROOT / "api" / "worker.py").read_text() + (ROOT / "api" / "devices" / "worker_inputs.py").read_text()')
        body=body.replace('    assert "WHERE device_request_collections.is_active=false" in api','''    shared = (ROOT / "api" / "devices" / "shared_collections.py").read_text()
    assert "INSERT INTO request_collections" in shared
    assert "This target already has an active request collection with that name" in shared
    assert "expected_digest" in shared
    assert "save_device_collection" in api''')
        lines[n.lineno-1:n.end_lineno]=[body]
p.write_text(''.join(lines))
sub('tests/test_target_authorization.py','    async def fetchval(self, query, *args):\n        raise AssertionError(query)', '''    async def fetchval(self, query, *args):
        if 'target_effective_authorization_target' in query:
            return TARGET_ID if str(args[0]) == str(TARGET_ID) else None
        raise AssertionError(query)''')
sub('tests/test_target_authorization.py','        self.executed.append((query, args))','''        self.executed.append((query, args))
        if 'UPDATE targets SET authorization_inheritance=false' in query:
            return 'UPDATE 1' ''')
sub('tests/test_hunt_knowledge_pages.py','        self.calls = []','''        self.calls = []
        self.db.execute('CREATE TABLE targets (id TEXT PRIMARY KEY, asset_owner_id TEXT)')
        self.db.executemany('INSERT INTO targets VALUES (?,NULL)',[(str(TARGET),),(str(OTHER),)])''')
sub('tests/test_hunt_knowledge_pages.py','    def insert(self, kind, **values):','''    def insert(self, kind, **values):
        if values.get('device_target_id') and not values.get('target_id'):
            values['target_id']=values['device_target_id']  # canonical alias populated by migration''')
p=Path('tests/test_hunt_knowledge_pages.py');s=p.read_text()
if 'test_device_history_includes_child_services_but_not_a_different_asset' not in s:
    s+='''\n\ndef test_device_history_includes_child_services_but_not_a_different_asset():
    db=KnowledgeDB()
    child=str(uuid.UUID(int=999001))
    db.db.execute('INSERT INTO targets VALUES (?,?)',(child,str(TARGET)))
    db.insert('scans',id='root-scan',target_id=str(TARGET),status='completed',created_at=STAMP)
    db.insert('scans',id='child-scan',target_id=child,status='completed',created_at=STAMP)
    db.insert('scans',id='foreign-scan',target_id=str(OTHER),status='completed',created_at=STAMP)
    assert {row['id'] for row in page(db,'scans',device=True)['rows']}=={'root-scan','child-scan'}
'''
    p.write_text(s)
p=Path('.implementation/check.sh');s=p.read_text()
if 'python -m playwright install --with-deps chromium' not in s:
    s=s.replace('npm --prefix ui ci --silent','python -m playwright install --with-deps chromium\nnpm --prefix ui ci --silent',1)
p.write_text(s)
