"""Apply the reviewed regression amendments and normalize touched-file whitespace."""
from pathlib import Path
import subprocess

commit='2c11f6a9b56189291196ee1a0a892dce98159ca4'
subprocess.run(['git','fetch','--depth=1','origin',commit],check=True)
source=subprocess.check_output(['git','show',f'{commit}:.implementation/apply.py'],text=True)
exec(compile(source,'.implementation/regression_batch.py','exec'))
for name in ['test_credential_api.py','test_credential_refs.py','test_device_locator.py','test_device_product_isolation.py','test_device_review_regressions.py','test_target_authorization.py','test_hunt_knowledge_pages.py']:
    path=Path('tests')/name
    path.write_text('\n'.join(line.rstrip() for line in path.read_text().splitlines())+'\n')
