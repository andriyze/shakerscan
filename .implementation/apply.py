"""Resume the reviewed integration batch with the exact current UI anchor."""
from pathlib import Path
import subprocess

# Do not let a diagnostic file shadow Python's standard-library inspect module.
Path('.implementation/inspect.py').unlink(missing_ok=True)
commit='a09a1f7da26e6acb5451fb71049db0845e3bd3b7'
subprocess.run(['git','fetch','--depth=1','origin',commit],check=True)
source=subprocess.check_output(['git','show',f'{commit}:.implementation/apply.py'],text=True)
source=source.replace('        <RetireDeviceButton deviceId={deviceId}', '<RetireDeviceButton deviceId={device.id}')
exec(compile(source, '.implementation/integration_batch.py', 'exec'))
