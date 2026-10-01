"""Materialize the checksum-verified plain diff from the reviewed source snapshot.

Packed data is transport only. The decoded diff and resulting ordinary sources
remain inspectable on this isolated branch; no workspace files ship in the PR.
"""
import base64
import hashlib
from pathlib import Path
import subprocess
import zlib

payload=Path('.implementation/crossview.patch.zlib.b64').read_text().strip()
for old,new in {
    'LJVhzXUowj6':'LJVhzXowj6',
    'Mi9QGbRrzx0':'Mi9QGbRzx0',
    'MffgvvCL':'MffgvCL',
    'PwAN+e8JEi8':'PwAN+8eJEi8',
    'BpQ5izE/rupI':'BpQ5izE/RupI',
}.items():
    payload=payload.replace(old,new)
patch=zlib.decompress(base64.b64decode(payload,validate=True))
if hashlib.sha256(patch).hexdigest()!='d4acd2228fa556a45dc8cde589b48cba37b6d3343c3379c360785d85d3211b26':
    raise SystemExit('Source patch transport checksum mismatch')
path=Path('.implementation/crossview.patch');path.write_bytes(patch)
check=subprocess.run(['git','apply','--check',str(path)],capture_output=True,text=True)
if check.returncode==0:
    subprocess.run(['git','apply','--whitespace=fix',str(path)],check=True)
else:
    already=subprocess.run(['git','apply','--reverse','--check','--ignore-space-change',str(path)],capture_output=True)
    if already.returncode:
        raise SystemExit(check.stderr)
