import json
from pathlib import Path
import subprocess
import sys

import pytest

# bounded_exec enforces the sandbox with RLIMIT_AS and a seccomp filter. macOS
# has neither -- setrlimit raises "current limit exceeds maximum limit" before
# the launcher runs -- so these assert nothing there. They are NOT optional:
# Linux CI must run them, which is why this skips on platform rather than on a
# missing import.
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="bounded_exec sandbox requires Linux RLIMIT_AS and seccomp",
)


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scanner/scanner_tools/bounded_exec.py"


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LAUNCHER), "--", sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_bounded_exec_preserves_read_only_computation_and_loads_seccomp():
    completed = _run(
        'import json; from pathlib import Path; '
        'mode=next(line.split(":",1)[1].strip() for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("Seccomp:")); '
        'print(json.dumps({"mode":mode,"digest":__import__("hashlib").sha256(b"fixture").hexdigest()}))'
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["mode"] == "2"
    assert len(result["digest"]) == 64


def test_bounded_exec_denies_external_socket_creation_before_scanner_code_runs():
    completed = _run(
        'import json,socket; '
        'result={}; '
        '\ntry: socket.socket()'
        '\nexcept OSError as exc: result={"blocked":True,"errno":exc.errno}'
        '\nelse: result={"blocked":False}'
        '\nprint(json.dumps(result))'
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"blocked": True, "errno": 1}


def test_bounded_exec_preserves_local_unix_socketpair_for_scanner_ipc():
    completed = _run(
        'import json,socket; left,right=socket.socketpair(); '
        'left.sendall(b"ok"); received=right.recv(2); left.close(); right.close(); '
        'print(json.dumps({"received":received.decode()}))'
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"received": "ok"}


def test_bounded_exec_denies_ipv6_socket_creation():
    completed = _run(
        'import json,socket; result={}; '
        '\ntry: socket.socket(socket.AF_INET6, socket.SOCK_STREAM)'
        '\nexcept OSError as exc: result={"blocked":True,"errno":exc.errno}'
        '\nelse: result={"blocked":False}'
        '\nprint(json.dumps(result))'
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"blocked": True, "errno": 1}
