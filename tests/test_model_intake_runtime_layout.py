from pathlib import Path
import subprocess
import sys


def test_model_intake_imports_from_worker_runtime_layout():
    """The worker image exposes scanner/scanner_tools as top-level scanner_tools.

    Keep this separate-process check because the normal test layout imports the
    same modules through scanner.scanner_tools and would hide packaging drift.
    """
    scanner_root = Path(__file__).resolve().parents[1] / "scanner"
    script = (
        "import sys; "
        f"sys.path.insert(0, {str(scanner_root)!r}); "
        "import scanner_tools.model_intake; "
        "print('ok')"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd="/tmp",
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"
