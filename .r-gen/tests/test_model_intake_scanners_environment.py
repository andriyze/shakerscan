"""The sanitized scanner environment must keep BLAS single-threaded on many-core hosts."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from scanner_tools.model_intake_scanners import _safe_environment  # noqa: E402


def test_scanner_environment_pins_blas_threads(tmp_path):
    env = _safe_environment(tmp_path)
    assert env["OPENBLAS_NUM_THREADS"] == "1"
    assert env["OMP_NUM_THREADS"] == "1"
    assert env["MKL_NUM_THREADS"] == "1"
    # Still a closed environment: nothing from the caller's shell leaks through.
    assert set(env) <= {
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "NO_PROXY", "no_proxy",
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
        "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
    }
