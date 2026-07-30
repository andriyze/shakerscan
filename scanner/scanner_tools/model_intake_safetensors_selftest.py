"""Build-time, non-skippable smoke tests for the official parser boundary."""

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
from safetensors.numpy import save_file

from model_intake_safetensors_runtime import inspect_with_official_parser


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        safe = root / "safe.safetensors"
        save_file(
            {"embedding.weight": np.asarray([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)},
            str(safe),
            metadata={"description": "hostile-looking </script> ${TOKEN} is inert metadata"},
        )
        accepted = inspect_with_official_parser(safe, _digest(safe), numeric_mode="full")
        assert accepted["status"] == "PASS", accepted
        assert accepted["official_parser"]["status"] == "PASS", accepted
        assert accepted["numeric_values_checked"] == 4, accepted

        non_finite = root / "non-finite.safetensors"
        save_file({"weight": np.asarray([1.0, np.nan], dtype=np.float32)}, str(non_finite))
        rejected_numeric = inspect_with_official_parser(non_finite, _digest(non_finite), numeric_mode="full")
        assert rejected_numeric["status"] == "FAIL", rejected_numeric
        assert "full_scan_non_finite_weights" in rejected_numeric["blockers"], rejected_numeric

        truncated = root / "truncated.safetensors"
        truncated.write_bytes(safe.read_bytes()[:-1])
        rejected_format = inspect_with_official_parser(truncated, _digest(truncated), numeric_mode="full")
        assert rejected_format["status"] == "FAIL", rejected_format
        assert "official_safetensors_parser_rejected_artifact" in rejected_format["blockers"], rejected_format
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
