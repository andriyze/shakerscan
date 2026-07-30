"""Official safetensors-parser gate plus content-free bounded evidence.

This entry point runs in its own hash-locked virtual environment. The Rust
parser is authoritative for format acceptance; ShakerScan's independent
layout/numeric pass adds defense-in-depth evidence and a full-value option.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
from typing import Any

import numpy as np
from safetensors import safe_open

from model_intake_runtime import _load_layout, inspect_safetensors


NUMPY_DTYPES = {
    "F64": "<f8",
    "F32": "<f4",
    "F16": "<f2",
}


def _full_numeric_scan(path: Path) -> dict[str, int]:
    """Vectorized, chunked scan of every supported floating-point value."""
    layout = _load_layout(path)
    checked = 0
    non_finite = 0
    chunk_elements = 4 * 1024 * 1024
    for tensor in layout["tensor_specs"]:
        dtype = tensor["dtype"]
        if dtype not in {*NUMPY_DTYPES, "BF16"} or not tensor["elements"]:
            continue
        count = int(tensor["elements"])
        offset = int(layout["payload_offset"] + tensor["start"])
        mapped = np.memmap(
            path,
            mode="r",
            dtype=("<u2" if dtype == "BF16" else NUMPY_DTYPES[dtype]),
            offset=offset,
            shape=(count,),
        )
        for start in range(0, count, chunk_elements):
            values = mapped[start : min(count, start + chunk_elements)]
            if dtype == "BF16":
                non_finite += int(np.count_nonzero((values & 0x7F80) == 0x7F80))
            else:
                non_finite += int(np.count_nonzero(~np.isfinite(values)))
            checked += int(values.size)
        del mapped
    return {"values_checked": checked, "non_finite_values": non_finite}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_with_official_parser(
    path: Path,
    expected_digest: str,
    *,
    numeric_mode: str = "full",
) -> dict[str, Any]:
    actual_digest = _sha256(path)
    parser_evidence: dict[str, Any] = {
        "name": "huggingface-safetensors-rust",
        "version": version("safetensors"),
        "authoritative": True,
        "status": "FAIL",
        "tensor_count": 0,
    }
    try:
        with safe_open(str(path), framework="np", device="cpu") as handle:
            keys = list(handle.keys())
            # get_slice asks the official binding to validate every tensor's
            # dtype/shape/offset metadata without materializing its payload.
            shapes = [list(handle.get_slice(key).get_shape()) for key in keys]
            parser_evidence.update({
                "status": "PASS",
                "tensor_count": len(keys),
                "rank_counts": {
                    str(rank): sum(1 for shape in shapes if len(shape) == rank)
                    for rank in sorted({len(shape) for shape in shapes})
                },
                "metadata_present": bool(handle.metadata()),
            })
    except Exception as exc:  # Rust binding exposes typed exceptions by version.
        parser_evidence["error"] = f"{type(exc).__name__}:{exc}"

    # The independent structural pass remains sampled and bounded. Production
    # full mode then checks every supported floating value via chunked memmap.
    manual = inspect_safetensors(path, expected_digest, numeric_mode="sampled")
    blockers = list(manual.get("blockers") or [])
    if numeric_mode == "full" and parser_evidence["status"] == "PASS":
        try:
            numeric = _full_numeric_scan(path)
            manual["numeric_values_checked"] = numeric["values_checked"]
            manual["non_finite_values"] = numeric["non_finite_values"]
            manual["numeric_scan_mode"] = "full"
            if numeric["non_finite_values"]:
                blockers.append("full_scan_non_finite_weights")
        except Exception as exc:
            manual["full_numeric_scan_error"] = f"{type(exc).__name__}:{exc}"
            blockers.append("full_numeric_scan_failed")
    if parser_evidence["status"] != "PASS":
        blockers.append("official_safetensors_parser_rejected_artifact")
    if actual_digest != expected_digest:
        blockers.append("artifact_digest_mismatch")
    blockers = sorted(set(blockers))
    manual.update({
        "status": "FAIL" if blockers else "PASS",
        "artifact_loaded": not blockers,
        "artifact_sha256": actual_digest,
        "official_parser": parser_evidence,
        "parser_authority": "official_safetensors_rust",
        "blockers": blockers,
    })
    manual.setdefault("known_answer_tests", []).append({
        "id": "official-parser-accepted-exact-artifact",
        "status": "PASS" if parser_evidence["status"] == "PASS" and actual_digest == expected_digest else "FAIL",
    })
    return manual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact")
    parser.add_argument("expected_digest")
    parser.add_argument("--numeric-mode", choices=("sampled", "full"), default="full")
    args = parser.parse_args()
    result = inspect_with_official_parser(
        Path(args.artifact),
        args.expected_digest,
        numeric_mode=args.numeric_mode,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
