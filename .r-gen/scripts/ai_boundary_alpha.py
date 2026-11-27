#!/usr/bin/env python3
"""Local synthetic demo and secret-free contract validation (source checkout)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "api"), str(ROOT / "scanner"), str(ROOT / "tests"), str(ROOT)]

from ai_gate.boundary.contract import BoundaryContract, ContractError


def emit(value: dict[str, Any], output: str | None) -> None:
    if output is None:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    # Never silently replace a previous run or follow a report-path symlink.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


async def demo(mode: str, nested: bool) -> dict[str, Any]:
    from ai_gate.boundary.runner import run_boundary_scan
    from tests.ai_boundary_fixtures import boundary_fixture

    async with boundary_fixture(mode, nested=nested) as fixture:
        options = fixture.options()
        result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
    if not fixture.cleaned:
        raise RuntimeError("synthetic_fixture_cleanup_failed")
    result["demo"] = {"synthetic": True, "real_llm_tested": False, "fixture_cleanup_complete": True,
                      "mode": mode, "wire_format": "nested" if nested else "flat"}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate a secret-free contract without network calls")
    validate.add_argument("contract")
    demonstrate = commands.add_parser("demo", help="Run the real verifier against a loopback synthetic app")
    demonstrate.add_argument("--mode", choices=["secure", "vulnerable", "backend_leak", "trace_only", "echo"], default="secure")
    demonstrate.add_argument("--nested", action="store_true", help="Use a different JSON request/response layout")
    demonstrate.add_argument("--output", help="New JSON evidence file; existing files are never overwritten")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            path = Path(args.contract)
            if path.stat().st_size > 65536:
                raise ContractError("contract_file_too_large")
            contract = BoundaryContract.parse(json.loads(path.read_text(encoding="utf-8")))
            emit({"valid": True, "name": contract.name, "contract_sha256": contract.digest,
                  "planned_attempts": len(contract.attacks) * contract.repetitions}, None)
            return 0
        result = asyncio.run(demo(args.mode, args.nested))
        emit(result, args.output)
        decision = result["ai_gate"]["decision"]["decision"]
        if args.output:
            print(json.dumps({"decision": decision, "state": result["ai_gate"]["boundary"]["state"]}))
        return {"allow": 0, "block": 1, "needs_approval": 2}[decision]
    except ContractError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError) as exc:
        # Do not print arbitrary input data, credentials, URLs, or response bodies.
        print(json.dumps({"error": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
