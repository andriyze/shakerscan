#!/usr/bin/env python3
"""Apply the explicit Hunt HTTP-write patch to one audited detached checkout.

Temporary authoring helper; not included in the implementation branch or PR.
Every original blob and replacement anchor is checked before any source is written.
"""
from __future__ import annotations
import argparse
import ast
import difflib
import hashlib
from pathlib import Path
import subprocess
import sys

BASE = "7f5920bd5f4b08fbda11222871b0e2d68e0cd755"
HERE = Path(__file__).resolve().parent
HASHES = {
    "api/runtime/capability_registry.py": "0be83f71b57dbfcf008c4ba7fa33ad075f51a167",
    "api/hunt/interaction_router.py": "a43395d2655c10a6780a4abc4e25abb48c407bc8",
    "api/worker.py": "469c3798afbf41a71b51d470935bd68adf5d902e",
    "api/capabilities/inline.py": "16fe4b83da9ce7958b87903ef37650d0efd13011",
    "api/scan/authorization.py": "4e2719e4f3619c8c1b588478b826979a78f10196",
    "tests/test_hunt_http_capability.py": "3df96283a4000e53086088067ccc26b8d90ee595",
    "skills/hunt/SKILL.md": "da06699cfe3e6b798dab13296f50514646b36692",
    "skills/web/core/02-tool-execution-safety.md": "d020765bfaf127fd4578a8627a03058fc48fc79e",
}
NEW_FILES = (
    "api/runtime/hunt_http_contract.py",
    "tests/test_hunt_http_write_contract.py",
    "tests/test_hunt_http_write_integration.py",
    "docs/hunt-http-writes.md",
)

def once(source: str, before: str, after: str, label: str) -> str:
    count = source.count(before)
    if count != 1:
        raise ValueError(f"{label}: expected one exact anchor; found {count}; no files written")
    return source.replace(before, after, 1)

def section(source: str, start: str, end: str, edits, label: str) -> str:
    if source.count(start) != 1:
        raise ValueError(f"{label}: function boundary missing or ambiguous")
    first = source.index(start)
    last = source.index(end, first)
    body = source[first:last]
    for index, (before, after) in enumerate(edits):
        body = once(body, before, after, f"{label}/{index}")
    return source[:first] + body + source[last:]

def transformations(original: dict[str, str]) -> dict[str, str]:
    result = dict(original)
    path = "api/runtime/capability_registry.py"
    source = once(result[path], "from types import MappingProxyType\n",
        "from types import MappingProxyType\nfrom .hunt_http_contract import validate_http_request_input\n", path)
    source = once(source,
        '        _validate_schema_value(spec.input_schema, value, path="input", depth=0)\n        return dict(value)',
        '        _validate_schema_value(spec.input_schema, value, path="input", depth=0)\n'
        '        if spec.name == "http.request":\n'
        '            try:\n'
        '                validate_http_request_input(value)\n'
        '            except ValueError as exc:\n'
        '                raise CapabilityInputContractError(str(exc)) from exc\n'
        '        return dict(value)', path)
    source = once(source,
        '"http.request", "Send one target-pinned read-only request, optionally as a managed principal.",',
        '"http.request", "Send one target-pinned request, optionally as a managed principal. "\n'
        '            "POST/PUT/PATCH/DELETE require the Hunt\'s existing state-changing authority; "\n'
        '            "GET/HEAD/OPTIONS remain available without it.",', path)
    source = section(source,
        '        CapabilitySpec(\n            "http.request",',
        '        CapabilitySpec(\n            "artifact.inspect",', ((
            '"method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},',
            '"method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]},\n'
            '                "json_body": {"type": "object", "description": "Non-secret JSON body for an authorized write. Mutually exclusive with form_body."},\n'
            '                "form_body": {"type": "object", "description": "Non-secret form fields for an authorized write. Mutually exclusive with json_body."},'
        ),), path)
    result[path] = source

    path = "api/hunt/interaction_router.py"
    source = once(result[path], "from .run_service import agent_tools\n",
        "from .run_service import agent_tools\n"
        "try:\n"
        "    from runtime.hunt_http_contract import require_http_request_authority, redact_http_request_body\n"
        "except ModuleNotFoundError:\n"
        "    from ..runtime.hunt_http_contract import require_http_request_authority, redact_http_request_body\n", path)
    source = section(source,
        "async def _execute_hunt_capability_lifecycle(\n",
        "\n\nasync def _enqueue_canonical_network_capability(\n", ((
            '            principal_slot = (\n',
            '            writes_http = False\n'
            '            if name == "http.request":\n'
            '                try:\n'
            '                    writes_http = require_http_request_authority(request.input, policy)\n'
            '                except ValueError as exc:\n'
            '                    raise HTTPException(status_code=403, detail=str(exc)) from exc\n'
            '            principal_slot = (\n'
        ), (
            '                spec.requires_active_approval\n                or principal_slot != "anonymous"',
            '                spec.requires_active_approval\n                or writes_http\n                or principal_slot != "anonymous"'
        ), (
            'else "active" if forges_identity or uses_direct_origin or uses_service_origin',
            'else "active" if forges_identity or uses_direct_origin or uses_service_origin or writes_http'
        ), (
            '            charges["agent_actions"] = 1\n',
            '            if writes_http:\n'
            '                charges["state_changing_requests"] = 1\n'
            '            charges["agent_actions"] = 1\n'
        )), path)
    source = once(source,
        '    redacted = _arsenal_routes._redact_agent_payload(dict(capability_input or {}))\n',
        '    values = dict(capability_input or {})\n'
        '    if capability_name == "http.request":\n'
        '        values = redact_http_request_body(values)\n'
        '    redacted = _arsenal_routes._redact_agent_payload(values)\n', path)
    result[path] = source

    path = "api/scan/authorization.py"
    result[path] = once(result[path],
        '        return CAPABILITY_REGISTRY.require(capability_name).requires_active_approval\n',
        '        specification = CAPABILITY_REGISTRY.require(capability_name)\n'
        '        values = _value(action, "capability_input", {})\n'
        '        method = str(_value(values, "method", "") or "").upper()\n'
        '        # Writes must not inherit http.request\'s passive baseline shortcut.\n'
        '        return specification.requires_active_approval or (\n'
        '            capability_name == "http.request"\n'
        '            and method in {"POST", "PUT", "PATCH", "DELETE"}\n'
        '        )\n', path)

    path = "api/worker.py"
    source = section(result[path],
        "async def _revalidate_hunt_action_authority(\n",
        "\n\ndef _worker_hunt_profile_context(\n", ((
            '    capability_name: str,\n) -> None:',
            '    capability_name: str,\n    capability_input: Mapping[str, Any] | None = None,\n) -> None:'
        ), (
            '        action=SimpleNamespace(capability_name=capability_name),',
            '        action=SimpleNamespace(\n'
            '            capability_name=capability_name, capability_input=dict(capability_input or {}),\n'
            '        ),'
        )), path)
    source = section(source,
        "async def process_canonical_http_capability_job(",
        "\n\nasync def process_job(", ((
            '        spec = agent_tools.CAPABILITY_REGISTRY.require(capability_name)\n',
            '        spec = agent_tools.CAPABILITY_REGISTRY.require(capability_name)\n'
            '        from runtime.hunt_http_contract import require_http_request_authority, redact_http_request_body\n'
        ), (
            '                    active_testing=bool(hunt_policy.get("active_testing")),\n',
            '                    active_testing=bool(hunt_policy.get("active_testing")),\n'
            '                    allow_state_changing_http=bool(hunt_policy.get("allow_state_changing_http")),\n'
        ), (
            '                requested_budget = dict(stored.record.requested)\n',
            '                requested_budget = dict(stored.record.requested)\n'
            '                writes_http = False\n'
            '                if capability_name == "http.request":\n'
            '                    writes_http = require_http_request_authority(\n'
            '                        capability_input, hunt_policy, requested_budget=requested_budget,\n'
            '                    )\n'
        ), (
            '                    policy=policy,\n                    capability_name=capability_name,\n                )\n',
            '                    policy=policy,\n                    capability_name=capability_name,\n'
            '                    capability_input=capability_input,\n                )\n'
        ), (
            '                    allow_write=False,\n',
            '                    allow_write=writes_http,\n'
        ), (
            '                **public_input,\n                "as_principal": principal_slot,',
            '                **redact_http_request_body(public_input),\n                "as_principal": principal_slot,'
        )), path)
    result[path] = source

    path = "api/capabilities/inline.py"
    result[path] = section(result[path],
        "class HttpRequestExecutionAdapter(_InlineAdapter):\n",
        "\n\nclass _MeasuredObservationExecutionAdapter(", ((
            '        error = str(result.get("error") or "").strip()\n',
            '        if "state_changing_requests" in self._requested_budget:\n'
            '            # Charge an attempted write even if its response was lost.\n'
            '            request_view = result.get("request") if execution_started else {}\n'
            '            request_method = str(request_view.get("method") or "").upper()\n'
            '            actual["state_changing_requests"] = (\n'
            '                1 if execution_started and request_method in {"POST", "PUT", "PATCH", "DELETE"} else 0\n'
            '            )\n'
            '        error = str(result.get("error") or "").strip()\n'
        ),), path)

    path = "tests/test_hunt_http_capability.py"
    result[path] = once(result[path], '    assert "allow_write=False" in handler\n',
        '    assert "allow_write=writes_http" in handler\n'
        '    assert "require_http_request_authority(" in handler\n'
        '    assert "requested_budget=requested_budget" in handler\n'
        '    assert "capability_input=capability_input" in handler\n', path)
    path = "skills/hunt/SKILL.md"
    result[path] = once(result[path], "## Investigate\n", """## Authorized HTTP workflows

`http.request` supports GET/HEAD/OPTIONS and authorized POST/PUT/PATCH/DELETE with
one `json_body` or `form_body`. Read the running server's schema; do not declare
PUT or pairing unavailable from an older read-only description. The same capability
and saved principal references apply across web, API, network and device Hunts.

For an operator-requested workflow such as TV pairing, request
`allow_state_changing_http: true` when creating the Hunt and reuse the target's
standing authorization. Do not ask again for each HTTP verb, port, or pairing step.
An already-admitted passive Hunt has not gained write authority; start an appropriately
configured Hunt using the existing target authorization rather than inventing a receipt.

Bodies here are non-secret workflow inputs. Reusable secrets stay in managed profiles
or encrypted collections. Do not claim that this capability completes a secret-bearing
pairing exchange, or that a response status proves pairing succeeded. Preserve the
actual response and report the specific remaining credential/protocol capability gap.
Write redirects are observations; do not replay them automatically. Follow a necessary
next step explicitly under the same authority and budget. A missing permission, missing
executor, transport failure, and model refusal are different diagnoses.

See `docs/hunt-http-writes.md` for the synthetic pairing-start request and remaining work.

## Investigate
""", path)
    path = "skills/web/core/02-tool-execution-safety.md"
    result[path] = once(result[path],
        '| Baseline request | `http.request` | Read-only request; not arbitrary body replay or a raw connection |',
        '| HTTP request / workflow step | `http.request` | GET/HEAD/OPTIONS are baseline requests; POST/PUT/PATCH/DELETE plus JSON/form bodies require saved state-changing authority and are metered. Not a raw socket or arbitrary body export. |', path)
    return result

def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--diff", type=Path)
    args = parser.parse_args()
    root = Path(git(args.repository.resolve(), "rev-parse", "--show-toplevel"))
    if git(root, "rev-parse", "HEAD") != BASE:
        raise ValueError(f"Expected audited base {BASE}")
    if git(root, "status", "--porcelain"):
        raise ValueError("Worktree is not clean")
    original = {}
    for path, expected in HASHES.items():
        data = (root / path).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected:
            raise ValueError(f"{path}: original blob mismatch; no files written")
        original[path] = data.decode("utf-8")
    result = transformations(original)
    for path in NEW_FILES:
        if (root / path).exists():
            raise ValueError(f"{path} already exists")
        result[path] = (HERE / path).read_text(encoding="utf-8")
    for path, source in result.items():
        if path.endswith(".py"):
            ast.parse(source, filename=path)
    diff = "".join("".join(difflib.unified_diff(
        original.get(path, "").splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile=f"a/{path}" if path in original else "/dev/null", tofile=f"b/{path}",
    )) for path, source in sorted(result.items()))
    if args.diff:
        args.diff.write_text(diff, encoding="utf-8")
    if args.check:
        print(f"Validated {len(result)} files without changing repository sources")
        return 0
    for path, source in result.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source, encoding="utf-8")
    print(f"Applied {len(result)} files; review diff and test results")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
