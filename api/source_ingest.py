"""Opt-in grey-box source grounding (B2): Python port of T3MP3ST's whitebox ingest.

Stdlib-only and host-testable: crawl -> regex function/class block extraction ->
exposure/risk classification -> greedy budget pack. Deviations from the TS pipeline
(src/recon/code-ingest.ts): no tree-sitter grammars, no call graph, no reachability
scoring — route/risk heuristics are regex-based and exposure ranking is content +
path based. Everything produced here is a LEAD or an excerpt for the planner —
never a finding, never an approved invariant contract.

Containment is a faithful port of ``resolveContainedRepoPath``: the repo must
resolve (after realpath on BOTH sides) inside the configured source root
(``SHAKERSCAN_SOURCE_ROOT``), which is REQUIRED — unlike T3MP3ST's homedir default,
we fail closed when the operator has not explicitly designated a source root.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Optional

SOURCE_ROOT_ENV = "SHAKERSCAN_SOURCE_ROOT"


class SourceIngestError(Exception):
    """Clean operator-facing ingest failure (maps to HTTP 400, never a 500)."""


def resolve_contained_source_path(input_path: Any, *, environ: Optional[Mapping[str, str]] = None) -> str:
    """Resolve ``input_path`` to a real directory contained in the configured source root.

    Mirrors T3MP3ST resolveContainedRepoPath (whitebox.ts:200-224): realpath both the root and
    the candidate (symlink-safe), require a directory, and reject anything whose relative path
    escapes the root. The root comes from SHAKERSCAN_SOURCE_ROOT and is REQUIRED.
    """
    env = environ if environ is not None else os.environ
    if not isinstance(input_path, str) or not input_path.strip():
        raise SourceIngestError("source_dir is required and must be a non-empty string")
    root_raw = (env.get(SOURCE_ROOT_ENV) or "").strip()
    if not root_raw:
        raise SourceIngestError(
            f"{SOURCE_ROOT_ENV} is not set; designate the directory tree sources may be ingested from")
    try:
        root = os.path.realpath(root_raw)
        if not os.path.isdir(root):
            raise SourceIngestError(f"configured {SOURCE_ROOT_ENV} does not resolve to an existing directory")
    except OSError:
        raise SourceIngestError(f"configured {SOURCE_ROOT_ENV} does not resolve to an existing directory")
    try:
        real = os.path.realpath(input_path.strip())
    except OSError:
        raise SourceIngestError("source_dir does not resolve to an existing path")
    if os.path.commonpath((root, real)) != root:
        raise SourceIngestError(
            f"source_dir resolves outside the allowed root ({root}). "
            f"Set {SOURCE_ROOT_ENV} to analyze sources kept elsewhere.")
    if not os.path.isdir(real):
        raise SourceIngestError("source_dir must be a directory")
    return real


# =============================================================================
# Crawl
# =============================================================================

_INCLUDE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php", ".java", ".cs")
_DEFAULT_EXCLUDES = frozenset({
    "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "target", "vendor",
    "venv", ".venv", "__pycache__", ".next", ".nuxt", "coverage", ".idea", ".vscode",
    "migrations", "fixtures", "__fixtures__", "testdata",
})
_MAX_FILE_BYTES = 256_000
_MAX_FILES = 400
_MAX_TOTAL_BYTES = 4_000_000
_MAX_BLOCKS = 1200
_BLOCK_MAX_LINES = 80


def _crawl(root: str) -> tuple[list[Path], bool]:
    """Deterministic recursive walk (sorted descent), extension allowlist + default excludes,
    file-count and byte ceilings. Returns (paths, truncated)."""
    out: list[Path] = []
    total_bytes = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _DEFAULT_EXCLUDES)
        for name in sorted(filenames):
            if not name.endswith(_INCLUDE_EXTS):
                continue
            path = Path(dirpath) / name
            try:
                resolved = path.resolve(strict=True)
                if os.path.commonpath((root, str(resolved))) != root or not resolved.is_file():
                    continue
                size = resolved.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > _MAX_FILE_BYTES:
                continue
            if len(out) >= _MAX_FILES or total_bytes + size > _MAX_TOTAL_BYTES:
                truncated = True
                break
            out.append(resolved)
            total_bytes += size
        if truncated:
            break
    return out, truncated


# =============================================================================
# Block extraction (regex; no tree-sitter)
# =============================================================================

_BLOCK_START = re.compile(
    r"^(?:export\s+)?(?:async\s+)?(?:"
    r"def\s+\w+|class\s+\w+"                              # python
    r"|function\s+\w+|[\w$]+\s*=\s*(?:async\s*)?(?:function|\()"  # js/ts
    r"|func\s+(?:\(\w+\s+[\w*]+\)\s+)?\w+"                # go
    r"|def\s+\w+|class\s+\w+"                             # ruby (same kw)
    r"|public\s+(?:static\s+)?[\w<>\[\]]+\s+\w+\s*\("     # java/c#
    r"|\[(?:Route|Http(?:Get|Post|Put|Patch|Delete))"     # c# attrs
    r"|@(app|router)\.(route|get|post|put|patch|delete)"  # flask-style decorators
    r")"
)


def _extract_blocks(rel_path: str, text: str) -> list[dict[str, Any]]:
    """Split a file into definition-anchored blocks (cap _BLOCK_MAX_LINES each); a file with no
    definition match contributes one whole-file block. Blocks carry 1-based start lines."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if _BLOCK_START.match(line.strip())]
    if not starts:
        body = "\n".join(lines[:_BLOCK_MAX_LINES])
        return [{"path": rel_path, "start": 1, "body": body}] if body.strip() else []
    blocks: list[dict[str, Any]] = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else min(len(lines), start + _BLOCK_MAX_LINES)
        end = min(end, start + _BLOCK_MAX_LINES)
        body = "\n".join(lines[start:end])
        if body.strip():
            blocks.append({"path": rel_path, "start": start + 1, "body": body})
    return blocks


# =============================================================================
# Exposure + risk classification
# =============================================================================

_ROUTE_RES: tuple[tuple[re.Pattern[str], Optional[str]], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), method) for pattern, method in (
        (r"@(?:app|router|bp)\.(route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", None),
        (r"(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", None),
        (r"\.(?:route)\s*\(\s*[\"']([^\"']+)", None),
        (r"http\.HandleFunc\s*\(\s*[\"']([^\"']+)", None),
        (r"@(Get|Post|Put|Patch|Delete|RequestMapping)\s*\(\s*[\"']?([^\"')]*)", None),
        (r"\[(?:Route|Http(Get|Post|Put|Patch|Delete))\s*\(?\s*[\"']?([^\"'\)]*)", None),
    )
)

_ATTACK_SURFACE_RE = re.compile(
    r"(?:req\.|request\.|params\[|query\[|\.query|\.body|HttpRequest|RequestContext|"
    r"$_GET|$_POST|$_REQUEST|\.form\[|\.args\.get)", re.IGNORECASE)
_SECURITY_CONTROL_RE = re.compile(
    r"(?:login_required|require_auth|authorize|permission|has_role|is_admin|jwt\.|verify_token|"
    r"check_password|authenticate|@roles|policy\.|access_control)", re.IGNORECASE)
_RISK_RES: tuple[re.Pattern[str], ...] = tuple(re.compile(pattern) for pattern in (
    r"\beval\s*\(", r"\bexec\s*\(", r"os\.system", r"subprocess\.", r"shell\s*=\s*True",
    r"pickle\.loads", r"yaml\.load\s*\(", r"innerHTML", r"document\.write",
    r"dangerouslySetInnerHTML", r"(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*(?:\+|f[\"'])",
    r"\.execute\s*\(\s*(?:f[\"']|[^)]*\+)", r"send_file\s*\(", r"redirect\s*\(\s*(?:request|req)",
    r"jwt\.decode\s*\([^)]*verify\s*=\s*False", r"child_process\.exec", r"Runtime\.getRuntime",
    r"ObjectInputStream", r"unserialize\s*\(",
))
_SSRF_IDOR_SHAPE_RE = re.compile(
    r"(?:fetch|get|post|request)\s*\(\s*(?:req\.|request\.|params|\.query)[^)]*(?:url|uri|href|host)"
    r"|(?:url|uri|href)\s*=\s*(?:req\.|request\.)", re.IGNORECASE)

_EXPOSURE_BASE = {
    "exposed_externally": 100,
    "attack_surface": 80,
    "exposed_internally": 50,
    "security_control": 40,
    "neutral": 10,
}

_ROUTE_PATH_RE = re.compile(r"[\"'](/(?:api|rest|v\d|auth|admin|user|account|order|workshop)[^\"']*)[\"']")


def _classify(block: dict[str, Any]) -> dict[str, Any]:
    body = block["body"]
    route_match = _ROUTE_PATH_RE.search(body)
    decorated = any(pattern.search(body) for pattern, _m in _ROUTE_RES)
    if decorated:
        exposure = "exposed_externally"
    elif _ATTACK_SURFACE_RE.search(body):
        exposure = "attack_surface"
    elif _SECURITY_CONTROL_RE.search(body):
        exposure = "security_control"
    else:
        exposure = "neutral"
    signals = [pattern.pattern[:40] for pattern in _RISK_RES if pattern.search(body)]
    score = _EXPOSURE_BASE[exposure] + 10 * len(signals)
    if _SSRF_IDOR_SHAPE_RE.search(body):
        score += 20
        signals.append("ssrf_idor_shape")
    return {
        **block,
        "exposure": exposure,
        "risk_signals": signals[:8],
        "score": score,
        "route_hint": route_match.group(1)[:200] if route_match else None,
    }


# =============================================================================
# Pack
# =============================================================================

def ingest_source_excerpt(repo_dir: str, *, token_budget: int = 6000) -> dict[str, Any]:
    """Crawl -> extract -> classify -> greedy budget pack. Returns a security-ordered excerpt
    (highest-priority blocks first), ingest stats, and route hints for lead generation."""
    root = os.path.realpath(repo_dir)
    files, truncated = _crawl(root)
    blocks: list[dict[str, Any]] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = os.path.relpath(str(path), root)
        blocks.extend(_extract_blocks(rel, text))
        if len(blocks) >= _MAX_BLOCKS:
            truncated = True
            blocks = blocks[:_MAX_BLOCKS]
            break
    ranked = sorted(
        (_classify(block) for block in blocks),
        key=lambda item: (-item["score"], item["path"], item["start"]),
    )
    char_budget = max(1000, int(token_budget) * 4)
    packed: list[str] = []
    hints: list[dict[str, Any]] = []
    used = 0
    included = 0
    for unit in ranked:
        header = f"=== {unit['path']}:L{unit['start']} [{unit['exposure']}]"
        if unit["risk_signals"]:
            header += f" signals={len(unit['risk_signals'])}"
        header += " ==="
        chunk = f"{header}\n{unit['body']}"
        if used + len(chunk) > char_budget:
            continue
        packed.append(chunk)
        used += len(chunk) + 2
        included += 1
        if unit["exposure"] == "exposed_externally" and unit.get("route_hint") and len(hints) < 50:
            method = "GET"
            verb = re.search(
                r"(?i)\.(get|post|put|patch|delete)\s*\(|@(Get|Post|Put|Patch|Delete)|"
                r"Http(Get|Post|Put|Patch|Delete)", unit["body"])
            if verb:
                method = next((g.upper() for g in verb.groups() if g), "GET")
            hints.append({
                "kind": "route",
                "route": unit["route_hint"],
                "method": method,
                "metadata_json": {
                    "source": "source_ingest",
                    "file": f"{unit['path']}:L{unit['start']}",
                    "risk_signals": unit["risk_signals"],
                },
            })
    text = (
        "SOURCE EXCERPT (operator-supplied repo; grey-box grounding — hints and leads only, "
        "verify everything live):\n" + "\n\n".join(packed)
    )
    by_exposure: dict[str, int] = {}
    for unit in ranked:
        by_exposure[unit["exposure"]] = by_exposure.get(unit["exposure"], 0) + 1
    return {
        "text": text,
        "stats": {
            "files": len(files),
            "blocks": len(ranked),
            "included_units": included,
            "dropped_units": len(ranked) - included,
            "by_exposure": by_exposure,
            "truncated": truncated,
            "token_budget": int(token_budget),
        },
        "hints": hints,
    }


def ingest_source(source_dir: Any, *, token_budget: int = 6000,
                  environ: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    """Containment-checked ingest entry point (raises SourceIngestError on any boundary)."""
    real = resolve_contained_source_path(source_dir, environ=environ)
    result = ingest_source_excerpt(real, token_budget=token_budget)
    result["source_root"] = real
    return result


if __name__ == "__main__":  # self-test
    import tempfile

    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        os.environ[SOURCE_ROOT_ENV] = root
        repo = Path(root) / "app"
        repo.mkdir()
        (repo / "routes.py").write_text(
            "from flask import request\n\n"
            "@app.route('/api/users')\n"
            "def users():\n"
            "    q = request.args.get('q')\n"
            "    return db.execute('SELECT * FROM users WHERE name=' + q)\n"
        )
        (repo / "util.py").write_text("def add(a, b):\n    return a + b\n")
        result = ingest_source(str(repo), token_budget=2000)
        assert result["stats"]["files"] == 2
        assert result["stats"]["by_exposure"]["exposed_externally"] == 1
        assert result["hints"] and result["hints"][0]["route"] == "/api/users"
        assert "routes.py" in result["text"] and "util.py" in result["text"]
        try:
            ingest_source(outside)
            raise SystemExit("containment failed")
        except SourceIngestError:
            pass
        print(json.dumps(result["stats"], indent=2, sort_keys=True))
