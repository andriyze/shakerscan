#!/usr/bin/env python3
"""Write a content-free, explicitly non-publishing V2 acceptance receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_IMAGES = {"scanner", "api", "ui", "signer"}
REQUIRED_TOOLS = {"docker", "node", "npm", "python"}


class CandidateAcceptanceError(RuntimeError):
    """The acceptance evidence is incomplete or not exactly bound."""


def _pairs(values: list[str], *, subject: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, item = str(value).partition("=")
        name, item = name.strip(), item.strip()
        if not separator or not name or not item or name in result:
            raise CandidateAcceptanceError(f"invalid {subject} binding: {value}")
        result[name] = item
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise CandidateAcceptanceError(
            f"cannot hash acceptance evidence {path.name}: {exc}"
        ) from exc
    return digest.hexdigest()


def _json_object(path: Path, *, subject: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateAcceptanceError(f"cannot read {subject}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise CandidateAcceptanceError(f"{subject} must contain one JSON object")
    return value


def build_receipt(
    *,
    source_sha: str,
    workflow_sha: str,
    images: Mapping[str, str],
    tool_versions: Mapping[str, str],
    template_manifest_path: Path,
    evidence_paths: Mapping[str, Path],
) -> dict[str, Any]:
    if not SOURCE_SHA.fullmatch(source_sha):
        raise CandidateAcceptanceError("candidate source must be a full lowercase SHA")
    if not SOURCE_SHA.fullmatch(workflow_sha):
        raise CandidateAcceptanceError("workflow source must be a full lowercase SHA")
    if set(images) != REQUIRED_IMAGES or not all(
        SHA256.fullmatch(str(value)) for value in images.values()
    ):
        raise CandidateAcceptanceError(
            "exact scanner, API, UI, and signer image identities are required"
        )
    if set(tool_versions) != REQUIRED_TOOLS or not all(tool_versions.values()):
        raise CandidateAcceptanceError(
            "Docker, Node, npm, and Python versions are required"
        )
    manifest = _json_object(
        template_manifest_path, subject="template manifest evidence"
    )
    if manifest.get("schema_version") != "template-manifest/v1":
        raise CandidateAcceptanceError("template manifest schema is not canonical V1")
    manifest_digest = str(manifest.get("manifest_digest") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_digest):
        raise CandidateAcceptanceError("template manifest has no exact digest")
    if not evidence_paths:
        raise CandidateAcceptanceError("candidate acceptance evidence is required")
    evidence = {
        name: _sha256(path)
        for name, path in sorted(evidence_paths.items())
    }
    receipt: dict[str, Any] = {
        "schema_version": "v2-candidate-acceptance/v1",
        "status": "pass",
        "publication": "none",
        "promotion_authorized": False,
        "candidate_sha": source_sha,
        "workflow_sha": workflow_sha,
        "reachability_ref": "refs/heads/v2",
        "images": dict(sorted(images.items())),
        "tool_versions": dict(sorted(tool_versions.items())),
        "template_manifest": {
            "manifest_digest": manifest_digest,
            "evidence_sha256": _sha256(template_manifest_path),
        },
        "evidence_sha256": evidence,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--tool-version", action="append", default=[])
    parser.add_argument("--template-manifest", required=True, type=Path)
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        evidence = {
            name: Path(path)
            for name, path in _pairs(args.evidence, subject="evidence").items()
        }
        receipt = build_receipt(
            source_sha=args.source_sha,
            workflow_sha=args.workflow_sha,
            images=_pairs(args.image, subject="image"),
            tool_versions=_pairs(args.tool_version, subject="tool version"),
            template_manifest_path=args.template_manifest,
            evidence_paths=evidence,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except CandidateAcceptanceError as exc:
        print(f"V2 candidate acceptance failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
