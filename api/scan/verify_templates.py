"""Verify a vulnerability candidate with exactly the checks it names, as a normal Scan.

An Exposure candidate (a CVE matched to an observed product/version) may name the
Nuclei templates the pinned bundle ships for that CVE. ``verify_templates`` on a Scan
submission runs those templates -- and no other active template -- against the target's
frozen origin. Everything else is an ordinary Scan: the target's standing authorization,
the active-testing policy, budgets, placement and proof rules apply unchanged.

The immutable template manifest is the authority: each verify template is one manifest
entry bound to the pinned template bundle. At execution the worker re-reads the template
from that bundle and still drops intrusive templates, and non-GET templates unless
state-changing HTTP is authorized, failing closed with a coverage gap.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

MAX_VERIFY_TEMPLATES = 10
VERIFY_TEMPLATE_TAG = "cve-verify"
VERIFY_TEMPLATE_RISK = "safe_active"
VERIFY_SEVERITIES = "info,low,medium,high,critical"
_TEMPLATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


class VerifyTemplatesError(ValueError):
    """A verify request the Scan cannot admit; the message names what is missing."""


def normalized_verify_template_ids(values: Any) -> tuple[str, ...]:
    if values in (None, (), []):
        return ()
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise VerifyTemplatesError("verify_templates must be a list of template ids")
    ids = []
    for value in values:
        text = str(value or "").strip().lower() if isinstance(value, str) else ""
        if not _TEMPLATE_ID.fullmatch(text):
            raise VerifyTemplatesError("verify_templates contains an invalid template id")
        ids.append(text)
    unique = tuple(sorted(set(ids)))
    if len(unique) > MAX_VERIFY_TEMPLATES:
        raise VerifyTemplatesError(f"verify_templates accepts at most {MAX_VERIFY_TEMPLATES} templates")
    return unique


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def verify_template_digest(template_id: str, *, bundle_commit: str, bundle_sha256: str) -> str:
    """Bind one verify entry to the exact pinned template bundle it is read from."""
    return _digest({
        "schema_version": "canonical-nuclei-verify-template/v1",
        "template_bundle_commit": bundle_commit,
        "template_bundle_sha256": bundle_sha256,
        "template_id": template_id,
    })


def verify_template_rows(ids: Iterable[str], *, bundle_commit: str, bundle_sha256: str) -> list[dict[str, Any]]:
    return [{
        "template_id": template_id,
        "template_digest": verify_template_digest(
            template_id, bundle_commit=bundle_commit, bundle_sha256=bundle_sha256),
        "risk": VERIFY_TEMPLATE_RISK,
        "tags": [VERIFY_TEMPLATE_TAG],
    } for template_id in normalized_verify_template_ids(list(ids))]


def manifest_verify_template_ids(entries: Sequence[Mapping[str, Any]], *, bundle_commit: str,
                                 bundle_sha256: str) -> tuple[str, ...]:
    """The verify entries of a manifest; an entry that claims the tag but does not bind to the
    pinned bundle is an error, never silently dropped."""
    ids = []
    for entry in entries:
        if list(entry.get("tags") or ()) != [VERIFY_TEMPLATE_TAG]:
            continue
        template_id = str(entry.get("template_id") or "")
        if (
            not _TEMPLATE_ID.fullmatch(template_id)
            or entry.get("risk") != VERIFY_TEMPLATE_RISK
            or entry.get("batch_index") != 0
            or entry.get("template_digest") != verify_template_digest(
                template_id, bundle_commit=bundle_commit, bundle_sha256=bundle_sha256)
        ):
            raise VerifyTemplatesError("template manifest holds an unbound verify template")
        ids.append(template_id)
    if len(ids) > MAX_VERIFY_TEMPLATES:
        raise VerifyTemplatesError("template manifest holds too many verify templates")
    return tuple(sorted(set(ids)))


def verify_scan_options(ids: Sequence[str], *, bundle_commit: str, bundle_sha256: str) -> dict[str, Any]:
    return {
        "severity": VERIFY_SEVERITIES,
        "template_pack_digest": _digest({
            "schema_version": "canonical-nuclei-verify-pack/v1",
            "template_bundle_commit": bundle_commit,
            "template_bundle_sha256": bundle_sha256,
            "template_ids": list(ids),
        }),
        "verify_template_ids": ",".join(ids),
    }
