"""Reversible, bounded endpoint groups for the Hunt frontier.

Equal HTTP statuses do not establish a shared handler. Status-only sibling
inference is disabled: literal routes remain separate. Identifier-shaped path
segments are only a tentative grouping hint, never evidence of route existence.
Client routes, trailing slashes and namespaces retain their original identity.

Group identity includes method, authentication context, parameter shape/location
and content type. Exact duplicates reduce sample_count, but all member IDs and
results survive. Representatives are metadata-only; use their IDs for drill-down.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Any, Iterable, Mapping

_INTEGER = re.compile(r"^[0-9]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{24,}$")
SPEC_DECLARED = "spec_declared"
ID_SHAPED = "id_shaped_segment"
UNGROUPED = "distinct_path"
# Retained for readers of historical output, never emitted by this implementation.
HOMOGENEOUS_SIBLINGS = "homogeneous_siblings"
EXACT_DUPLICATES = "identical_requests"
_LANES = ("unresolved_lead", "unexplored", "follow_up", "settled")


def _variant(row: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(row.get("method") or "GET").upper(),
        str(row.get("auth_state") or "anonymous"),
        str(row.get("param_shape") or ""),
        str(row.get("param_location") or ""),
        str(row.get("content_type") or ""),
    )


def _lane(row: Mapping[str, Any]) -> str:
    verdict = str(row.get("last_verdict") or "untested").lower()
    status = str(row.get("test_status") or "").lower()
    # Inventory findings are leads, not a second proof/verification predicate.
    if verdict == "findings":
        return "unresolved_lead"
    if status in {"untested", "stale"} or verdict == "untested":
        return "unexplored"
    if verdict in {"clean", "exploited", "verified"} and status not in {"partial", "error"}:
        return "settled"
    return "follow_up"


def _row_order(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (_LANES.index(_lane(row)), str(row.get("path") or "/"),
            _variant(row), str(row.get("id") or ""))


@dataclass
class EndpointGroup:
    method: str
    auth_state: str
    template: str
    evidence: str
    param_shape: str = ""
    param_location: str = ""
    content_type: str = ""
    sample_count: int = 0
    member_count: int = 0
    sample_ids: list[str] = field(default_factory=list)
    representatives: list[dict[str, Any]] = field(default_factory=list)
    principal_contexts: list[str] = field(default_factory=list)
    prior_results: dict[str, int] = field(default_factory=dict)
    open_questions: list[str] = field(default_factory=list)
    frontier_state: str = "settled"

    @property
    def identity(self) -> tuple[str, ...]:
        return (self.method, self.auth_state, self.template, self.param_shape,
                self.param_location, self.content_type)

    def as_row(self) -> dict[str, Any]:
        group_id = hashlib.sha256(json.dumps(self.identity).encode()).hexdigest()
        return {
            "group_id": group_id, "method": self.method, "auth_state": self.auth_state,
            "route_template": self.template, "grouping_evidence": self.evidence,
            "grouping_inferred": self.evidence == ID_SHAPED,
            "param_shape": self.param_shape or None,
            "param_location": self.param_location or None,
            "content_type": self.content_type or None,
            "sample_count": self.sample_count, "member_count": self.member_count,
            "duplicate_count": self.member_count - self.sample_count,
            "representatives": self.representatives,
            "principal_contexts": self.principal_contexts,
            "prior_results": self.prior_results, "open_questions": self.open_questions,
            "sample_ids": self.sample_ids, "frontier_state": self.frontier_state,
        }


def _template_for(path: str, spec: set[str], namespaces: set[str]) -> tuple[str, str]:
    if "#" in path:
        return path, UNGROUPED
    # Explicit literal operations take precedence over a parameter declaration.
    if path in spec:
        return path, SPEC_DECLARED
    if path.rstrip("/") in namespaces:
        return path, UNGROUPED
    suffix = "/" if path.endswith("/") else ""
    parent, _, segment = path.rstrip("/").rpartition("/")
    if not parent:
        return path, UNGROUPED
    candidate = f"{parent}/{{id}}{suffix}"
    if candidate in spec:
        return candidate, SPEC_DECLARED
    if any(pattern.fullmatch(segment) for pattern in (_INTEGER, _UUID, _LONG_HEX)):
        return candidate, ID_SHAPED
    return path, UNGROUPED


def group_endpoint_rows(
    rows: Iterable[Mapping[str, Any]], *, spec_templates: Iterable[str] = (),
    representatives_per_group: int = 3,
) -> list[EndpointGroup]:
    """Project rows without deleting any member or promoting status similarity to a route.

    Optional declarations apply to this input's method scope; the production
    query does not currently supply specifications. Keep representative counts
    bounded independently from member IDs.
    """
    if type(representatives_per_group) is not int or not 1 <= representatives_per_group <= 10:
        raise ValueError("representatives_per_group must be between 1 and 10")
    materialised = sorted((dict(row) for row in rows), key=_row_order)
    spec = set(spec_templates)
    namespaces = {
        str(row.get("path") or "").rstrip("/").rpartition("/")[0]
        for row in materialised if "#" not in str(row.get("path") or "")
    }
    grouped: dict[tuple[str, ...], EndpointGroup] = {}
    seen: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for row in materialised:
        method, auth, shape, location, content_type = _variant(row)
        path = str(row.get("path") or "/")
        template, evidence = _template_for(path, spec, namespaces)
        key = (method, auth, template, shape, location, content_type)
        if key not in grouped:
            grouped[key] = EndpointGroup(method, auth, template, evidence, shape,
                                         location, content_type, principal_contexts=[auth])
        group = grouped[key]
        group.member_count += 1
        if row.get("id") is not None:
            group.sample_ids.append(str(row["id"]))
        verdict = str(row.get("last_verdict") or "untested")
        group.prior_results[verdict] = group.prior_results.get(verdict, 0) + 1
        if _LANES.index(_lane(row)) < _LANES.index(group.frontier_state):
            group.frontier_state = _lane(row)
        # Only the distinct-sample counter and representative list are deduplicated.
        # IDs and results above must include later duplicate rows too.
        if path in seen[key]:
            continue
        seen[key].add(path)
        group.sample_count += 1
        if len(group.representatives) < representatives_per_group:
            group.representatives.append({
                "id": str(row["id"]) if row.get("id") is not None else None,
                "path": path, "param_shape": shape or None,
                "param_location": location or None, "content_type": content_type or None,
                "last_http_status": row.get("last_http_status"),
                "test_status": row.get("test_status"), "last_verdict": row.get("last_verdict"),
            })
    for group in grouped.values():
        group.sample_ids.sort()
        group.prior_results = dict(sorted(group.prior_results.items()))
        if group.member_count > group.sample_count:
            group.open_questions.append(
                f"{group.member_count - group.sample_count} identical request(s) collapsed; all IDs retained"
            )
        if group.evidence == ID_SHAPED:
            group.open_questions.append("identifier-shaped grouping is tentative; confirm through sample_ids")
        if group.frontier_state == "unexplored":
            group.open_questions.append("contains unexplored samples; prior results do not establish coverage")
        if group.principal_contexts == ["anonymous"]:
            group.open_questions.append("only inventoried anonymously; authenticated behavior is unknown")
    # Round-robin active lanes reserves exploration slots. Neither density nor
    # parameterization changes rank. Completed/clean-only groups follow active work.
    lanes: dict[str, list[EndpointGroup]] = {name: [] for name in _LANES}
    for group in sorted(grouped.values(), key=lambda item: item.identity):
        lanes[group.frontier_state].append(group)
    active = [group for batch in zip_longest(*(lanes[name] for name in _LANES[:-1]))
              for group in batch if group is not None]
    return active + lanes["settled"]
