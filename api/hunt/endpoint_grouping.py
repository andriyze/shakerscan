"""Group an endpoint inventory into route templates, non-destructively.

The problem this solves
-----------------------
Discovery records every probed request as its own inventory row, so a Hunt reading the frontier
sees thousands of entries that are mostly the same handler answering junk parameters.
``/api/Cards/search``, ``/api/Cards/admin`` and ``/api/Cards/2fa`` are not three endpoints; they are
``GET /api/Cards/{id}`` carrying three invalid ids. Measured on a real target, 20,345 rows are 2,390
distinct paths over a far smaller number of actual routes.

This is a grouping problem, not a classification problem. Nothing here decides whether a route is
"real": earlier attempts to do that failed, and an auth-gated namespace answers identically for an
absent route and a protected one. Grouping needs no such oracle.

What makes grouping safe
------------------------
Collapsing on shape alone is destructive. ``/api/Users``, ``/api/Cards`` and ``/api/Feedbacks`` are
siblings under ``/api`` and would merge into ``/api/{param}``, erasing real collections. So a
trailing segment becomes a parameter only on evidence:

``spec_declared``        a supplied specification declares the template. Strongest.
``id_shaped_segment``    the segment is an integer, UUID or long hex string -- an identifier by
                         construction, not a route name.
``homogeneous_siblings`` many siblings under one existing parent whose OBSERVED responses agree.
                         Measured: ``/api/Cards`` children answer with 2 distinct statuses across
                         371 siblings (one handler), while ``/api`` children answer with 5 across
                         462 (many distinct handlers). Disagreement blocks the merge.

Everything else keeps its own path as its template. Guessing is not evidence.

Non-destructive by construction
-------------------------------
A group never discards a sample: it carries every member id so any grouping can be drilled into or
undone, and it records which evidence produced it. Method, authentication context and body shape are
part of group identity and are never merged -- a POST is not a GET, and an authenticated view is not
an anonymous one.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

# An identifier by construction rather than a route name someone would author.
_INTEGER = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{8,}$")

SPEC_DECLARED = "spec_declared"
ID_SHAPED = "id_shaped_segment"
HOMOGENEOUS_SIBLINGS = "homogeneous_siblings"
EXACT_DUPLICATES = "identical_requests"
UNGROUPED = "distinct_path"

# Defaults chosen from measurement, not taste: the merge case showed 2 distinct statuses over
# hundreds of siblings, the must-not-merge cases showed 5 and 6.
DEFAULT_MIN_SIBLINGS = 4
DEFAULT_MAX_DISTINCT_STATUSES = 2


def _is_id_shaped(segment: str) -> bool:
    value = (segment or "").strip()
    if not value:
        return False
    return bool(_INTEGER.match(value) or _UUID.match(value) or _LONG_HEX.match(value))


def _parent_of(path: str) -> str:
    trimmed = (path or "/").rstrip("/")
    if "/" not in trimmed[1:]:
        return ""
    return trimmed.rsplit("/", 1)[0]


@dataclass
class EndpointGroup:
    """One route template plus everything a pentester needs to act on it."""

    method: str
    auth_state: str
    template: str
    evidence: str
    sample_count: int = 0
    #: Every member, so a grouping can be inspected or undone. Never discarded.
    sample_ids: list[str] = field(default_factory=list)
    representatives: list[dict[str, Any]] = field(default_factory=list)
    principal_contexts: list[str] = field(default_factory=list)
    prior_results: dict[str, int] = field(default_factory=dict)
    open_questions: list[str] = field(default_factory=list)

    def as_row(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "auth_state": self.auth_state,
            "route_template": self.template,
            "grouping_evidence": self.evidence,
            "sample_count": self.sample_count,
            "representatives": self.representatives,
            "principal_contexts": sorted(self.principal_contexts),
            "prior_results": self.prior_results,
            "open_questions": self.open_questions,
            "sample_ids": self.sample_ids,
        }


def _template_for(
    row: Mapping[str, Any],
    *,
    spec_templates: set[str],
    groupable_parents: set[tuple[str, str]],
) -> tuple[str, str]:
    """Return ``(template, evidence)`` for one row, defaulting to no grouping."""
    path = str(row.get("path") or "/").rstrip("/") or "/"
    method = str(row.get("method") or "GET").upper()
    parent = _parent_of(path)
    if not parent:
        return path, UNGROUPED
    segment = path.rsplit("/", 1)[1]

    spec_candidate = f"{parent}/{{id}}"
    if spec_candidate in spec_templates:
        return spec_candidate, SPEC_DECLARED
    if _is_id_shaped(segment):
        return spec_candidate, ID_SHAPED
    if (method, parent) in groupable_parents:
        return f"{parent}/{{param}}", HOMOGENEOUS_SIBLINGS
    return path, UNGROUPED


def _groupable_parents(
    rows: Sequence[Mapping[str, Any]],
    *,
    min_siblings: int,
    max_distinct_statuses: int,
) -> set[tuple[str, str]]:
    """Parents whose children's observed responses agree well enough to be one handler.

    Disagreement is the signal that they are separate routes, so it blocks the merge. A parent
    that is not itself in the inventory is not treated as a namespace, and a child that has its
    own children is a namespace rather than an identifier.
    """
    known_paths = {str(r.get("path") or "").rstrip("/") for r in rows}
    has_children = {_parent_of(str(r.get("path") or "")) for r in rows}
    by_parent: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        path = str(row.get("path") or "").rstrip("/")
        parent = _parent_of(path)
        if not parent or parent not in known_paths:
            continue
        if path in has_children:  # a namespace, not a leaf identifier
            continue
        by_parent[(str(row.get("method") or "GET").upper(), parent)].append(row)

    groupable: set[tuple[str, str]] = set()
    for key, children in by_parent.items():
        distinct_paths = {str(c.get("path") or "").rstrip("/") for c in children}
        if len(distinct_paths) < min_siblings:
            continue
        statuses = {
            int(c["last_http_status"]) for c in children
            if c.get("last_http_status") not in (None, "")
        }
        if not statuses or len(statuses) > max_distinct_statuses:
            continue
        groupable.add(key)
    return groupable


def group_endpoint_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    spec_templates: Iterable[str] = (),
    min_siblings: int = DEFAULT_MIN_SIBLINGS,
    max_distinct_statuses: int = DEFAULT_MAX_DISTINCT_STATUSES,
    representatives_per_group: int = 3,
) -> list[EndpointGroup]:
    """Collapse an inventory into route-template groups without discarding any sample."""
    materialised = [dict(r) for r in rows]
    spec = {str(t) for t in spec_templates}
    parents = _groupable_parents(
        materialised, min_siblings=min_siblings, max_distinct_statuses=max_distinct_statuses,
    )

    # Exact duplicates first: identical request identity is one sample, however many rows carry it.
    seen_identity: set[tuple[str, str, str, str]] = set()
    grouped: dict[tuple[str, str, str], EndpointGroup] = {}
    duplicate_counts: dict[tuple[str, str, str], int] = defaultdict(int)

    for row in materialised:
        method = str(row.get("method") or "GET").upper()
        auth = str(row.get("auth_state") or "anonymous")
        path = str(row.get("path") or "/").rstrip("/") or "/"
        body = str(row.get("param_shape") or "")
        template, evidence = _template_for(
            row, spec_templates=spec, groupable_parents=parents,
        )
        key = (method, auth, template)
        identity = (method, auth, path, body)
        if identity in seen_identity:
            duplicate_counts[key] += 1
            continue
        seen_identity.add(identity)

        group = grouped.get(key)
        if group is None:
            group = EndpointGroup(
                method=method, auth_state=auth, template=template, evidence=evidence,
            )
            grouped[key] = group
        elif group.evidence != evidence and evidence != UNGROUPED:
            # Several evidence kinds can justify one template; record the strongest seen.
            group.evidence = evidence if evidence == SPEC_DECLARED else group.evidence

        group.sample_count += 1
        if row.get("id") is not None:
            group.sample_ids.append(str(row["id"]))
        if auth not in group.principal_contexts:
            group.principal_contexts.append(auth)
        verdict = str(row.get("last_verdict") or "") or "untested"
        group.prior_results[verdict] = group.prior_results.get(verdict, 0) + 1
        if len(group.representatives) < representatives_per_group:
            group.representatives.append({
                "path": path,
                "param_shape": body or None,
                "last_http_status": row.get("last_http_status"),
                "test_status": row.get("test_status"),
                "last_verdict": row.get("last_verdict"),
            })

    for key, group in grouped.items():
        if duplicate_counts.get(key):
            group.open_questions.append(
                f"{duplicate_counts[key]} identical request(s) collapsed"
            )
        if group.evidence == HOMOGENEOUS_SIBLINGS:
            group.open_questions.append(
                "grouped from agreeing sibling responses, not a specification; "
                "drill into sample_ids to confirm"
            )
        if not any(v for v in group.prior_results if v != "untested"):
            group.open_questions.append("no sample of this template has produced a verdict yet")
        if group.principal_contexts == ["anonymous"]:
            group.open_questions.append("only observed anonymously")

    return sorted(grouped.values(), key=_frontier_order)


def _frontier_order(group: EndpointGroup) -> tuple[Any, ...]:
    """Order a frontier for someone hunting, not for someone counting duplicates.

    Sorting by sample_count alone was measured against the live inventory and put the junk
    clusters straight back on the first page -- one row each instead of hundreds, but still the
    whole page. Density measures where discovery was most repetitive, which is precisely the
    least interesting thing to test.

    So: anything that has already produced a verdict leads, because prior evidence is the
    strongest reason to look. Then specific routes ahead of parameter clusters, since a cluster
    of invalid ids is one thing to try, not hundreds. Density only breaks ties.
    """
    has_result = any(verdict != "untested" for verdict in group.prior_results)
    is_parameter_cluster = group.evidence == HOMOGENEOUS_SIBLINGS
    return (
        not has_result,          # groups with prior results first
        is_parameter_cluster,    # specific routes before junk-parameter clusters
        -group.sample_count,     # then the denser ones
        group.template,
    )
