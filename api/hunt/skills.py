"""The Hunt skill library: methodology the planner reads, bound to real capabilities.

A skill is testing methodology plus a declaration of which capabilities it needs. It is not
a new execution path, a second registry, or an authority. Binding validates that the Hunt's
existing authority can execute the methodology, but does not grant, remove, or resize that
authority. ``api/hunt/contracts.py`` remains the sole authority on what a run may call.

Skills are published with an honest support level. ShakerScan has no capability for several
adapters the upstream library assumes (out-of-band callbacks, concurrent batches, raw single
connections, file upload, log observation), so those skills are listed as ``partial`` and
cannot be bound. Discovering that mid-run, after the planner has committed to a procedure it
cannot execute, is the failure this replaces.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import pathlib
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.capability_registry import CAPABILITY_REGISTRY


SKILL_LIBRARY_SCHEMA = "hunt-skill/v2"
LIBRARY_DOCUMENT_FILES = frozenset({"README.md"})
SUPPORT_LEVELS = frozenset({"supported", "partial", "reference"})
# Only these may be bound to a run. The others are published for reading.
BINDABLE_SUPPORT = frozenset({"supported"})
MAX_SKILLS_PER_HUNT = 4
MAX_CONTEXT_SKILL_SUGGESTIONS = 3
_SUGGESTION_STOP_WORDS = frozenset({
    "and", "application", "authorized", "comprehensive", "for", "from", "hunt",
    "investigate", "security", "target", "test", "testing", "the", "this", "web",
    "with",
})
# Budget dimensions a skill may lower. Deliberately a subset of the hunt budget: a skill
# declares testing cost, not run topology.
SKILL_BUDGET_DIMENSIONS = frozenset({
    "max_http_requests",
    "max_duration_seconds",
    "max_state_changing_requests",
    "max_oob_interactions",
})
SKILL_TOP_LEVEL_FIELDS = frozenset({
    "id", "name", "title", "description", "version", "kind", "phase", "risk",
    "support", "target_kinds", "capabilities", "optional_capabilities",
    "missing_capabilities", "server_enforced", "server_satisfied_prerequisites",
    "budget", "routing", "preconditions", "techniques", "promotion_gate",
    "requires_skills", "deferred_techniques", "source",
})
SKILL_ROUTING_FIELDS = frozenset({"triggers", "indicators", "exclusions"})
SKILL_DEFERRED_FIELDS = frozenset({"technique", "requires"})


class HuntSkillError(ValueError):
    """A skill declaration is malformed or claims capability it does not have."""


@dataclass(frozen=True)
class HuntSkillSpec:
    """One validated, immutable skill declaration."""

    skill_id: str
    name: str
    title: str
    description: str
    version: str
    kind: str
    phase: str
    risk: str
    support: str
    target_kinds: frozenset[str]
    capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    server_enforced: tuple[str, ...]
    budget: Mapping[str, int]
    triggers: tuple[str, ...]
    indicators: tuple[str, ...]
    exclusions: tuple[str, ...]
    preconditions: tuple[str, ...]
    techniques: tuple[str, ...]
    promotion_gate: str
    requires_skills: tuple[str, ...]
    # Techniques the methodology describes that this runtime cannot execute, each naming what
    # it would need. A skill stays bindable for the part it can run; the rest is stated up
    # front instead of failing when the planner reaches for it.
    deferred_techniques: tuple[Mapping[str, str], ...]
    source: str
    body_sha256: str
    path: str

    @property
    def bindable(self) -> bool:
        return self.support in BINDABLE_SUPPORT

    def catalog_entry(self) -> dict[str, Any]:
        """Small routing record suitable for listing the complete catalog."""
        return {
            "skill_id": self.skill_id,
            "title": self.title,
            "description": self.description,
            "phase": self.phase,
            "support": self.support,
            "bindable": self.bindable,
            "target_kinds": sorted(self.target_kinds),
            "methodology_url": f"/hunt/skills/{self.skill_id}",
        }

    def public(self, *, include_body: bool = False) -> dict[str, Any]:
        """The content-free projection served to clients and planners."""
        item: dict[str, Any] = {
            "schema_version": SKILL_LIBRARY_SCHEMA,
            "skill_id": self.skill_id,
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "version": self.version,
            "kind": self.kind,
            "phase": self.phase,
            "risk": self.risk,
            "support": self.support,
            "bindable": self.bindable,
            "target_kinds": sorted(self.target_kinds),
            "capabilities": list(self.capabilities),
            "optional_capabilities": list(self.optional_capabilities),
            "missing_capabilities": list(self.missing_capabilities),
            "server_enforced": list(self.server_enforced),
            "budget": dict(self.budget),
            "routing": {
                "triggers": list(self.triggers),
                "indicators": list(self.indicators),
                "exclusions": list(self.exclusions),
            },
            "preconditions": list(self.preconditions),
            "techniques": list(self.techniques),
            "promotion_gate": self.promotion_gate,
            "requires_skills": list(self.requires_skills),
            "deferred_techniques": [dict(item) for item in self.deferred_techniques],
            "source": self.source,
            "body_sha256": self.body_sha256,
        }
        if include_body:
            item["methodology"] = read_skill_body(self)
        return item


def _text(value: Any, *, field: str, skill: str, required: bool = True) -> str:
    text = str(value or "").strip()
    if not text and required:
        raise HuntSkillError(f"{skill}: {field} is required")
    return text


def _names(value: Any, *, field: str, skill: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise HuntSkillError(f"{skill}: {field} must be a list")
    out: list[str] = []
    for item in value:
        name = str(item or "").strip()
        if name and name not in out:
            out.append(name)
    return tuple(out)


def _budget(value: Any, *, skill: str) -> Mapping[str, int]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise HuntSkillError(f"{skill}: budget must be an object")
    out: dict[str, int] = {}
    for key, raw in value.items():
        name = str(key).strip()
        if name not in SKILL_BUDGET_DIMENSIONS:
            raise HuntSkillError(f"{skill}: budget dimension {name} is not a skill ceiling")
        try:
            amount = int(raw)
        except (TypeError, ValueError) as exc:
            raise HuntSkillError(f"{skill}: budget {name} must be an integer") from exc
        if amount <= 0:
            raise HuntSkillError(f"{skill}: budget {name} must be positive")
        out[name] = amount
    return MappingProxyType(out)


def _deferred(value: Any, *, skill: str) -> tuple[Mapping[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise HuntSkillError(f"{skill}: deferred_techniques must be a list")
    out: list[Mapping[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise HuntSkillError(f"{skill}: each deferred technique must be an object")
        unknown = sorted(set(item) - SKILL_DEFERRED_FIELDS)
        if unknown:
            raise HuntSkillError(
                f"{skill}: unsupported deferred technique fields: {', '.join(unknown)}"
            )
        technique = str(item.get("technique") or "").strip()
        requires = str(item.get("requires") or "").strip()
        if not technique or not requires:
            raise HuntSkillError(
                f"{skill}: a deferred technique needs both a name and what it requires"
            )
        out.append(MappingProxyType({"technique": technique, "requires": requires}))
    return tuple(out)


def build_skill_spec(meta: Mapping[str, Any], *, path: str, body: str) -> HuntSkillSpec:
    """Validate one declaration against the live capability registry."""
    unknown = sorted(set(meta) - SKILL_TOP_LEVEL_FIELDS)
    if unknown:
        raise HuntSkillError(
            f"{path}: unsupported skill fields: {', '.join(unknown)}"
        )
    skill_id = _text(meta.get("id"), field="id", skill=path)
    support = _text(meta.get("support"), field="support", skill=skill_id)
    if support not in SUPPORT_LEVELS:
        raise HuntSkillError(f"{skill_id}: support {support} is not a known level")

    target_kinds = frozenset(_names(meta.get("target_kinds"), field="target_kinds", skill=skill_id))
    if not target_kinds:
        raise HuntSkillError(f"{skill_id}: target_kinds is required")

    capabilities = _names(meta.get("capabilities"), field="capabilities", skill=skill_id)
    optional = _names(meta.get("optional_capabilities"), field="optional_capabilities", skill=skill_id)
    missing = _names(meta.get("missing_capabilities"), field="missing_capabilities", skill=skill_id)

    # A skill may only name capabilities that exist and that a planner can actually call.
    # Without this the manifest would advertise work the runtime refuses -- the
    # "advertised but not accepted" failure this library is meant to remove.
    for name in (*capabilities, *optional):
        try:
            spec = CAPABILITY_REGISTRY.require(name)
        except KeyError as exc:
            raise HuntSkillError(f"{skill_id}: unknown capability {name}") from exc
        if not spec.planner_visible:
            raise HuntSkillError(f"{skill_id}: capability {name} is not planner-visible")
        if not target_kinds & set(spec.target_kinds):
            raise HuntSkillError(
                f"{skill_id}: capability {name} supports no declared target kind"
            )

    if support == "supported" and missing:
        raise HuntSkillError(
            f"{skill_id}: support is 'supported' while capabilities are still missing"
        )
    if support == "partial" and not missing:
        raise HuntSkillError(f"{skill_id}: support is 'partial' but nothing is missing")
    if support == "supported" and not capabilities:
        raise HuntSkillError(f"{skill_id}: a bindable skill must name at least one capability")

    routing = meta.get("routing") or {}
    if not isinstance(routing, Mapping):
        raise HuntSkillError(f"{skill_id}: routing must be an object")
    unknown_routing = sorted(set(routing) - SKILL_ROUTING_FIELDS)
    if unknown_routing:
        raise HuntSkillError(
            f"{skill_id}: unsupported routing fields: {', '.join(unknown_routing)}"
        )

    return HuntSkillSpec(
        skill_id=skill_id,
        name=_text(meta.get("name"), field="name", skill=skill_id),
        title=_text(meta.get("title"), field="title", skill=skill_id),
        description=_text(meta.get("description"), field="description", skill=skill_id),
        version=_text(meta.get("version"), field="version", skill=skill_id),
        kind=_text(meta.get("kind"), field="kind", skill=skill_id),
        phase=_text(meta.get("phase"), field="phase", skill=skill_id),
        risk=_text(meta.get("risk"), field="risk", skill=skill_id),
        support=support,
        target_kinds=target_kinds,
        capabilities=capabilities,
        optional_capabilities=optional,
        missing_capabilities=missing,
        server_enforced=_names(meta.get("server_enforced"), field="server_enforced", skill=skill_id),
        budget=_budget(meta.get("budget"), skill=skill_id),
        triggers=_names(routing.get("triggers"), field="triggers", skill=skill_id),
        indicators=_names(routing.get("indicators"), field="indicators", skill=skill_id),
        exclusions=_names(routing.get("exclusions"), field="exclusions", skill=skill_id),
        preconditions=_names(meta.get("preconditions"), field="preconditions", skill=skill_id),
        techniques=_names(meta.get("techniques"), field="techniques", skill=skill_id),
        promotion_gate=_text(
            meta.get("promotion_gate"), field="promotion_gate", skill=skill_id, required=False
        ),
        requires_skills=_names(meta.get("requires_skills"), field="requires_skills", skill=skill_id),
        deferred_techniques=_deferred(meta.get("deferred_techniques"), skill=skill_id),
        source=_text(meta.get("source"), field="source", skill=skill_id, required=False),
        body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        path=path,
    )


class HuntSkillLibrary:
    """Validated, immutable-by-convention source of skill truth."""

    def __init__(
        self,
        specs: Iterable[HuntSkillSpec],
        *,
        catalog_status: str = "ready",
        catalog_root: str | None = None,
        catalog_issues: Iterable[Mapping[str, str]] = (),
    ) -> None:
        by_id: dict[str, HuntSkillSpec] = {}
        for spec in specs:
            if spec.skill_id in by_id:
                raise HuntSkillError(f"duplicate skill: {spec.skill_id}")
            by_id[spec.skill_id] = spec
        # A skill cannot require one that is absent or unbindable: the prerequisite would
        # silently never run.
        for spec in by_id.values():
            if not spec.bindable:
                continue
            for required in spec.requires_skills:
                other = by_id.get(required)
                if other is None:
                    raise HuntSkillError(f"{spec.skill_id}: requires unknown skill {required}")
                if not other.bindable:
                    raise HuntSkillError(
                        f"{spec.skill_id}: requires {required}, which is not bindable"
                    )
        self._by_id = MappingProxyType(by_id)
        self.catalog_status = str(catalog_status)
        self.catalog_root = catalog_root
        self.catalog_issues = tuple(MappingProxyType(dict(item)) for item in catalog_issues)

    def health(self) -> dict[str, Any]:
        return {
            "status": self.catalog_status,
            "root": self.catalog_root,
            "loaded_count": len(self),
            "issue_count": len(self.catalog_issues),
            "issues": [dict(item) for item in self.catalog_issues],
        }

    def __len__(self) -> int:
        return len(self._by_id)

    def require(self, skill_id: str) -> HuntSkillSpec:
        try:
            return self._by_id[str(skill_id or "").strip()]
        except KeyError as exc:
            raise KeyError(f"unknown skill: {skill_id}") from exc

    def list(
        self, *, target_kind: str | None = None, support: str | None = None,
    ) -> tuple[HuntSkillSpec, ...]:
        specs = tuple(self._by_id.values())
        if target_kind:
            kind = str(target_kind).strip().lower()
            specs = tuple(item for item in specs if kind in item.target_kinds)
        if support:
            specs = tuple(item for item in specs if item.support == support)
        return tuple(sorted(specs, key=lambda item: item.skill_id))

    def bindable(self, *, target_kind: str | None = None) -> tuple[HuntSkillSpec, ...]:
        return self.list(target_kind=target_kind, support="supported")

    @staticmethod
    def _routing_terms(value: str) -> frozenset[str]:
        return frozenset(
            token for token in re.findall(r"[a-z0-9]+", str(value or "").lower())
            if len(token) > 2 and token not in _SUGGESTION_STOP_WORDS
        )

    def available_for_hunt(
        self,
        *,
        target_kind: str,
        allowed_capabilities: Iterable[str] | None = None,
    ) -> tuple[HuntSkillSpec, ...]:
        """Return bindable skills whose complete prerequisite chain fits this authority.

        The public catalog can call this without an allowlist to describe target-kind support.
        Hunt start passes its already-derived policy allowlist, making the context-pack result
        authoritative without letting a recommendation grant authority.
        """
        available = set(allowed_capabilities) if allowed_capabilities is not None else None
        compatible: list[HuntSkillSpec] = []
        for spec in self.bindable(target_kind=target_kind):
            try:
                expanded = self.resolve_for_hunt([spec.skill_id], target_kind=target_kind)
            except HuntSkillError:
                continue
            if available is not None and any(
                name not in available
                for item in expanded
                for name in item.capabilities
            ):
                continue
            compatible.append(spec)
        return tuple(compatible)

    def suggest(
        self,
        *,
        goal: str,
        target_kind: str,
        allowed_capabilities: Iterable[str] | None = None,
        signals: Iterable[str] = (),
        exclude: Iterable[str] = (),
        limit: int = MAX_CONTEXT_SKILL_SUGGESTIONS,
    ) -> tuple[dict[str, Any], ...]:
        """Return compact, deterministic advice without loading methodology bodies.

        ``goal`` is the operator's objective. ``signals`` are bounded technology or surface
        observations collected later in the run. They influence ranking only: they cannot bind
        a skill, grant a capability, or modify scope.
        """
        goal_terms = self._routing_terms(goal)
        signal_terms = self._routing_terms(" ".join(str(item) for item in signals))
        query_terms = goal_terms | signal_terms
        excluded = {str(item) for item in exclude}
        ranked: list[
            tuple[int, HuntSkillSpec, tuple[str, ...], tuple[str, ...]]
        ] = []
        for spec in self.available_for_hunt(
            target_kind=target_kind, allowed_capabilities=allowed_capabilities,
        ):
            if spec.skill_id in excluded:
                continue
            routing_text = " ".join((
                spec.skill_id, spec.name, spec.title, spec.description,
                *spec.triggers, *spec.indicators, *spec.techniques,
            ))
            skill_terms = self._routing_terms(routing_text)
            matched_goal = tuple(sorted(goal_terms & skill_terms))
            matched_signals = tuple(sorted(signal_terms & skill_terms))
            # Routing metadata is more intentional than prose, so an overlap there is worth
            # more. This remains deterministic advice: only an explicit skill_ids request binds.
            routing_terms = self._routing_terms(" ".join((*spec.triggers, *spec.indicators)))
            score = (
                len(query_terms & skill_terms)
                + (3 * len(goal_terms & routing_terms))
                + (5 * len(signal_terms & routing_terms))
            )
            ranked.append((score, spec, matched_goal, matched_signals))

        ranked.sort(key=lambda item: (-item[0], item[1].skill_id))
        selected = [item for item in ranked if item[0] > 0]
        if not selected:
            # A broad objective still benefits from an explicit baseline. Never silently bind it.
            baseline_order = (
                "skill.web.http-baselining-replay-and-differential-analysis",
                "skill.web.stateful-crawling-content-and-parameter-discovery",
                "skill.web.api-inventory-openapi-and-contract-testing",
            )
            by_id = {item[1].skill_id: item for item in ranked}
            selected = [by_id[skill_id] for skill_id in baseline_order if skill_id in by_id][:1]
        suggestions: list[dict[str, Any]] = []
        for _, spec, matched_goal, matched_signals in selected[:max(0, int(limit))]:
            if matched_signals:
                reason = "Observed signals: " + ", ".join(matched_signals[:4])
            elif matched_goal:
                reason = "Objective matches: " + ", ".join(matched_goal[:4])
            else:
                reason = "Baseline methodology for initial surface discovery"
            suggestions.append({
                "skill_id": spec.skill_id,
                "title": spec.title,
                "reason": reason,
                "methodology_url": f"/hunt/skills/{spec.skill_id}",
                "bind_url": f"/hunts/{{hunt_id}}/skills/{spec.skill_id}/bind",
                "auto_bound": False,
            })
        return tuple(suggestions)

    def resolve_for_hunt(
        self, skill_ids: Iterable[str], *, target_kind: str,
    ) -> tuple[HuntSkillSpec, ...]:
        """Return the exact skills a hunt may bind, or explain why it may not."""
        requested = [str(item or "").strip() for item in skill_ids if str(item or "").strip()]
        if not requested:
            return ()
        if self.catalog_status == "unavailable":
            raise HuntSkillError("Hunt skill catalog is unavailable on this runtime")
        # The cap applies to what the operator chose. Prerequisites are expanded below and
        # do not consume the operator's budget of choices.
        if len(requested) > MAX_SKILLS_PER_HUNT:
            raise HuntSkillError(
                f"a hunt may bind at most {MAX_SKILLS_PER_HUNT} skills"
            )
        seen: list[HuntSkillSpec] = []
        for skill_id in requested:
            try:
                spec = self.require(skill_id)
            except KeyError as exc:
                raise HuntSkillError(f"unknown skill {skill_id}") from exc
            if any(item.skill_id == spec.skill_id for item in seen):
                continue
            if not spec.bindable:
                detail = (
                    ", ".join(spec.missing_capabilities)
                    if spec.missing_capabilities else spec.support
                )
                raise HuntSkillError(
                    f"skill {skill_id} cannot be bound to a hunt ({detail})"
                )
            if str(target_kind).strip().lower() not in spec.target_kinds:
                raise HuntSkillError(
                    f"skill {skill_id} does not support target kind {target_kind}"
                )
            seen.append(spec)
        # Expand prerequisites transitively. A skill that declares one genuinely cannot run
        # without it -- 25 of the 30 need the baselining skill -- so demanding the operator
        # name it as well would only teach them to paste a fixed list.
        expanded = list(seen)
        pending = list(seen)
        while pending:
            spec = pending.pop()
            for required in spec.requires_skills:
                if any(item.skill_id == required for item in expanded):
                    continue
                prerequisite = self.require(required)
                if str(target_kind).strip().lower() not in prerequisite.target_kinds:
                    raise HuntSkillError(
                        f"skill {spec.skill_id} requires {required}, which does not "
                        f"support target kind {target_kind}"
                    )
                expanded.append(prerequisite)
                pending.append(prerequisite)
        return tuple(expanded)

    @staticmethod
    def capability_allowlist(specs: Iterable[HuntSkillSpec]) -> tuple[str, ...]:
        """The union of declared requirements, for diagnostics and UI only."""
        names: list[str] = []
        for spec in specs:
            for name in (*spec.capabilities, *spec.optional_capabilities):
                if name not in names:
                    names.append(name)
        return tuple(sorted(names))

    @staticmethod
    def budget_ceilings(specs: Iterable[HuntSkillSpec]) -> dict[str, int]:
        """Aggregate methodology budget guidance without modifying the Hunt budget."""
        ceilings: dict[str, int] = {}
        for spec in specs:
            for name, amount in spec.budget.items():
                ceilings[name] = max(ceilings.get(name, 0), int(amount))
        return ceilings


def _frontmatter(text: str) -> tuple[Mapping[str, Any], str]:
    import yaml

    if not text.startswith("---"):
        raise HuntSkillError("skill file has no frontmatter")
    try:
        _, raw, body = text.split("---", 2)
    except ValueError as exc:
        raise HuntSkillError("skill frontmatter is not terminated") from exc
    try:
        meta = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise HuntSkillError("skill frontmatter is malformed YAML") from exc
    if not isinstance(meta, Mapping):
        raise HuntSkillError("skill frontmatter must be a mapping")
    return meta, body.lstrip("\n")


def skill_library_root() -> pathlib.Path | None:
    """Locate ``skills/web`` across source checkout, container, and installed runtime."""
    configured = os.environ.get("SHAKERSCAN_SKILLS_DIR")
    candidates = [pathlib.Path(configured)] if configured else []
    here = pathlib.Path(__file__).resolve()
    candidates += [
        here.parent.parent.parent / "skills" / "web",   # source checkout
        pathlib.Path("/workspace/skills/web"),          # api container mount
        pathlib.Path("/app/skills/web"),                # packaged runtime
        pathlib.Path.home() / ".shakerscan" / "skills" / "web",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def load_skill_library(root: pathlib.Path | None = None) -> HuntSkillLibrary:
    """Build the library while quarantining malformed files and reporting mount health."""
    location = root or skill_library_root()
    if location is None or not location.is_dir():
        return HuntSkillLibrary(
            (), catalog_status="unavailable",
            catalog_root=str(location) if location is not None else None,
            catalog_issues=({
                "path": str(location) if location is not None else "",
                "error": "skill directory is not mounted",
            },),
        )
    issues: list[dict[str, str]] = []
    by_id: dict[str, HuntSkillSpec] = {}
    try:
        paths = sorted(location.glob("*.md"))
    except OSError as exc:
        return HuntSkillLibrary(
            (), catalog_status="unavailable", catalog_root=str(location),
            catalog_issues=({"path": str(location), "error": type(exc).__name__},),
        )
    for path in paths:
        # Prose that documents the library rather than declaring a skill. Everything else
        # must carry frontmatter: a malformed skill fails loudly instead of disappearing.
        if path.name in LIBRARY_DOCUMENT_FILES:
            continue
        try:
            meta, body = _frontmatter(path.read_text(encoding="utf-8"))
            spec = build_skill_spec(meta, path=str(path), body=body)
            if spec.skill_id in by_id:
                raise HuntSkillError(f"duplicate skill: {spec.skill_id}")
            by_id[spec.skill_id] = spec
        except (HuntSkillError, OSError, UnicodeError) as exc:
            issues.append({"path": str(path), "error": str(exc) or type(exc).__name__})

    # Quarantine bindable declarations whose prerequisite disappeared with a malformed
    # file. Repeat because removing one prerequisite can invalidate another dependent.
    while True:
        invalid: list[tuple[str, str]] = []
        for skill_id, spec in by_id.items():
            if not spec.bindable:
                continue
            for required in spec.requires_skills:
                prerequisite = by_id.get(required)
                if prerequisite is None or not prerequisite.bindable:
                    invalid.append((skill_id, f"requires unavailable skill {required}"))
                    break
        if not invalid:
            break
        for skill_id, error in invalid:
            spec = by_id.pop(skill_id)
            issues.append({"path": spec.path, "error": error})

    status = "degraded" if issues else "ready"
    if not by_id and not issues:
        status = "empty"
    return HuntSkillLibrary(
        by_id.values(), catalog_status=status, catalog_root=str(location),
        catalog_issues=issues,
    )


def read_skill_body(spec: HuntSkillSpec) -> str:
    """Read one skill's methodology text."""
    _, body = _frontmatter(pathlib.Path(spec.path).read_text(encoding="utf-8"))
    return body


@dataclass(frozen=True)
class BoundSkills:
    """What binding a skill selection did to an otherwise already-decided run."""

    specs: tuple[HuntSkillSpec, ...]
    allowed_capabilities: tuple[str, ...]
    budget: Any
    context_section: Mapping[str, Any]


def bind_skills_to_hunt(
    skill_ids: Iterable[str],
    *,
    target_kind: str,
    allowed_capabilities: tuple[str, ...],
    budget: Any,
    library: HuntSkillLibrary | None = None,
    goal: str = "",
) -> BoundSkills:
    """Resolve methodology against an already-decided authority envelope.

    Binding is descriptive and auditable. It verifies that every required capability is already
    allowed, but preserves the Hunt capability manifest and budget exactly. Methodology must not
    become a second authority system or turn a later adaptive choice into a privilege change.
    """
    resolved_library = library or skill_library()
    specs = resolved_library.resolve_for_hunt(
        skill_ids, target_kind=target_kind,
    )
    if not specs:
        return BoundSkills(
            (), allowed_capabilities, budget,
            skill_context_section(
                (), requested=skill_ids, library=resolved_library,
                target_kind=target_kind, allowed_capabilities=allowed_capabilities,
                goal=goal,
            ),
        )

    # Every capability a skill lists as required must survive the policy filter. Checking
    # only that *something* survived let a session-testing skill bind to a passive,
    # credential-free hunt with two of its five requirements, so the planner would follow a
    # methodology it could not carry out and report the gap as a result.
    available = set(allowed_capabilities)
    for spec in specs:
        withheld = [name for name in spec.capabilities if name not in available]
        if withheld:
            raise HuntSkillError(
                f"skill {spec.skill_id} requires {', '.join(withheld)}, which this Hunt "
                "policy withholds; grant the matching authority or choose another skill"
            )
    return BoundSkills(
        specs, allowed_capabilities, budget, skill_context_section(
            specs, requested=skill_ids, library=resolved_library,
            target_kind=target_kind, allowed_capabilities=allowed_capabilities,
            goal=goal,
        ),
    )


async def record_initial_skill_bindings(
    conn: Any,
    *,
    hunt_run_id: Any,
    specs: Iterable[HuntSkillSpec],
    requested_skill_ids: Iterable[str],
) -> None:
    """Persist initial methodology selection without adding logic to the API root."""
    requested = {str(item) for item in requested_skill_ids}
    for spec in specs:
        await conn.execute(
            """INSERT INTO hunt_skill_events (
                   hunt_run_id, skill_id, event_type, skill_version,
                   body_sha256, reason, evidence_refs
               ) VALUES ($1,$2,'bound',$3,$4,$5,'[]'::jsonb)""",
            hunt_run_id,
            spec.skill_id,
            spec.version,
            spec.body_sha256,
            (
                "Explicitly selected at Hunt start"
                if spec.skill_id in requested
                else "Required by selected methodology"
            ),
        )


def skill_context_section(
    specs: Iterable[HuntSkillSpec], *, requested: Iterable[str],
    library: HuntSkillLibrary | None = None,
    target_kind: str = "web",
    allowed_capabilities: Iterable[str] | None = None,
    goal: str = "",
) -> dict[str, Any]:
    """The planner-facing skill block written into a run's context pack."""
    resolved_library = library or skill_library()
    resolved_specs = tuple(specs)
    chosen = {str(item) for item in requested}
    available = resolved_library.available_for_hunt(
        target_kind=target_kind, allowed_capabilities=allowed_capabilities,
    )
    suggested = [
        {
            **item,
            "methodology_url": (
                f"/hunts/{{hunt_id}}/skills/{item['skill_id']}/read"
            ),
        }
        for item in resolved_library.suggest(
            goal=goal, target_kind=target_kind,
            allowed_capabilities=allowed_capabilities,
            exclude=(spec.skill_id for spec in resolved_specs),
        )
    ]
    return {
        "schema_version": SKILL_LIBRARY_SCHEMA,
        "catalog": {
            "url": "/hunt/skills",
            "suggestions_url": "/hunts/{hunt_id}/skills/suggestions",
            "status": resolved_library.catalog_status,
            "loaded_count": len(resolved_library),
            "bindable_for_policy_count": len(available),
        },
        "selection": {
            "requested_skill_ids": sorted(chosen),
            "selection_optional": True,
            "binding_is_explicit": True,
            "auto_bound": False,
            "maximum": MAX_SKILLS_PER_HUNT,
            "instruction": (
                "Do not read the whole catalog. Fetch one suggested methodology only when "
                "its evidence trigger is relevant, then bind it explicitly if used."
            ),
        },
        "suggested": suggested,
        "bound": [
            {
                "skill_id": spec.skill_id,
                "title": spec.title,
                "version": spec.version,
                "body_sha256": spec.body_sha256,
                "phase": spec.phase,
                # False marks a prerequisite the server added, so the planner can tell what
                # it chose from what it inherited.
                "requested": spec.skill_id in chosen,
                "methodology_url": f"/hunts/{{hunt_id}}/skills/{spec.skill_id}/read",
            }
            for spec in resolved_specs
        ],
    }


_LIBRARY: HuntSkillLibrary | None = None


def skill_library() -> HuntSkillLibrary:
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = load_skill_library()
    return _LIBRARY


__all__ = [
    "BINDABLE_SUPPORT",
    "MAX_CONTEXT_SKILL_SUGGESTIONS",
    "MAX_SKILLS_PER_HUNT",
    "SKILL_BUDGET_DIMENSIONS",
    "SKILL_LIBRARY_SCHEMA",
    "SUPPORT_LEVELS",
    "HuntSkillError",
    "HuntSkillLibrary",
    "HuntSkillSpec",
    "BoundSkills",
    "bind_skills_to_hunt",
    "build_skill_spec",
    "load_skill_library",
    "skill_context_section",
    "record_initial_skill_bindings",
    "read_skill_body",
    "skill_library",
    "skill_library_root",
]
