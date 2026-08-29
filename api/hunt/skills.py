"""The Hunt skill library: methodology the planner reads, bound to real capabilities.

A skill is testing methodology plus a declaration of which capabilities it needs. It is not
a new execution path, a second registry, or an authority. Binding a skill to a hunt can only
*narrow* what that hunt may do -- the capability allowlist is intersected, never extended,
and budget ceilings only ever move down. ``api/hunt/contracts.py`` remains the sole authority
on what a run is allowed to call.

Skills are published with an honest support level. ShakerScan has no capability for several
adapters the upstream library assumes (out-of-band callbacks, concurrent batches, raw single
connections, file upload, log observation), so those skills are listed as ``partial`` and
cannot be bound. Discovering that mid-run, after the planner has committed to a procedure it
cannot execute, is the failure this replaces.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
import hashlib
import os
import pathlib
from types import MappingProxyType
from typing import Any, Iterable, Mapping

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.capability_registry import CAPABILITY_REGISTRY


SKILL_LIBRARY_SCHEMA = "hunt-skill/v1"
LIBRARY_DOCUMENT_FILES = frozenset({"README.md"})
SUPPORT_LEVELS = frozenset({"supported", "partial", "reference"})
# Only these may be bound to a run. The others are published for reading.
BINDABLE_SUPPORT = frozenset({"supported"})
MAX_SKILLS_PER_HUNT = 4
# Budget dimensions a skill may lower. Deliberately a subset of the hunt budget: a skill
# declares testing cost, not run topology.
SKILL_BUDGET_DIMENSIONS = frozenset({
    "max_http_requests",
    "max_duration_seconds",
    "max_state_changing_requests",
    "max_oob_interactions",
})


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

    def __init__(self, specs: Iterable[HuntSkillSpec]) -> None:
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

    def resolve_for_hunt(
        self, skill_ids: Iterable[str], *, target_kind: str,
    ) -> tuple[HuntSkillSpec, ...]:
        """Return the exact skills a hunt may bind, or explain why it may not."""
        requested = [str(item or "").strip() for item in skill_ids if str(item or "").strip()]
        if not requested:
            return ()
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
        """The union of what the bound skills need.

        A union across bound skills, then intersected by the caller with what the run's
        policy already permits. A skill can therefore only ever narrow a hunt.
        """
        names: list[str] = []
        for spec in specs:
            for name in (*spec.capabilities, *spec.optional_capabilities):
                if name not in names:
                    names.append(name)
        return tuple(sorted(names))

    @staticmethod
    def budget_ceilings(specs: Iterable[HuntSkillSpec]) -> dict[str, int]:
        """The most permissive ceiling any bound skill declares.

        Taking the maximum lets two skills run in one hunt without starving each other,
        while the run's own profile still caps the result -- the caller applies these only
        where they are lower than what the profile already allows.
        """
        ceilings: dict[str, int] = {}
        for spec in specs:
            for name, amount in spec.budget.items():
                ceilings[name] = max(ceilings.get(name, 0), int(amount))
        return ceilings


def _frontmatter(text: str) -> tuple[Mapping[str, Any], str]:
    import yaml

    if not text.startswith("---"):
        raise HuntSkillError("skill file has no frontmatter")
    _, raw, body = text.split("---", 2)
    meta = yaml.safe_load(raw)
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
    """Build the library from disk. A missing directory yields an empty library.

    An empty library is a supported state: the skill plane is additive, and a runtime that
    was installed without it must still start and hunt.
    """
    location = root or skill_library_root()
    if location is None:
        return HuntSkillLibrary(())
    specs = []
    for path in sorted(location.glob("*.md")):
        # Prose that documents the library rather than declaring a skill. Everything else
        # must carry frontmatter: a malformed skill fails loudly instead of disappearing.
        if path.name in LIBRARY_DOCUMENT_FILES:
            continue
        meta, body = _frontmatter(path.read_text(encoding="utf-8"))
        specs.append(build_skill_spec(meta, path=str(path), body=body))
    return HuntSkillLibrary(specs)


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
) -> BoundSkills:
    """Resolve the bound skills and apply them as a narrowing of an already-decided run.

    Returns the bound specs, the intersected capability allowlist, a budget whose dimensions
    are lowered only where a skill is stricter than the profile, and the planner-facing
    context section. Raises ``HuntSkillError`` when the selection cannot be honoured, so the
    caller can refuse the start rather than run something other than what was asked for.
    """
    specs = (library or skill_library()).resolve_for_hunt(
        skill_ids, target_kind=target_kind,
    )
    if not specs:
        return BoundSkills((), allowed_capabilities, budget, {})

    wanted = set(HuntSkillLibrary.capability_allowlist(specs))
    narrowed = tuple(name for name in allowed_capabilities if name in wanted)
    if not narrowed:
        raise HuntSkillError(
            "the selected skills need capabilities this Hunt policy withholds; grant the "
            "matching authority or choose another skill"
        )
    for name, ceiling in HuntSkillLibrary.budget_ceilings(specs).items():
        current = getattr(budget, name, None)
        if isinstance(current, int) and 0 < ceiling < current:
            budget = dataclasses.replace(budget, **{name: ceiling})
    return BoundSkills(
        specs, narrowed, budget, skill_context_section(specs, requested=skill_ids),
    )


def skill_context_section(
    specs: Iterable[HuntSkillSpec], *, requested: Iterable[str],
) -> dict[str, Any]:
    """The planner-facing skill block written into a run's context pack."""
    chosen = {str(item) for item in requested}
    return {
        "schema_version": SKILL_LIBRARY_SCHEMA,
        "catalog": "/hunt/skills",
        "bound": [
            {
                "skill_id": spec.skill_id,
                "title": spec.title,
                "phase": spec.phase,
                "techniques": list(spec.techniques),
                "preconditions": list(spec.preconditions),
                "promotion_gate": spec.promotion_gate,
                "capabilities": list(spec.capabilities),
                "deferred_techniques": [dict(item) for item in spec.deferred_techniques],
                # False marks a prerequisite the server added, so the planner can tell what
                # it chose from what it inherited.
                "requested": spec.skill_id in chosen,
                "methodology_url": f"/hunt/skills/{spec.skill_id}",
            }
            for spec in specs
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
    "read_skill_body",
    "skill_library",
    "skill_library_root",
]
