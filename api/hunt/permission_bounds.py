"""Pre-authorization bounds a person sets when a Hunt starts (``--allow``).

Grammar (one bound per string, at most ``MAX_BOUNDS``)::

    budget.raise:<N>x                    each dimension up to N times its start limit (1 < N <= 10)
    budget.raise:<dimension>=<max>       one dimension up to an absolute total
    credential.use:<target-id|host>,...  credentials whose home target is one of these
    target.authorize:<pattern>,...       host[:port] or *.domain[:port], IDNA ASCII
    capability:<flag>                    active-testing | state-changing | oob | tcp-discovery
                                         | active-replay
    ssh.host_trust:first-contact         recorded; SSH requests are not raised in this release

The server parses bounds; nothing here is trusted from the agent. A host pattern must sit at or
below a registrable domain under the bundled Public Suffix List (``public_suffix``, including its
private section), so ``*``, ``*.com``, ``*.co.uk``, ``*.github.io`` and ``co.uk`` are refused while
``*.example.co.uk`` and ``*.user.github.io`` are accepted. A stored bound that names a public
suffix (accepted before this check) is kept as stored but covers nothing (``HostPattern.refused``,
``refused_bounds``). A bound never covers a hard limit: requests are only ever raised for
refusals on the allowable list, and every grant still passes the same scope, kind and admission
checks as before.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import re
from typing import Any
import uuid

try:
    from scope.psl import public_suffix_refusal
except ModuleNotFoundError:  # package import (api.hunt.permission_bounds)
    from ..scope.psl import public_suffix_refusal

from .permission_reasons import (
    KIND_BUDGET_RAISE,
    KIND_CAPABILITY_ENABLE,
    KIND_CREDENTIAL_USE,
    KIND_SSH_HOST_TRUST,
    KIND_TARGET_AUTHORIZE,
)

MAX_BOUNDS = 32
# JSON/JavaScript clients must represent a total exactly (as budget_amendments.MAX_BUDGET_VALUE).
MAX_BUDGET_VALUE = 2**53 - 1
MAX_BUDGET_MULTIPLIER = 10
CAPABILITY_FLAGS: Mapping[str, tuple[str, ...]] = {
    # flag -> the policy fields it turns on (state-changing implies active testing, as at start)
    "active-testing": ("active_testing",),
    "state-changing": ("active_testing", "allow_state_changing_http"),
    "oob": ("active_testing", "allow_oob_interactions"),
    "tcp-discovery": ("active_testing", "network_discovery"),
    "active-replay": ("active_testing", "allow_state_changing_http"),
}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DIMENSION = re.compile(r"^max_[a-z_]{2,40}$")


class BoundError(ValueError):
    """A bound outside the grammar; the message names the bound."""


class PublicSuffixBoundError(BoundError):
    """A host pattern that would cover a whole public suffix; carries the parsed pattern."""

    def __init__(self, message: str, pattern: "HostPattern") -> None:
        super().__init__(message)
        self.pattern = pattern


@dataclass(frozen=True)
class HostPattern:
    host: str  # IDNA ASCII, lower case, without "*."
    wildcard: bool
    port: int | None
    # Set only when a stored bound names a public suffix: it is kept as stored and covers nothing.
    refused: str | None = field(default=None, compare=False)

    def covers(self, host: str, port: int | None) -> bool:
        if self.refused:
            return False
        host = host.lower().rstrip(".")
        if self.port is not None and port != self.port:
            return False
        if self.wildcard:
            return host.endswith("." + self.host)
        return host == self.host

    def text(self) -> str:
        return ("*." if self.wildcard else "") + self.host + (f":{self.port}" if self.port else "")


def _idna(host: str) -> str:
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise BoundError(f"host {host!r} is not a valid IDNA name") from exc
    return ascii_host.rstrip(".")


def parse_host_pattern(raw: str) -> HostPattern:
    text = raw.strip()
    port: int | None = None
    if ":" in text and not text.startswith("["):
        text, _, port_text = text.rpartition(":")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise BoundError(f"target.authorize pattern {raw!r} has an invalid port")
        port = int(port_text)
    wildcard = text.startswith("*.")
    host = _idna(text[2:] if wildcard else text)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BoundError("target.authorize takes host names, not addresses")
    labels = host.split(".")
    if "*" in host or not all(_LABEL.fullmatch(label) for label in labels):
        raise BoundError(f"target.authorize pattern {raw!r} is not a host name or *.domain")
    # The host must be at or below a registrable domain (eTLD+1, Public Suffix List with its
    # private section): "*", "*.com", "*.co.uk", "*.github.io" and "co.uk" are refused.
    refusal = public_suffix_refusal(host, wildcard=wildcard, port=port)
    if refusal:
        raise PublicSuffixBoundError(refusal, HostPattern(host, wildcard, port, refused=refusal))
    return HostPattern(host, wildcard, port)


def _stored_host_pattern(raw: str) -> HostPattern:
    """A stored ``target.authorize`` pattern. One naming a public suffix (accepted before the
    Public Suffix List check) is not reinterpreted or dropped silently: it keeps its stored text
    and covers nothing, with the reason in ``refused``."""
    try:
        return parse_host_pattern(raw)
    except PublicSuffixBoundError as exc:
        return exc.pattern


def _stored_credential_target(raw: str) -> str | None:
    """A stored ``credential.use`` entry, or None when it names a public suffix as a host."""
    try:
        uuid.UUID(raw)
        return raw
    except ValueError:
        pass
    try:
        parse_host_pattern(raw)
    except PublicSuffixBoundError:
        return None
    except BoundError:
        return raw
    return raw


def refused_bounds(value: Mapping[str, Any]) -> list[dict[str, str]]:
    """The stored host bounds that name a public suffix and therefore cover nothing."""
    refused: list[dict[str, str]] = []
    for item in value.get("target_patterns") or ():
        pattern = _stored_host_pattern(str(item))
        if pattern.refused:
            refused.append({"bound": f"{KIND_TARGET_AUTHORIZE}:{item}", "message": (
                f"{pattern.refused}. This pre-authorization was stored before public suffixes were "
                "refused; it no longer covers any host. Start the Hunt with a bound you control."
            )})
    for item in value.get("credential_targets") or ():
        if _stored_credential_target(str(item)) is None:
            refused.append({"bound": f"{KIND_CREDENTIAL_USE}:{item}", "message": (
                f"{item} is a public suffix; this credential bound no longer covers any host."
            )})
    return refused


@dataclass(frozen=True)
class Bounds:
    budget_multiplier: float | None = None
    budget_totals: Mapping[str, int] = field(default_factory=dict)
    credential_targets: tuple[str, ...] = ()
    target_patterns: tuple[HostPattern, ...] = ()
    capability_flags: tuple[str, ...] = ()
    ssh_first_contact: bool = False

    def public(self) -> dict[str, Any]:
        return {
            "budget_multiplier": self.budget_multiplier,
            "budget_totals": dict(self.budget_totals or {}),
            "credential_targets": list(self.credential_targets),
            "target_patterns": [pattern.text() for pattern in self.target_patterns],
            "capability_flags": list(self.capability_flags),
            "ssh_host_trust_first_contact": self.ssh_first_contact,
        }

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.public(), sort_keys=True).encode()).hexdigest()

    @property
    def empty(self) -> bool:
        return self.public() == Bounds().public()

    # Coverage. Each answers for one request subject; hard limits never reach here.
    def covers_budget(self, *, dimension: str, start_limit: int, needed_total: int) -> int | None:
        """The total to grant when ``needed_total`` fits, else None."""
        ceilings = []
        if self.budget_multiplier:
            ceilings.append(int(start_limit * self.budget_multiplier))
        total = dict(self.budget_totals or {}).get(dimension)
        if total is not None:
            ceilings.append(int(total))
        ceiling = max(ceilings, default=0)
        return ceiling if ceiling >= needed_total and ceiling > 0 else None

    def covers_credential(self, *, home_target_id: str, home_host: str | None) -> bool:
        wanted = {item.lower() for item in self.credential_targets}
        return str(home_target_id).lower() in wanted or bool(home_host and home_host.lower() in wanted)

    def covers_target(self, *, host: str, port: int | None) -> bool:
        return any(pattern.covers(host, port) for pattern in self.target_patterns)

    def covers_capability(self, flag: str) -> bool:
        return flag in self.capability_flags


def parse_bounds(values: Iterable[Any], *, budget_fields: Iterable[str] | None = None) -> Bounds:
    """Parse ``--allow`` strings; raise ``BoundError`` naming the first bad one.

    ``budget_fields`` (the Hunt budget dimensions) is passed in by the start contract rather than
    imported, so this grammar stays below the start contract in the import graph.
    """
    budget_fields = frozenset(budget_fields) if budget_fields is not None else None
    items = [str(value or "").strip() for value in values]
    if len(items) > MAX_BOUNDS:
        raise BoundError(f"at most {MAX_BOUNDS} allow bounds")
    multiplier: float | None = None
    totals: dict[str, int] = {}
    credential_targets: list[str] = []
    patterns: list[HostPattern] = []
    flags: list[str] = []
    first_contact = False
    for item in items:
        kind, sep, value = item.partition(":")
        if not sep or not value.strip():
            raise BoundError(f"allow bound {item[:80]!r} must be <kind>:<value>")
        value = value.strip()
        if kind == KIND_BUDGET_RAISE:
            if value.endswith("x"):
                try:
                    factor = float(value[:-1])
                except ValueError as exc:
                    raise BoundError(f"budget.raise multiplier {value!r} is invalid") from exc
                if not 1 < factor <= MAX_BUDGET_MULTIPLIER:
                    raise BoundError(f"budget.raise multiplier must be above 1 and at most {MAX_BUDGET_MULTIPLIER}")
                multiplier = max(multiplier or 0, factor)
            else:
                name, eq, amount = value.partition("=")
                if not eq or not _DIMENSION.fullmatch(name) or (
                    budget_fields is not None and name not in budget_fields
                ):
                    raise BoundError(f"budget.raise bound {value!r} must be <N>x or <max_dimension>=<total>")
                if not amount.isdigit() or not 0 < int(amount) <= MAX_BUDGET_VALUE:
                    raise BoundError(f"budget.raise total for {name} is invalid")
                totals[name] = max(totals.get(name, 0), int(amount))
        elif kind == KIND_CREDENTIAL_USE:
            for part in value.split(","):
                part = part.strip()
                try:
                    credential_targets.append(str(uuid.UUID(part)))
                except ValueError:
                    pattern = parse_host_pattern(part)
                    if pattern.wildcard or pattern.port:
                        raise BoundError("credential.use names target ids or exact hosts")
                    credential_targets.append(pattern.host)
        elif kind == KIND_TARGET_AUTHORIZE:
            patterns.extend(parse_host_pattern(part) for part in value.split(",") if part.strip())
        elif kind == "capability" or kind == KIND_CAPABILITY_ENABLE:
            if value not in CAPABILITY_FLAGS:
                raise BoundError(
                    f"capability bound must be one of {', '.join(sorted(CAPABILITY_FLAGS))}"
                )
            flags.append(value)
        elif kind == KIND_SSH_HOST_TRUST:
            if value != "first-contact":
                raise BoundError("ssh.host_trust bound must be first-contact")
            first_contact = True
        else:
            raise BoundError(f"allow bound kind {kind[:40]!r} is not pre-authorizable")
    return Bounds(
        budget_multiplier=multiplier, budget_totals=totals,
        credential_targets=tuple(dict.fromkeys(credential_targets)),
        target_patterns=tuple(dict.fromkeys(patterns)),
        capability_flags=tuple(dict.fromkeys(flags)),
        ssh_first_contact=first_contact,
    )


def bounds_from_public(value: Mapping[str, Any]) -> Bounds:
    """Rebuild stored bounds (``Bounds.public()``)."""
    return Bounds(
        budget_multiplier=value.get("budget_multiplier"),
        budget_totals={str(k): int(v) for k, v in dict(value.get("budget_totals") or {}).items()},
        credential_targets=tuple(
            item for item in (str(raw) for raw in value.get("credential_targets") or ())
            if _stored_credential_target(item) is not None
        ),
        target_patterns=tuple(_stored_host_pattern(item) for item in value.get("target_patterns") or ()),
        capability_flags=tuple(str(item) for item in value.get("capability_flags") or ()),
        ssh_first_contact=bool(value.get("ssh_host_trust_first_contact")),
    )


def merge(bounds: Sequence[Bounds]) -> Bounds:
    return Bounds() if not bounds else Bounds(
        budget_multiplier=max((b.budget_multiplier or 0 for b in bounds), default=0) or None,
        budget_totals={
            key: max(int(dict(b.budget_totals or {}).get(key) or 0) for b in bounds)
            for key in {k for b in bounds for k in dict(b.budget_totals or {})}
        },
        credential_targets=tuple(dict.fromkeys(t for b in bounds for t in b.credential_targets)),
        target_patterns=tuple(dict.fromkeys(p for b in bounds for p in b.target_patterns)),
        capability_flags=tuple(dict.fromkeys(f for b in bounds for f in b.capability_flags)),
        ssh_first_contact=any(b.ssh_first_contact for b in bounds),
    )


__all__ = [
    "Bounds", "BoundError", "CAPABILITY_FLAGS", "HostPattern", "MAX_BOUNDS", "PublicSuffixBoundError",
    "bounds_from_public", "merge", "parse_bounds", "parse_host_pattern", "refused_bounds",
]
