"""Pre-authorization bounds a person sets when a Hunt starts (``--allow``).

Grammar (one bound per string, at most ``MAX_BOUNDS``)::

    budget.raise:<N>x                    each dimension up to N times its start limit (1 < N <= 10)
    budget.raise:<dimension>=<max>       one dimension up to an absolute total
    credential.use:<target-id|host>,...  credentials whose home target is one of these
    target.authorize:<pattern>,...       host[:port] or *.domain[:port]; IDNA 2008/UTS #46 ASCII
    capability:<flag>                    active-testing | state-changing | oob | tcp-discovery
                                         | active-replay
    ssh.host_trust:first-contact         recorded; SSH requests are not raised in this release

The server parses bounds; nothing here is trusted from the agent. A host pattern must contain a
registrable domain, so ``*`` and ``*.com`` are refused. A bound never covers a hard limit:
requests are only ever raised for refusals on the allowable list, and every grant still passes
the same scope, kind and admission checks as before.

Hosts are spelled by the one canonicalizer every destination subject uses
(``host_names.canonical_host``: strict IDNA 2008 with UTS #46), so a bound names the host the HTTP
client connects to. Bounds stored before that (IDNA 2003, which turned ``straße.example`` into
``strasse.example``) carry no ``host_canonicalization`` marker; ``stored_bounds`` re-derives
them from the strings the person approved and withholds every host bound whose two encodings
differ, rather than silently reinterpreting approved scope (``LegacyHostBound``).
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
    from scanner_tools.host_names import (
        HOST_CANONICALIZATION, HostNameError, canonical_host, display_host, host_forms,
    )
except ModuleNotFoundError:  # package import (api.hunt.permission_bounds)
    from scanner.scanner_tools.host_names import (
        HOST_CANONICALIZATION, HostNameError, canonical_host, display_host, host_forms,
    )

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


def _host_or_none(host: Any) -> str | None:
    """A subject's host in canonical form; None (never a match) when strict processing refuses it."""
    try:
        return canonical_host(host)
    except HostNameError:
        return None


@dataclass(frozen=True)
class HostPattern:
    host: str  # IDNA 2008/UTS #46 ASCII, lower case, without "*."
    wildcard: bool
    port: int | None

    def covers(self, host: str, port: int | None) -> bool:
        host = _host_or_none(host)
        if host is None:
            return False
        if self.port is not None and port != self.port:
            return False
        if self.wildcard:
            return host.endswith("." + self.host)
        return host == self.host

    def text(self) -> str:
        return ("*." if self.wildcard else "") + self.host + (f":{self.port}" if self.port else "")


def _canonical(host: str) -> str:
    try:
        return canonical_host(host)
    except HostNameError as exc:
        raise BoundError(
            f"{exc}; spell the host as its canonical name (an IDN as its IDNA 2008/UTS #46 "
            "xn-- form, an address in dotted decimal)"
        ) from exc


def _legacy_idna2003(host: str) -> str:
    """How bounds stored before ``HOST_CANONICALIZATION`` spelled a host (Python's IDNA 2003
    codec). Used only to recognise those rows; never to decide coverage."""
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise BoundError(f"host {host!r} is not a valid IDNA name") from exc
    return ascii_host.rstrip(".")


def parse_host_pattern(raw: str, *, _encode: Any = _canonical) -> HostPattern:
    text = raw.strip()
    port: int | None = None
    if ":" in text and not text.startswith("["):
        text, _, port_text = text.rpartition(":")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise BoundError(f"target.authorize pattern {raw!r} has an invalid port")
        port = int(port_text)
    wildcard = text.startswith("*.")
    host = _encode(text[2:] if wildcard else text)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BoundError("target.authorize takes host names, not addresses")
    labels = host.split(".")
    if "*" in host or not all(_LABEL.fullmatch(label) for label in labels):
        raise BoundError(f"target.authorize pattern {raw!r} is not a host name or *.domain")
    # A registrable domain needs at least two labels under the wildcard: "*" and "*.com" refused.
    if len(labels) < 2:
        raise BoundError(f"target.authorize pattern {raw!r} must name a registrable domain")
    return HostPattern(host, wildcard, port)


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
            "host_canonicalization": HOST_CANONICALIZATION,
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
        if str(home_target_id).lower() in wanted:
            return True
        host = _host_or_none(home_host) if home_host else None
        return bool(host and host in wanted)

    def covers_target(self, *, host: str, port: int | None) -> bool:
        return any(pattern.covers(host, port) for pattern in self.target_patterns)

    def covers_capability(self, flag: str) -> bool:
        return flag in self.capability_flags


def parse_bounds(values: Iterable[Any], *, budget_fields: Iterable[str] | None = None) -> Bounds:
    """Parse ``--allow`` strings; raise ``BoundError`` naming the first bad one.

    ``budget_fields`` (the Hunt budget dimensions) is passed in by the start contract rather than
    imported, so this grammar stays below the start contract in the import graph.
    """
    return _parse_bounds(values, budget_fields=budget_fields, encode=_canonical)


def _parse_bounds(values: Iterable[Any], *, budget_fields: Iterable[str] | None, encode: Any) -> Bounds:
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
                    pattern = parse_host_pattern(part, _encode=encode)
                    if pattern.wildcard or pattern.port:
                        raise BoundError("credential.use names target ids or exact hosts")
                    credential_targets.append(pattern.host)
        elif kind == KIND_TARGET_AUTHORIZE:
            patterns.extend(parse_host_pattern(part, _encode=encode) for part in value.split(",") if part.strip())
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
    """Rebuild stored bounds (``Bounds.public()``) written under ``HOST_CANONICALIZATION``.

    A row without the marker is a legacy (IDNA 2003) row: use ``stored_bounds`` with the strings
    the person approved. Here its host bounds are withheld (fail closed).
    """
    return stored_bounds(value).bounds


def _host_parts(values: Iterable[Any]) -> list[tuple[str, str, str, str, str]]:
    """(kind, bound text, host spelling, ``*.`` prefix, ``:port`` suffix) for every host the
    ``--allow`` strings name. The prefix and suffix are spelled as ``HostPattern.text()`` does."""
    parts: list[tuple[str, str, str, str, str]] = []
    for item in values:
        kind, _sep, value = str(item or "").strip().partition(":")
        if kind not in {KIND_TARGET_AUTHORIZE, KIND_CREDENTIAL_USE}:
            continue
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if kind == KIND_CREDENTIAL_USE:
                try:
                    uuid.UUID(part)
                    continue
                except ValueError:
                    pass
            text, suffix = part, ""
            if ":" in text and not text.startswith("["):
                text, _, port_text = text.rpartition(":")
                suffix = f":{int(port_text)}" if port_text.isdigit() and int(port_text) else ""
            prefix = "*." if text.startswith("*.") else ""
            parts.append((kind, f"{kind}:{part}", text[len(prefix):], prefix, suffix))
    return parts


def _display_pattern(text: str | None) -> str:
    """``*.xn--strae-oqa.example:443 (Unicode: *.straße.example:443)``: a pattern's canonical ASCII
    form with its Unicode form beside it."""
    text = str(text or "")
    prefix = "*." if text.startswith("*.") else ""
    host, suffix = text[len(prefix):], ""
    if ":" in host:
        host, _, port = host.rpartition(":")
        suffix = f":{port}"
    shown = host_forms(host)
    if shown["unicode"] == shown["ascii"]:
        return text
    return f"{prefix}{shown['ascii']}{suffix} (Unicode: {prefix}{shown['unicode']}{suffix})"


@dataclass(frozen=True)
class LegacyHostBound:
    """A host bound stored under IDNA 2003 that no longer matches anything until re-approved."""
    bound: str
    stored_as: str | None
    canonical: str | None
    reason: str

    def finding(self) -> str:
        """What changed, in one sentence."""
        if self.reason == "encoding_changed":
            return (f"The bound {self.bound!r} was stored as {self.stored_as!r} (IDNA 2003), but the host "
                    f"the client connects to is {_display_pattern(self.canonical)} (IDNA 2008/UTS #46).")
        if self.reason == "host_invalid":
            return (f"The bound {self.bound!r} was stored as {self.stored_as!r} (IDNA 2003), but the host "
                    "is not a valid IDNA 2008/UTS #46 name.")
        return (f"The bound {self.bound!r} was stored before hosts were spelled with IDNA 2008/UTS #46, "
                "and the string that was approved could not be confirmed.")

    def public(self) -> dict[str, Any]:
        if self.reason == "host_invalid":
            action = ("It no longer covers any request. Start the Hunt again with a bound that spells "
                      "the host you mean; your other bounds and grants are unchanged.")
        else:
            action = ("It no longer covers any request. Approve the re-approval request this Hunt "
                      "raises (shakerscan approve) to cover the host shown; your other bounds and "
                      "grants are unchanged.")
        message = f"{self.finding()} {action}"
        return {"bound": self.bound, "stored_as": self.stored_as, "canonical": self.canonical,
                "reason": self.reason, "reapproval_required": True, "message": message}


@dataclass(frozen=True)
class StoredBounds:
    bounds: Bounds
    legacy: tuple[LegacyHostBound, ...] = ()


def _without_marker(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in dict(value).items() if key != "host_canonicalization"}


def _rebuilt(value: Mapping[str, Any], *, target_patterns: Iterable[str],
             credential_targets: Iterable[str]) -> Bounds:
    return Bounds(
        budget_multiplier=value.get("budget_multiplier"),
        budget_totals={str(k): int(v) for k, v in dict(value.get("budget_totals") or {}).items()},
        credential_targets=tuple(str(item) for item in credential_targets),
        target_patterns=tuple(parse_host_pattern(item) for item in target_patterns),
        capability_flags=tuple(str(item) for item in value.get("capability_flags") or ()),
        ssh_first_contact=bool(value.get("ssh_host_trust_first_contact")),
    )


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _encoding_review(values: Iterable[Any]) -> tuple[set[tuple[str, str]], list[LegacyHostBound]]:
    """Split the hosts ``values`` name into those IDNA 2003 and IDNA 2008/UTS #46 spell alike
    (``(kind, host)``) and those they do not (withheld, ``LegacyHostBound``)."""
    stable: set[tuple[str, str]] = set()
    legacy: list[LegacyHostBound] = []
    for kind, bound, host, prefix, suffix in _host_parts(values):
        try:
            old: str | None = _legacy_idna2003(host)
        except BoundError:
            old = None
        try:
            new: str | None = canonical_host(host)
        except HostNameError:
            new = None
        if new is not None and new == old:
            # Keyed by the whole pattern ([*.]host[:port]) as stored: a stable bound keeps exactly
            # its own wildcard and port, never those of a changed bound with the same IDNA 2003 host.
            stable.add((kind, prefix + new + suffix))
        else:
            legacy.append(LegacyHostBound(
                bound=bound, stored_as=prefix + old + suffix if old else None,
                canonical=prefix + new + suffix if new else None,
                reason="encoding_changed" if new else "host_invalid",
            ))
    return stable, legacy


def legacy_host_changes(values: Iterable[Any]) -> list[LegacyHostBound]:
    """The hosts in ``--allow`` strings that IDNA 2003 spelled differently from IDNA 2008/UTS #46.

    An approval recorded (or a proposal digested) under IDNA 2003 that names one of these must be
    approved again: the scope it names is not the scope the person saw.
    """
    return _encoding_review(values)[1]


def stored_bounds(value: Mapping[str, Any], *, source_allow: Sequence[Any] | None = None) -> StoredBounds:
    """The bounds a stored row grants, failing closed on legacy host spellings.

    A row with the current ``host_canonicalization`` is rebuilt as stored. A legacy row (no
    marker) was parsed with IDNA 2003: its budget and capability bounds stand, and each host bound
    stands only when ``source_allow`` (the strings the person approved) reproduces the stored row
    and that host's IDNA 2003 and IDNA 2008 encodings are identical. Every other host bound is
    withheld and reported, so approved scope is never silently reinterpreted.
    """
    value = dict(value or {})
    if value.get("host_canonicalization") == HOST_CANONICALIZATION:
        return StoredBounds(_rebuilt(
            value, target_patterns=value.get("target_patterns") or (),
            credential_targets=value.get("credential_targets") or (),
        ))
    patterns = [str(item) for item in value.get("target_patterns") or ()]
    credentials = [str(item) for item in value.get("credential_targets") or ()]
    host_credentials = [item for item in credentials if not _is_uuid(item)]
    id_credentials = [item for item in credentials if _is_uuid(item)]
    if not patterns and not host_credentials:
        return StoredBounds(_rebuilt(value, target_patterns=(), credential_targets=id_credentials))
    try:
        reproduced = _parse_bounds(
            [str(item) for item in source_allow or ()], budget_fields=None, encode=_legacy_idna2003,
        ) if source_allow is not None else None
    except BoundError:
        reproduced = None
    if reproduced is None or _without_marker(reproduced.public()) != _without_marker(value):
        withheld = tuple(
            LegacyHostBound(bound=f"{kind}:{item}", stored_as=item, canonical=item, reason="source_unconfirmed")
            for kind, item in (*((KIND_TARGET_AUTHORIZE, item) for item in patterns),
                               *((KIND_CREDENTIAL_USE, item) for item in host_credentials))
        )
        return StoredBounds(_rebuilt(value, target_patterns=(), credential_targets=id_credentials), withheld)
    stable, legacy = _encoding_review(source_allow or ())
    kept_patterns = [item for item in patterns if (KIND_TARGET_AUTHORIZE, item) in stable]
    kept_hosts = [item for item in host_credentials if (KIND_CREDENTIAL_USE, item) in stable]
    kept_credentials = [item for item in credentials if item in id_credentials or item in kept_hosts]
    return StoredBounds(
        _rebuilt(value, target_patterns=kept_patterns, credential_targets=kept_credentials),
        tuple(legacy),
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


def bound_hosts(values: Iterable[Any]) -> list[dict[str, str]]:
    """Each host an ``--allow`` list names, with the canonical ASCII form it covers, for an
    approval screen: ``{"bound", "ascii", "display"}``. A host strict processing refuses is
    reported with an empty ``ascii``."""
    shown: list[dict[str, str]] = []
    for _kind, bound, host, _prefix, _suffix in _host_parts(values):
        try:
            ascii_host = canonical_host(host)
        except HostNameError:
            shown.append({"bound": bound, "ascii": "", "display": "not a valid IDNA 2008/UTS #46 host"})
            continue
        shown.append({"bound": bound, "ascii": ascii_host, "display": display_host(ascii_host)})
    return shown


__all__ = [
    "Bounds", "BoundError", "CAPABILITY_FLAGS", "HostPattern", "LegacyHostBound", "MAX_BOUNDS",
    "StoredBounds", "bound_hosts", "bounds_from_public", "legacy_host_changes", "merge", "parse_bounds",
    "parse_host_pattern", "stored_bounds",
]
