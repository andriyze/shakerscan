"""Public Suffix List lookups against a pinned, bundled snapshot (offline, fail closed).

Every scope decision that accepts a domain wildcard or an apex uses this module: Hunt
``target.authorize`` and ``credential.use`` bounds, ``allowed_root_domains`` in scope receipts
and target bindings, ``POST /discovery`` and the CT monitor (and, in 2.9, apex scope). Such a
pattern must sit at or below a registrable domain (eTLD+1). Counting labels is not enough:
``*.co.uk``, ``*.github.io`` and ``*.herokuapp.com`` each cover every site under a shared
suffix. The list includes its PRIVATE section, so ``github.io`` and ``herokuapp.com`` are public
suffixes here.

The snapshot is ``data/public_suffix_list.dat`` (Mozilla Public License 2.0; the file is
unmodified and keeps its MPL notice; see THIRD_PARTY_NOTICES.md). Its SHA-256 is pinned in
``data/public_suffix_list.sha256`` with the upstream commit and date, and is checked when this
module is imported: a modified or missing file raises ``PublicSuffixListError``, so no scope
decision silently treats every name as registrable. Nothing is fetched at runtime;
``scripts/update_psl.py`` refreshes the snapshot and pin in a reviewed change.

API::

    public_suffix(host) -> str
    registrable_domain(host) -> str | None        # None when host is itself a public suffix
    is_public_suffix(host) -> bool                # the host itself is a suffix (co.uk, kawasaki.jp)
    suffix_below(host) -> str | None              # a suffix rule strictly below (amazonaws.com)
    spans_public_suffix(host) -> bool             # a root/wildcard here covers other registrants
    require_registrable_or_below(host, wildcard=, subtree=) -> str   # raises PublicSuffixError
    public_suffix_refusal(host, wildcard=, port=, subtree=) -> str | None
    parse_domain(raw) -> str                      # a bare domain input; raises DomainNameError

Use ``spans_public_suffix`` (or ``wildcard=True``/``subtree=True``) for anything that covers a
subtree: a
``*.`` pattern, a scope root, a discovery apex, a monitored CT root. Use ``is_public_suffix``
only for an exact host. Semantics match ``publicsuffixlist``/``publicsuffix2``: the parent of a
``*.`` rule (``kawasaki.jp`` for ``*.kawasaki.jp``) is itself a public suffix.

Hosts are lowercased and a trailing dot is stripped; a non-ASCII host is encoded with IDNA 2008
and the UTS #46 mapping (as ``action_scope._canonical_host``). Rules written as Unicode in the
list are converted to A-labels when it is loaded.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import ipaddress
from pathlib import Path
import re

import idna

DATA_DIR = Path(__file__).resolve().parent / "data"
PSL_PATH = DATA_DIR / "public_suffix_list.dat"
PSL_PIN_PATH = DATA_DIR / "public_suffix_list.sha256"
PSL_LICENSE = "MPL-2.0"
MAX_DOMAIN_LENGTH = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class PublicSuffixListError(RuntimeError):
    """The bundled list is missing or is not the pinned snapshot."""


class PublicSuffixError(ValueError):
    """A name that is a public suffix where a registrable domain (or a name below one) is needed."""


class DomainNameError(PublicSuffixError):
    """A domain input that is not a bare host name (scheme, path, port, wildcard, address...)."""


def _pin() -> dict[str, str]:
    try:
        lines = PSL_PIN_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PublicSuffixListError(f"Public Suffix List pin is missing: {PSL_PIN_PATH}") from exc
    pin: dict[str, str] = {}
    for line in lines:
        if line.startswith("#"):
            key, sep, value = line[1:].partition(":")
            if sep:
                pin[key.strip()] = value.strip()
        elif line.strip():
            parts = line.split()
            if len(parts) == 2 and parts[1] == PSL_PATH.name:
                pin["sha256"] = parts[0].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", "")):
        raise PublicSuffixListError(f"Public Suffix List pin {PSL_PIN_PATH} names no sha256")
    return pin


def _ascii_rule(text: str) -> str:
    text = text.lower()
    return text if text.isascii() else idna.encode(text, uts46=True).decode("ascii")


@dataclass(frozen=True)
class _RuleSet:
    exact: frozenset[str]      # normal rules, plus the parent of every "*." rule
    wildcard: frozenset[str]   # parents of "*." rules
    exception: frozenset[str]  # "!" rules
    below: dict[str, str]      # name -> one rule strictly below it (for refusal messages)


@lru_cache(maxsize=1)
def _rules() -> _RuleSet:
    pin = _pin()
    try:
        raw = PSL_PATH.read_bytes()
    except OSError as exc:
        raise PublicSuffixListError(f"Public Suffix List snapshot is missing: {PSL_PATH}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin["sha256"]:
        raise PublicSuffixListError(
            f"Public Suffix List snapshot {PSL_PATH} does not match its pin "
            f"(sha256 {digest[:16]}..., pinned {pin['sha256'][:16]}...)"
        )
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for line in raw.decode("utf-8").splitlines():
        rule = line.strip().split(None, 1)[0] if line.strip() else ""
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exception.add(_ascii_rule(rule[1:]))
        elif rule.startswith("*."):
            wildcard.add(_ascii_rule(rule[2:]))
        else:
            exact.add(_ascii_rule(rule))
    # As publicsuffixlist/publicsuffix2 do: the parent of "*.kawasaki.jp" is itself a suffix.
    exact |= wildcard
    below: dict[str, str] = {}
    for name in sorted(exact | exception, key=lambda item: (item.count("."), item)):
        shown = name if name in exception or name not in wildcard else "*." + name
        labels = name.split(".")
        for index in range(1, len(labels)):
            below.setdefault(".".join(labels[index:]), shown)
    return _RuleSet(frozenset(exact), frozenset(wildcard), frozenset(exception), below)


def snapshot() -> dict[str, str]:
    """Provenance of the bundled snapshot: source, commit, date, licence and sha256."""
    _rules()
    return {**_pin(), "licence": PSL_LICENSE}


_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})


def _clean(host: str) -> str:
    """Lower case, IDNA 2008/UTS #46 A-labels, one trailing dot (any dot spelling) removed.

    Raises ``PublicSuffixError`` for a name IDNA refuses or one with an empty label.
    """
    host = str(host or "").strip().translate(_DOTS).lower()
    if host.endswith("."):
        host = host[:-1]
    if host and not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii").lower()
        except (UnicodeError, idna.IDNAError) as exc:
            raise PublicSuffixError(f"{host!r} is not a valid IDNA 2008 host name") from exc
    if host and not _is_address(host) and "" in host.split("."):
        raise PublicSuffixError(f"{host!r} has an empty label")
    return host


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _numeric_tld(host: str) -> bool:
    return host.rsplit(".", 1)[-1].isdigit()


def public_suffix(host: str) -> str:
    """The public suffix of ``host`` under the PSL algorithm (default rule ``*``)."""
    labels = _clean(host).split(".")
    rules = _rules()
    # An exception rule always prevails: its suffix is the rule minus its leftmost label.
    for index in range(len(labels)):
        if ".".join(labels[index:]) in rules.exception:
            return ".".join(labels[index + 1:])
    for index in range(len(labels)):  # longest candidate first
        candidate = ".".join(labels[index:])
        if candidate in rules.exact or (
            index + 1 < len(labels) and ".".join(labels[index + 1:]) in rules.wildcard
        ):
            return candidate
    return labels[-1]


def is_public_suffix(host: str) -> bool:
    """True when ``host`` is itself a public suffix (``com``, ``co.uk``, ``github.io``,
    ``kawasaki.jp``, ``lab``).

    An IP address is not a domain and is never a public suffix. A name IDNA refuses, one with an
    empty label, or one under an all-numeric "TLD" (``127.1``) counts as one, so it can never
    widen scope.
    """
    try:
        host = _clean(host)
    except PublicSuffixError:
        return True
    if not host or _is_address(host):
        return False
    if _numeric_tld(host):
        return True
    return public_suffix(host) == host


def suffix_below(host: str) -> str | None:
    """A public-suffix rule strictly below ``host`` (``s3.amazonaws.com`` for ``amazonaws.com``),
    or None. A wildcard or root on such a name would cover other registrants' sites."""
    try:
        host = _clean(host)
    except PublicSuffixError:
        return None
    return _rules().below.get(host)


def spans_public_suffix(host: str) -> bool:
    """True when a wildcard or scope root on ``host`` would cover sites of other registrants:
    ``host`` is a public suffix, or a public-suffix rule lies below it (``amazonaws.com``,
    ``crm.dev``). An address is neither. The check every root and ``*.`` pattern uses."""
    try:
        cleaned = _clean(host)
    except PublicSuffixError:
        return True
    if cleaned and _is_address(cleaned):
        return False
    return is_public_suffix(cleaned) or suffix_below(cleaned) is not None


def registrable_domain(host: str) -> str | None:
    """eTLD+1 of ``host`` (``example.co.uk`` for ``api.example.co.uk``); None for a public
    suffix, an address, or an empty or invalid host."""
    try:
        host = _clean(host)
    except PublicSuffixError:
        return None
    if not host or _is_address(host) or _numeric_tld(host):
        return None
    suffix = public_suffix(host)
    if suffix == host:
        return None
    return f"{host[: -len(suffix) - 1].split('.')[-1]}.{suffix}"


def public_suffix_refusal(host: str, *, wildcard: bool = False, port: int | None = None,
                          subtree: bool | None = None) -> str | None:
    """The refusal for a pattern on ``host`` that would cover sites of other registrants, else None.

    Any pattern on a public suffix is refused (``co.uk``, ``*.co.uk``). A wildcard is also refused
    when a public-suffix rule lies below it (``*.amazonaws.com`` covers ``*.s3.amazonaws.com``).
    ``*.example.co.uk`` and ``example.co.uk`` are fine. ``subtree`` (default: ``wildcard``)
    applies the below-rule check to a bare name that covers its subtree (a root, a discovery
    domain) while the message shows the name as typed.
    """
    subtree = wildcard if subtree is None else subtree
    try:
        cleaned = _clean(host)
    except PublicSuffixError as exc:
        return str(exc)
    shown = ("*." if wildcard else "") + cleaned + (f":{port}" if port else "")
    if is_public_suffix(cleaned):
        candidate = "example." + cleaned
        example = (f", e.g. {'*.' if wildcard else ''}{candidate}"
                   if not spans_public_suffix(candidate) else "")
        return (f"{shown} is a public suffix; name a domain you control{example} "
                "(a pattern must name a registrable domain or a name below one)")
    below = suffix_below(cleaned) if subtree else None
    if below:
        return (f"{shown} covers the public suffix {below}, whose sites belong to other "
                f"registrants; name a domain you control below it")
    return None


def require_registrable_or_below(host: str, *, wildcard: bool = False, subtree: bool | None = None) -> str:
    """``host`` normalized, when a pattern on it covers one registrant only; else raise.

    ``wildcard`` (a ``*.`` pattern or a scope root) also refuses names with public-suffix rules
    below them.
    """
    refusal = public_suffix_refusal(host, wildcard=wildcard, subtree=subtree)
    if refusal:
        raise PublicSuffixError(refusal)
    return _clean(host)


def parse_domain(raw: str) -> str:
    """A bare domain a person typed (discovery; apex scope later), normalized, at or below eTLD+1
    and with no public suffix below it (discovery covers its whole subtree).

    Refuses a scheme, path, port, userinfo, wildcard, IP literal, an all-numeric TLD, an invalid
    label or a name over 253 characters, then a public suffix. Returns the IDNA ASCII name.
    """
    text = str(raw or "").strip()
    shown = repr(text[:80])
    if not text:
        raise DomainNameError("a domain is required, e.g. example.com")
    if len(text) > 4 * MAX_DOMAIN_LENGTH:
        raise DomainNameError(f"a domain is at most {MAX_DOMAIN_LENGTH} characters")
    if "://" in text or any(char in text for char in "/?#@\\"):
        raise DomainNameError(f"{shown}: give a bare domain such as example.com, not a URL")
    if "*" in text:
        raise DomainNameError(f"{shown}: give the domain without a wildcard, e.g. example.com")
    if _is_address(text) or text.startswith("["):
        raise DomainNameError(f"{shown} is an IP address; give a domain name")
    if ":" in text:
        raise DomainNameError(f"{shown}: give the domain without a port")
    if any(char.isspace() for char in text):
        raise DomainNameError(f"{shown} contains whitespace")
    try:
        host = _clean(text)
    except PublicSuffixError as exc:
        raise DomainNameError(f"{shown} is not a valid host name ({exc})") from exc
    if len(host) > MAX_DOMAIN_LENGTH:
        raise DomainNameError(f"a domain is at most {MAX_DOMAIN_LENGTH} characters")
    if not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise DomainNameError(
            f"{shown} is not a valid host name (labels of letters, digits and hyphens, at most 63 each)"
        )
    if _is_address(host) or _numeric_tld(host):
        raise DomainNameError(f"{shown} is an IP address or ends in a numeric label; give a domain name")
    return require_registrable_or_below(host, subtree=True)


_rules()  # verify the pinned snapshot at import: a mismatch fails closed, loudly

__all__ = [
    "DomainNameError", "MAX_DOMAIN_LENGTH", "PSL_LICENSE", "PSL_PATH", "PSL_PIN_PATH",
    "PublicSuffixError", "PublicSuffixListError", "is_public_suffix", "parse_domain",
    "public_suffix", "public_suffix_refusal", "registrable_domain", "require_registrable_or_below",
    "snapshot", "spans_public_suffix", "suffix_below",
]
