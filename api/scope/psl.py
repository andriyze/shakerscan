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
    is_public_suffix(host) -> bool
    require_registrable_or_below(host) -> str     # raises PublicSuffixError
    public_suffix_refusal(host, wildcard=, port=) -> str | None
    parse_domain(raw) -> str                      # a bare domain input; raises DomainNameError

Hosts are lowercased and a trailing dot is stripped; a non-ASCII host is encoded with IDNA 2008
and the UTS #46 mapping (as ``action_scope._canonical_host``). Rules written as Unicode in the
list are converted to A-labels when it is loaded.
"""
from __future__ import annotations

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


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(exact rules, parents of ``*.`` rules, ``!`` exception rules), all ASCII."""
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
    return frozenset(exact), frozenset(wildcard), frozenset(exception)


def snapshot() -> dict[str, str]:
    """Provenance of the bundled snapshot: source, commit, date, licence and sha256."""
    _rules()
    return {**_pin(), "licence": PSL_LICENSE}


def _clean(host: str) -> str:
    host = str(host or "").strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if host and not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except (UnicodeError, idna.IDNAError) as exc:
            raise PublicSuffixError(f"{host!r} is not a valid IDNA 2008 host name") from exc
    return host


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def public_suffix(host: str) -> str:
    """The public suffix of ``host`` under the PSL algorithm (default rule ``*``)."""
    labels = _clean(host).split(".")
    exact, wildcard, exception = _rules()
    # An exception rule always prevails: its suffix is the rule minus its leftmost label.
    for index in range(len(labels)):
        if ".".join(labels[index:]) in exception:
            return ".".join(labels[index + 1:])
    for index in range(len(labels)):  # longest candidate first
        candidate = ".".join(labels[index:])
        if candidate in exact or (index + 1 < len(labels) and ".".join(labels[index + 1:]) in wildcard):
            return candidate
    return labels[-1]


def is_public_suffix(host: str) -> bool:
    """True when ``host`` is itself a public suffix (``com``, ``co.uk``, ``github.io``, ``lab``).

    An IP address is not a domain and is never a public suffix. A name IDNA refuses counts as
    one, so it can never widen scope.
    """
    try:
        host = _clean(host)
    except PublicSuffixError:
        return True
    if not host or _is_address(host):
        return False
    return public_suffix(host) == host


def registrable_domain(host: str) -> str | None:
    """eTLD+1 of ``host`` (``example.co.uk`` for ``api.example.co.uk``); None for a public
    suffix, an address, or an empty or invalid host."""
    try:
        host = _clean(host)
    except PublicSuffixError:
        return None
    if not host or _is_address(host) or "" in host.split("."):
        return None
    suffix = public_suffix(host)
    if suffix == host:
        return None
    return f"{host[: -len(suffix) - 1].split('.')[-1]}.{suffix}"


def public_suffix_refusal(host: str, *, wildcard: bool = False, port: int | None = None) -> str | None:
    """The refusal for a pattern on ``host`` that would cover a whole public suffix, else None.

    ``*.example.co.uk`` and ``example.co.uk`` are fine; ``*.co.uk`` and ``co.uk`` are refused.
    """
    if not is_public_suffix(host):
        return None
    try:
        host = _clean(host)
    except PublicSuffixError as exc:
        return str(exc)
    shown = ("*." if wildcard else "") + host + (f":{port}" if port else "")
    example = ("*." if wildcard else "") + "example." + host
    return (f"{shown} is a public suffix; name a domain you control, e.g. {example} "
            "(a pattern must name a registrable domain or a name below one)")


def require_registrable_or_below(host: str, *, wildcard: bool = False) -> str:
    """``host`` normalized, when it is a registrable domain or a name below one; else raise."""
    refusal = public_suffix_refusal(host, wildcard=wildcard)
    if refusal:
        raise PublicSuffixError(refusal)
    return _clean(host)


def parse_domain(raw: str) -> str:
    """A bare domain a person typed (discovery; apex scope later), normalized, at or below eTLD+1.

    Refuses a scheme, path, port, userinfo, wildcard, IP literal, invalid label or a name over
    253 characters, then a public suffix. Returns the IDNA ASCII, lower-case name.
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
    host = _clean(text)
    if len(host) > MAX_DOMAIN_LENGTH:
        raise DomainNameError(f"a domain is at most {MAX_DOMAIN_LENGTH} characters")
    if not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise DomainNameError(
            f"{shown} is not a valid host name (labels of letters, digits and hyphens, at most 63 each)"
        )
    if _is_address(host):
        raise DomainNameError(f"{shown} is an IP address; give a domain name")
    return require_registrable_or_below(host)


_rules()  # verify the pinned snapshot at import: a mismatch fails closed, loudly

__all__ = [
    "DomainNameError", "MAX_DOMAIN_LENGTH", "PSL_LICENSE", "PSL_PATH", "PSL_PIN_PATH",
    "PublicSuffixError", "PublicSuffixListError", "is_public_suffix", "parse_domain",
    "public_suffix", "public_suffix_refusal", "registrable_domain", "require_registrable_or_below",
    "snapshot",
]
