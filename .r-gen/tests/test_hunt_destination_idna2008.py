"""The scope guard spells a non-ASCII host as the HTTP client connects to it (N1 of the #358 review).

``action_scope._canonical_host`` used Python's ``idna`` codec (IDNA 2003), which maps the
deviation characters: ``straße.example`` became ``strasse.example``. httpx encodes with IDNA 2008
(the ``idna`` package) and connects to ``xn--strae-oqa.example``, a different registrable name,
so a grant, a cooldown or a same-host check could name one host while the request reached
another. ``resolve_hunt_http_origin`` also compared the raw lowercased host, so a non-ASCII
spelling of the Hunt's own host was refused or recorded unencoded.
"""
from __future__ import annotations

import httpx
import pytest
from action_scope import _canonical_host
from capabilities.http import resolve_hunt_http_origin
from runtime.models import TargetBinding

DEVIATIONS = {
    "straße.example": "xn--strae-oqa.example",
    "faß.de": "xn--fa-hia.de",
    "Straße.Example.": "xn--strae-oqa.example",
}


@pytest.mark.parametrize("host, ascii_host", DEVIATIONS.items())
def test_the_canonical_host_is_the_one_httpx_connects_to(host, ascii_host):
    assert _canonical_host(host) == ascii_host
    assert httpx.URL(f"https://{host.lower().rstrip('.')}/").raw_host.decode() == ascii_host


@pytest.mark.parametrize("host, ascii_host", [
    ("ｅｖｉｌ.example", "evil.example"),  # full-width, mapped by UTS #46
    ("e\u200bvil.example", "evil.example"),  # zero-width space, mapped away
    ("ＥＶＩＬ．example", "evil.example"),  # full-width capitals and full stop
    ("bücher.example", "xn--bcher-kva.example"),
    ("EVIL.example.", "evil.example"),
    ("xn--strae-oqa.example", "xn--strae-oqa.example"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_other_spellings_keep_their_mapping(host, ascii_host):
    assert _canonical_host(host) == ascii_host


def _target(host):
    return TargetBinding(
        target_id="t1", target_kind="web", canonical_host=host,
        allowed_origins=(f"https://{host}",), allowed_addresses=("93.184.216.34",),
    )


def test_a_non_ascii_spelling_of_the_hunts_own_host_is_that_host():
    bound = resolve_hunt_http_origin(
        _target("xn--strae-oqa.example"), "https://straße.example:8443", {"active_testing": True},
    )
    assert bound.allowed_origins[-1] == "https://xn--strae-oqa.example:8443"
    same = resolve_hunt_http_origin(_target("xn--strae-oqa.example"), "https://Straße.example", {})
    assert same.allowed_origins == ("https://xn--strae-oqa.example",)


def test_the_idna2003_spelling_is_another_host():
    """``strasse.example`` is a different name; the ß spelling never reaches it."""
    with pytest.raises(ValueError, match="exact target host"):
        resolve_hunt_http_origin(_target("strasse.example"), "https://straße.example", {"active_testing": True})
