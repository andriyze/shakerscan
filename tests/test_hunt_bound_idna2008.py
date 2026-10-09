"""Permission bounds spell hosts as the client connects to them (R3, external release audit 2026-10-09).

``permission_bounds._idna`` used Python's ``idna`` codec (IDNA 2003) while destination subjects,
the scope guard and httpx use IDNA 2008 with UTS #46. A person's ``target.authorize:straße.example``
was stored as ``strasse.example``: the intended host (``xn--strae-oqa.example``) was not covered,
and a different ASCII host, ``strasse.example``, was. Every host bound now goes through the one
strict canonicalizer (``scanner_tools.host_names.canonical_host``), a host strict processing refuses
is refused rather than re-encoded with the old codec, and bounds stored under IDNA 2003 fail closed
where the two encodings differ.

Reserved example names only. Encoding is pure: no DNS resolution and no network traffic.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from hunt.permission_bounds import (
    BoundError,
    bound_hosts,
    bounds_from_public,
    legacy_host_changes,
    parse_bounds,
    stored_bounds,
)
from hunt.permission_grants import GrantRefused, _approvable_proposal
from hunt.permission_reasons import KIND_CREDENTIAL_USE, KIND_PREAUTHORIZATION, KIND_TARGET_AUTHORIZE
from hunt.permission_store import public_preauthorization, public_request, render
from scanner_tools.host_names import HOST_CANONICALIZATION, HostNameError, canonical_host

# host -> (IDNA 2008/UTS #46 ASCII, the IDNA 2003 ASCII v2.8.0 stored)
DEVIATIONS = {
    "straße.example": ("xn--strae-oqa.example", "strasse.example"),
    "faß.example": ("xn--fa-hia.example", "fass.example"),
    "xς.example": ("xn--x-ymb.example", "xn--x-0mb.example"),  # final sigma; IDNA 2003 folds to σ
}
JOINERS = ("a‍b.example", "a‌b.example")  # ZWJ / ZWNJ: IDNA 2003 deleted them


def _v280_digest(value):
    """``Bounds.digest()`` as v2.8.0 computed it (no host_canonicalization field)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _v280_row(**fields):
    """A ``Bounds.public()`` row exactly as v2.8.0 stored it."""
    row = {"budget_multiplier": None, "budget_totals": {}, "credential_targets": [],
           "target_patterns": [], "capability_flags": [], "ssh_host_trust_first_contact": False}
    row.update(fields)
    return row


# --- the reproduction ------------------------------------------------------------------------

def test_the_audit_reproduction_is_fixed():
    bounds = parse_bounds(["target.authorize:straße.example"])
    assert bounds.public()["target_patterns"] == ["xn--strae-oqa.example"]
    runtime = canonical_host("straße.example")
    assert runtime == "xn--strae-oqa.example"
    assert bounds.covers_target(host=runtime, port=443), "the intended host is covered"
    assert not bounds.covers_target(host="strasse.example", port=443), "another ASCII host is not"


@pytest.mark.parametrize("host, forms", DEVIATIONS.items())
def test_every_idna_2003_2008_deviation_names_the_2008_host(host, forms):
    new, old = forms
    bounds = parse_bounds([f"target.authorize:{host}", f"credential.use:{host}"])
    assert [pattern.host for pattern in bounds.target_patterns] == [new]
    assert bounds.credential_targets == (new,)
    for spelling in (new, host, host.upper() if host.isascii() else host):
        assert bounds.covers_target(host=spelling, port=None)
    assert bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host=host)
    assert bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host=new)
    assert not bounds.covers_target(host=old, port=None)
    assert not bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host=old)


@pytest.mark.parametrize("host", JOINERS)
def test_joiners_are_refused_never_deleted(host):
    with pytest.raises(BoundError, match="IDNA 2008"):
        parse_bounds([f"target.authorize:{host}"])
    with pytest.raises(BoundError):
        parse_bounds([f"credential.use:{host}"])
    with pytest.raises(HostNameError):
        canonical_host(host)
    # The ASCII name IDNA 2003 produced is its own bound and never matches the joiner spelling.
    plain = parse_bounds(["target.authorize:ab.example"])
    assert not plain.covers_target(host=host, port=None)
    assert plain.covers_target(host="ab.example", port=None)


@pytest.mark.parametrize("bad", ["xn--zz.example", "a..example", "xn--strae-oqa-.example"])
def test_malformed_ascii_labels_are_refused(bad):
    with pytest.raises(BoundError):
        parse_bounds([f"target.authorize:{bad}"])


# --- wildcards, equivalence, distinct names ---------------------------------------------------

def test_wildcard_unicode_hosts():
    bounds = parse_bounds(["target.authorize:*.straße.example", "target.authorize:*.bücher.example:8443"])
    assert [pattern.text() for pattern in bounds.target_patterns] == [
        "*.xn--strae-oqa.example", "*.xn--bcher-kva.example:8443",
    ]
    assert bounds.covers_target(host="api.straße.example", port=443)
    assert bounds.covers_target(host="api.xn--strae-oqa.example", port=443)
    assert not bounds.covers_target(host="api.strasse.example", port=443)
    assert not bounds.covers_target(host="xn--strae-oqa.example", port=443), "a wildcard names subdomains"
    assert bounds.covers_target(host="shop.bücher.example", port=8443)
    assert not bounds.covers_target(host="shop.bücher.example", port=443)
    assert not bounds.covers_target(host="shop.bucher.example", port=8443)


@pytest.mark.parametrize("spelling", [
    "straße.example", "Straße.Example.", "xn--strae-oqa.example", "XN--STRAE-OQA.EXAMPLE",
    "ｓｔｒａßｅ.example",  # full-width letters, mapped by UTS #46
])
def test_unicode_and_punycode_spellings_are_one_bound(spelling):
    reference = parse_bounds(["target.authorize:xn--strae-oqa.example"])
    bounds = parse_bounds([f"target.authorize:{spelling}"])
    assert bounds.public() == reference.public()
    assert bounds.digest() == reference.digest()


@pytest.mark.parametrize("bound, other", [
    ("strasse.example", "xn--strae-oqa.example"),
    ("xn--strae-oqa.example", "strasse.example"),
    ("fass.example", "faß.example"),
    ("xn--x-0mb.example", "xς.example"),  # xσ.example is not xς.example
    ("ab.example", "a-b.example"),
])
def test_distinct_ascii_names_never_share_a_bound(bound, other):
    bounds = parse_bounds([f"target.authorize:{bound}", f"credential.use:{bound}"])
    assert canonical_host(bound) != canonical_host(other)
    assert not bounds.covers_target(host=other, port=None)
    assert not bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host=other)


# --- persisted bounds ------------------------------------------------------------------------

def test_new_rows_record_the_canonicalization_and_round_trip():
    bounds = parse_bounds(["target.authorize:straße.example", "budget.raise:2x"])
    value = bounds.public()
    assert value["host_canonicalization"] == HOST_CANONICALIZATION
    loaded = stored_bounds(json.loads(json.dumps(value)))
    assert loaded.legacy == ()
    assert loaded.bounds.public() == value
    assert bounds_from_public(value).covers_target(host="straße.example", port=None)


def test_a_legacy_bound_whose_encodings_differ_fails_closed():
    source = ["target.authorize:straße.example", "budget.raise:2x"]
    row = _v280_row(budget_multiplier=2.0, target_patterns=["strasse.example"])
    loaded = stored_bounds(row, source_allow=source)
    assert not loaded.bounds.covers_target(host="strasse.example", port=None), "not the old reading"
    assert not loaded.bounds.covers_target(host="xn--strae-oqa.example", port=None), "nor a silent new one"
    assert loaded.bounds.budget_multiplier == 2.0, "budget bounds are not host spellings and stand"
    (withheld,) = loaded.legacy
    shown = withheld.public()
    assert shown["reapproval_required"] is True and shown["reason"] == "encoding_changed"
    assert shown["stored_as"] == "strasse.example" and shown["canonical"] == "xn--strae-oqa.example"
    assert "xn--strae-oqa.example (Unicode: straße.example)" in shown["message"]
    assert "shakerscan approve" in shown["message"] and "other bounds and grants are unchanged" in shown["message"]
    # Without the source strings the row is not re-derived at all: host bounds withheld.
    assert not bounds_from_public(row).covers_target(host="strasse.example", port=None)


def test_a_legacy_credential_host_bound_fails_closed():
    home = str(uuid.uuid4())
    source = [f"credential.use:faß.example,{home}"]
    row = _v280_row(credential_targets=["fass.example", home])
    loaded = stored_bounds(row, source_allow=source)
    assert loaded.bounds.credential_targets == (home,), "the target id bound stands"
    assert not loaded.bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host="fass.example")
    assert not loaded.bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host="faß.example")
    assert loaded.bounds.covers_credential(home_target_id=home, home_host=None)
    assert [item.reason for item in loaded.legacy] == ["encoding_changed"]


def test_a_legacy_joiner_bound_fails_closed():
    row = _v280_row(target_patterns=["ab.example"])
    loaded = stored_bounds(row, source_allow=["target.authorize:a‍b.example"])
    assert loaded.bounds.target_patterns == ()
    (withheld,) = loaded.legacy
    assert withheld.reason == "host_invalid" and withheld.stored_as == "ab.example"


def test_identical_legacy_encodings_stay_valid():
    source = ["target.authorize:bücher.example:443", "target.authorize:*.api.example.com",
              "credential.use:login.example.com"]
    row = _v280_row(target_patterns=["xn--bcher-kva.example:443", "*.api.example.com"],
                    credential_targets=["login.example.com"])
    loaded = stored_bounds(row, source_allow=source)
    assert loaded.legacy == ()
    assert loaded.bounds.covers_target(host="bücher.example", port=443)
    assert loaded.bounds.covers_target(host="v1.api.example.com", port=443)
    assert loaded.bounds.covers_credential(home_target_id=str(uuid.uuid4()), home_host="login.example.com")


def test_an_explicit_ascii_bound_beside_a_changed_one_stands():
    """The person typed strasse.example too: that ASCII host was approved in its own right."""
    source = ["target.authorize:strasse.example,straße.example"]
    row = _v280_row(target_patterns=["strasse.example"])
    loaded = stored_bounds(row, source_allow=source)
    assert loaded.bounds.covers_target(host="strasse.example", port=None)
    assert not loaded.bounds.covers_target(host="xn--strae-oqa.example", port=None)
    assert [item.bound for item in loaded.legacy] == ["target.authorize:straße.example"]


@pytest.mark.parametrize("source, stored, kept, granted, refused", [
    # The changed bound covered strasse.example on every port; the stable one only on 8443.
    (["target.authorize:straße.example", "target.authorize:strasse.example:8443"],
     ["strasse.example", "strasse.example:8443"], ["strasse.example:8443"],
     [("strasse.example", 8443)], [("strasse.example", 443), ("strasse.example", None)]),
    # The changed wildcard covered every subdomain; the stable bound is the apex only.
    (["target.authorize:*.straße.example", "target.authorize:strasse.example"],
     ["*.strasse.example", "strasse.example"], ["strasse.example"],
     [("strasse.example", 443)], [("api.strasse.example", 443), ("api.xn--strae-oqa.example", 443)]),
    # The changed bound named one port on the apex; the stable wildcard never covers the apex.
    (["target.authorize:straße.example:443", "target.authorize:*.strasse.example"],
     ["strasse.example:443", "*.strasse.example"], ["*.strasse.example"],
     [("api.strasse.example", 443)], [("strasse.example", 443), ("xn--strae-oqa.example", 443)]),
])
def test_a_stable_bound_keeps_only_its_own_wildcard_and_port(source, stored, kept, granted, refused):
    """R3 review B1: re-derivation keyed stable hosts without their wildcard and port, so a
    withheld IDNA 2003 bound still granted through a stable one with the same host -- sometimes
    more than either. Each stored pattern now stands only as its exact stable self."""
    loaded = stored_bounds(_v280_row(target_patterns=stored), source_allow=source)
    assert [pattern.text() for pattern in loaded.bounds.target_patterns] == kept
    for host, port in granted:
        assert loaded.bounds.covers_target(host=host, port=port), (host, port)
    for host, port in refused:
        assert not loaded.bounds.covers_target(host=host, port=port), (host, port)
    (withheld,) = loaded.legacy
    assert withheld.reason == "encoding_changed" and "xn--strae-oqa.example" in withheld.canonical
    assert withheld.public()["stored_as"] in stored


@pytest.mark.parametrize("source", [None, [], ["target.authorize:other.example"]])
def test_a_legacy_row_its_source_does_not_reproduce_fails_closed(source):
    row = _v280_row(target_patterns=["api.example.com"], capability_flags=["oob"])
    loaded = stored_bounds(row, source_allow=source)
    assert loaded.bounds.target_patterns == ()
    assert loaded.bounds.capability_flags == ("oob",)
    assert [item.reason for item in loaded.legacy] == ["source_unconfirmed"]


def test_an_unconfirmed_stored_spelling_strict_parsing_refuses_is_reported_not_offered():
    """R3 review: an unconfirmed legacy bound is offered back in its stored IDNA 2003 spelling,
    which IDNA 2008 may refuse (xn--i-7iq.example). It is reported as host_invalid instead."""
    row = _v280_row(target_patterns=["xn--i-7iq.example", "api.example.com"], budget_multiplier=2.0)
    loaded = stored_bounds(row, source_allow=None)
    reasons = {item.bound: item.reason for item in loaded.legacy}
    assert reasons == {"target.authorize:xn--i-7iq.example": "host_invalid",
                       "target.authorize:api.example.com": "source_unconfirmed"}
    bad = next(item for item in loaded.legacy if item.reason == "host_invalid").public()
    assert "not a valid IDNA 2008/UTS #46 name" in bad["message"] and "Start the Hunt again" in bad["message"]
    assert loaded.bounds.budget_multiplier == 2.0 and loaded.bounds.target_patterns == ()


def test_a_current_row_with_a_host_that_no_longer_parses_fails_closed_without_raising():
    row = {**parse_bounds(["target.authorize:api.example.com", "budget.raise:2x"]).public(),
           "target_patterns": ["xn--i-7iq.example", "api.example.com"]}
    loaded = stored_bounds(row)
    assert loaded.bounds.target_patterns == () and loaded.bounds.budget_multiplier == 2.0
    assert {item.reason for item in loaded.legacy} == {"host_invalid", "source_unconfirmed"}


def test_the_preauthorization_listing_flags_legacy_rows():
    row = _v280_row(target_patterns=["strasse.example"])
    item = {"id": uuid.uuid4(), "bounds_json": row, "bounds_digest": _v280_digest(row),
            "created_by": "alice@example.test", "proof": "stepup", "created_at": None,
            "_stored": stored_bounds(row, source_allow=["target.authorize:straße.example"])}
    shown = public_preauthorization(item)
    assert shown["host_canonicalization"] == "idna2003-legacy"
    assert shown["reapproval_required"][0]["canonical"] == "xn--strae-oqa.example"
    current = parse_bounds(["target.authorize:straße.example"]).public()
    assert public_preauthorization({**item, "bounds_json": current, "_stored": stored_bounds(current)})[
        "reapproval_required"] == []


def test_a_legacy_proposal_naming_a_changed_host_must_be_proposed_again():
    allow = ["target.authorize:straße.example"]
    legacy_subject = {"allow": allow, "bounds_digest": _v280_digest(_v280_row(target_patterns=["strasse.example"]))}
    with pytest.raises(GrantRefused) as refused:
        _approvable_proposal(legacy_subject)
    assert refused.value.status_code == 409
    assert refused.value.detail["error"] == "preauthorization_reapproval_required"
    assert "xn--strae-oqa.example" in refused.value.detail["message"]
    assert legacy_host_changes(allow)[0].stored_as == "strasse.example"
    # A proposal raised now (its digest is of the IDNA 2008 parse) is granted as proposed.
    current = {"allow": allow, "bounds_digest": parse_bounds(allow).digest()}
    assert _approvable_proposal(current).covers_target(host="xn--strae-oqa.example", port=None)
    # A legacy proposal whose hosts encode alike is the same scope and stays grantable.
    ascii_allow = ["target.authorize:api.example.com"]
    old = {"allow": ascii_allow, "bounds_digest": _v280_digest(_v280_row(target_patterns=["api.example.com"]))}
    assert _approvable_proposal(old).covers_target(host="api.example.com", port=None)
    # A proposal strict processing refuses is never re-encoded with the old codec.
    with pytest.raises(GrantRefused):
        _approvable_proposal({"allow": ["target.authorize:a‍b.example"], "bounds_digest": "0" * 64})


# --- approval displays ------------------------------------------------------------------------

def _request_row(kind, subject):
    return {"id": uuid.uuid4(), "hunt_run_id": uuid.uuid4(), "kind": kind, "reason_code": "scope_other_host",
            "status": "pending", "subject_json": subject, "subject_digest": "0" * 64, "display_json": {},
            "action_id": None, "capability_name": None, "created_at": None, "expires_at": None,
            "decided_at": None, "decided_by": None, "decision_via": None, "decision_scope": None,
            "grant_id": None}


def test_the_destination_approval_shows_the_canonical_ascii_beside_the_unicode_form():
    subject = {"host": "xn--strae-oqa.example", "port": 443, "scheme": "https", "same_host": False,
               "origin": "https://xn--strae-oqa.example:443", "addresses": ["192.0.2.10"], "target_id": "t1"}
    shown = render(KIND_TARGET_AUTHORIZE, subject, {})
    assert shown["title"] == "Authorize xn--strae-oqa.example:443 for this Hunt"
    assert "straße" not in shown["title"], "a look-alike spelling never leads"
    assert ("Canonical ASCII host (matched and connected to): xn--strae-oqa.example "
            "(Unicode: straße.example)") in shown["explanation"]
    request = public_request(_request_row(KIND_TARGET_AUTHORIZE, subject))
    assert request["destination"] == {"ascii": "xn--strae-oqa.example", "unicode": "straße.example",
                                      "port": 443, "scheme": "https"}
    plain = render(KIND_TARGET_AUTHORIZE, {**subject, "host": "api.example.com"}, {})
    assert "Unicode" not in plain["explanation"]


def test_the_terminal_approval_prints_the_canonical_ascii_host():
    from hunt_approve import render_request

    subject = {"host": "xn--strae-oqa.example", "port": 443, "scheme": "https", "same_host": False,
               "origin": "https://xn--strae-oqa.example:443", "addresses": ["192.0.2.10"], "target_id": "t1"}
    text = render_request(public_request(_request_row(KIND_TARGET_AUTHORIZE, subject)))
    assert "Authorize xn--strae-oqa.example:443 for this Hunt" in text
    assert "xn--strae-oqa.example (Unicode: straße.example)" in text


def test_the_proposal_approval_names_the_host_each_bound_covers():
    allow = ["target.authorize:straße.example", "target.authorize:api.example.com", "budget.raise:2x"]
    shown = render(KIND_PREAUTHORIZATION, {"allow": allow}, {})
    assert ("target.authorize:straße.example covers xn--strae-oqa.example (Unicode: straße.example)"
            in shown["explanation"])
    assert "target.authorize:api.example.com covers api.example.com" in shown["explanation"]
    assert bound_hosts(allow)[0]["ascii"] == "xn--strae-oqa.example"
    request = public_request(_request_row(KIND_PREAUTHORIZATION, {"allow": allow}))
    assert [item["ascii"] for item in request["bound_hosts"]] == ["xn--strae-oqa.example", "api.example.com"]


def test_the_credential_approval_names_the_canonical_home_host():
    subject = {"profile_id": "p1", "profile_version": 1, "home_target_id": "t2",
               "home_host": "faß.example", "slot": "primary"}
    shown = render(KIND_CREDENTIAL_USE, subject, {"home_target_name": "Shop"})
    assert "target 'Shop' (xn--fa-hia.example (Unicode: faß.example))" in shown["explanation"]
    request = public_request(_request_row(KIND_CREDENTIAL_USE, subject))
    assert request["home_host"] == {"ascii": "xn--fa-hia.example", "unicode": "faß.example"}


# --- address spellings (one canonicalizer, also for target/scope comparison) ----------------

@pytest.mark.parametrize("spelling", ["010.000.000.001", "127.1", "2130706433", "0x7f.0.0.1",
                                      "０１０.0.0.1"])  # full-width 010.0.0.1
def test_non_canonical_ipv4_spellings_are_refused(spelling):
    """Many resolvers read 010.000.000.001 as octal (8.0.0.1); PostgreSQL inet reads it as
    10.0.0.1. Text that names two addresses is refused, never compared."""
    with pytest.raises(HostNameError, match="canonical IPv4"):
        canonical_host(spelling)
    with pytest.raises(BoundError):
        parse_bounds([f"target.authorize:{spelling}"])


@pytest.mark.parametrize("spelling, canonical", [
    ("192.0.2.1", "192.0.2.1"), ("[2001:DB8::0001]", "2001:db8::1"), ("2001:db8:0:0::1", "2001:db8::1"),
    ("１９２.0.2.1", "192.0.2.1"),
])
def test_ip_literals_have_one_canonical_spelling(spelling, canonical):
    assert canonical_host(spelling) == canonical


def test_target_authorization_compares_hosts_with_the_one_canonicalizer():
    from target_authorization import _host_key

    assert _host_key("[2001:DB8::0001]") == _host_key("2001:db8::1") == "2001:db8::1"
    assert _host_key("Straße.Example.") == _host_key("xn--strae-oqa.example")
    assert _host_key("strasse.example") != _host_key("straße.example")
    assert _host_key("010.000.000.001") == "", "refused: matches no scope host"


@pytest.mark.parametrize("spelling", [
    "a%41.example", "a@b.example", "a/b.example", "a\\b.example", "a b.example", "a*b.example",
    "*.example", "a|b.example", "a^b.example", "a<b.example", "a?b.example", "a#b.example",
    "fe80::1%eth0", "[fe80::1%25eth0]",
])
def test_hosts_a_browser_refuses_are_refused(spelling):
    """R3 review: the ASCII path passed WHATWG forbidden host code points and IPv6 zone ids, so
    the one canonicalizer could name a host no browser or HTTP client would."""
    with pytest.raises(HostNameError):
        canonical_host(spelling)


def test_a_bound_wildcard_is_only_a_leading_label():
    assert parse_bounds(["target.authorize:*.api.example.com"]).target_patterns[0].wildcard
    for bad in ("target.authorize:api.*.example.com", "target.authorize:a*.example.com",
                "target.authorize:a@b.example.com", "credential.use:a%2eb.example.com"):
        with pytest.raises(BoundError):
            parse_bounds([bad])


def test_underscores_and_plain_hosts_stay_valid():
    assert canonical_host("_dmarc.Example.COM.") == "_dmarc.example.com"
    assert canonical_host("under_score.example") == "under_score.example"


@pytest.mark.parametrize("url, code, words", [
    ("https://010.000.000.001/", "malformed_url", "canonical IPv4"),
    ("https://2852039166/", "malformed_url", "canonical IPv4"),
    ("https://a‍b.example/", "unicode_or_punycode_confusion", "IDNA 2008"),
])
def test_the_scope_refusal_names_the_real_reason(url, code, words):
    from action_scope import evaluate_scope, receipt_to_dict

    receipt = receipt_to_dict(evaluate_scope(url, environment="production"))
    assert receipt["verdict"] == "blocked" and code in receipt["blocked_by"]
    (check,) = [item for item in receipt["checks"] if item["name"] == code]
    assert check["status"] == "blocked" and words in check["message"]


@pytest.mark.parametrize("spelling", [" ~.example", " x.example", " a.example", "x.example　"])
def test_unicode_spaces_around_a_host_are_not_trimmed_away(spelling):
    """R3 review fuzz: str.strip() dropped Unicode spaces that UTS #46 refuses, so the
    canonicalizer accepted hosts the idna reference (and browsers) refuse."""
    with pytest.raises(HostNameError):
        canonical_host(spelling)
