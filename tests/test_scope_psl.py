"""The bundled Public Suffix List helper (``api/scope/psl.py``): unit tests, no network.

Runs against the real pinned snapshot; the integrity tests use a temporary copy.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from scope import psl  # noqa: E402
from scope.psl import (  # noqa: E402
    DomainNameError, PublicSuffixError, is_public_suffix, parse_domain, public_suffix,
    registrable_domain, require_registrable_or_below,
)


def test_bundled_list_matches_its_pin_and_keeps_its_licence_notice():
    raw = psl.PSL_PATH.read_bytes()
    snapshot = psl.snapshot()
    assert hashlib.sha256(raw).hexdigest() == snapshot["sha256"]
    assert snapshot["licence"] == "MPL-2.0" and len(snapshot["commit"]) == 40 and snapshot["date"]
    text = raw.decode("utf-8")
    assert text.startswith("// This Source Code Form is subject to the terms of the Mozilla Public")
    assert "===BEGIN PRIVATE DOMAINS===" in text
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    assert "Public Suffix List" in notices and snapshot["commit"] in notices


def test_a_modified_or_missing_snapshot_fails_closed(tmp_path, monkeypatch):
    copy = tmp_path / "public_suffix_list.dat"
    copy.write_bytes(psl.PSL_PATH.read_bytes().replace(b"\nco.uk\n", b"\n"))
    monkeypatch.setattr(psl, "PSL_PATH", copy)
    psl._rules.cache_clear()
    try:
        with pytest.raises(psl.PublicSuffixListError):
            is_public_suffix("co.uk")
        monkeypatch.setattr(psl, "PSL_PATH", tmp_path / "missing.dat")
        psl._rules.cache_clear()
        with pytest.raises(psl.PublicSuffixListError):
            registrable_domain("example.com")
        monkeypatch.setattr(psl, "PSL_PATH", ROOT / "api" / "scope" / "data" / "public_suffix_list.dat")
        monkeypatch.setattr(psl, "PSL_PIN_PATH", tmp_path / "missing.sha256")
        psl._rules.cache_clear()
        with pytest.raises(psl.PublicSuffixListError):
            public_suffix("example.com")
    finally:
        psl._rules.cache_clear()


@pytest.mark.parametrize(("host", "registrable"), [
    # From the PSL project's own test vectors (test_psl.txt), against this snapshot.
    ("com", None), ("example.com", "example.com"), ("b.example.com", "example.com"),
    ("uk.com", None), ("example.uk.com", "example.uk.com"),
    ("jp", None), ("test.jp", "test.jp"), ("ac.jp", None), ("kyoto.jp", None),
    ("test.kyoto.jp", "test.kyoto.jp"), ("ide.kyoto.jp", None),
    ("c.kobe.jp", None), ("b.c.kobe.jp", "b.c.kobe.jp"), ("city.kobe.jp", "city.kobe.jp"),
    ("www.city.kobe.jp", "city.kobe.jp"),
    ("ck", None), ("test.ck", None), ("b.test.ck", "b.test.ck"), ("www.ck", "www.ck"),
    ("www.www.ck", "www.ck"),
    ("xn--55qx5d.cn", None), ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("食狮.公司.cn", "xn--85x722f.xn--55qx5d.cn"),
    # Private section.
    ("github.io", None), ("user.github.io", "user.github.io"), ("herokuapp.com", None),
    ("app.herokuapp.com", "app.herokuapp.com"), ("s3.amazonaws.com", None),
    # Normalization.
    ("EXAMPLE.COM.", "example.com"), ("a.b.example.co.uk", "example.co.uk"),
    ("bücher.de", "xn--bcher-kva.de"),
    # Unlisted TLD: the default rule "*".
    ("lab", None), ("box.lab", "box.lab"), ("localhost", None),
    ("192.0.2.1", None), ("2001:db8::1", None), ("", None),
])
def test_registrable_domain_follows_the_psl_algorithm(host, registrable):
    assert registrable_domain(host) == registrable


@pytest.mark.parametrize("host", ["com", "co.uk", "github.io", "herokuapp.com", "s3.amazonaws.com", "test.ck", "ck", "CO.UK."])
def test_public_suffixes_are_refused(host):
    assert is_public_suffix(host)
    with pytest.raises(PublicSuffixError, match="is a public suffix"):
        require_registrable_or_below(host)


@pytest.mark.parametrize(("host", "normalized"), [
    ("www.ck", "www.ck"), ("example.co.uk", "example.co.uk"), ("a.b.example.co.uk", "a.b.example.co.uk"),
    ("user.github.io", "user.github.io"), ("EXAMPLE.COM.", "example.com"), ("bücher.de", "xn--bcher-kva.de"),
])
def test_registrable_names_and_names_below_are_accepted(host, normalized):
    assert require_registrable_or_below(host) == normalized


def test_a_name_idna_2008_refuses_is_never_registrable():
    homoglyph = "ex‍ample.com"  # a zero-width joiner IDNA 2008 refuses in this position
    assert registrable_domain(homoglyph) is None
    assert is_public_suffix(homoglyph)
    with pytest.raises(PublicSuffixError):
        parse_domain(homoglyph)


@pytest.mark.parametrize("raw", [
    "", "   ", "https://x.com", "x.com/path", "1.2.3.4", "[2001:db8::1]", "2001:db8::1", "*.x.com",
    "x.com:443", "user@x.com", "co.uk", "com", "github.io", "a b.com", "-bad.example.com",
    "a" * 64 + ".example.com", ("a" * 63 + ".") * 3 + "a" * 60 + ".com", "x" * 2000,
])
def test_parse_domain_refuses_anything_but_a_bare_registrable_name(raw):
    with pytest.raises(DomainNameError if raw not in {"co.uk", "com", "github.io"} else PublicSuffixError):
        parse_domain(raw)


@pytest.mark.parametrize(("raw", "normalized"), [
    ("example.com", "example.com"), (" Example.COM. ", "example.com"), ("dev.example.co.uk", "dev.example.co.uk"),
    ("bücher.de", "xn--bcher-kva.de"), ("user.github.io", "user.github.io"),
])
def test_parse_domain_normalizes_accepted_names(raw, normalized):
    assert parse_domain(raw) == normalized


def test_every_image_that_runs_the_api_carries_the_scope_package_and_snapshot():
    # runtime/models, action_scope and the Hunt bounds import scope.psl at API start: the API
    # image copies packages one by one, so a missing line is a start-up ImportError.
    assert "COPY api/scope /app/scope" in (ROOT / "scanner" / "Dockerfile").read_text()
    api_image = (ROOT / "scanner" / "Dockerfile.api").read_text()
    assert "COPY --from=scanner-runtime /app/scope /app/scope" in api_image
    copied = {line.split()[-1].removeprefix("/app/") for line in api_image.splitlines()
              if line.startswith("COPY --from=scanner-runtime /app/")}
    packages = {path.name for path in (ROOT / "api").iterdir() if (path / "__init__.py").is_file()}
    assert packages - {"ai_gate_boundary"} <= copied | {"ai_gate"}, sorted(packages - copied)


# Names a label-counting first cut got wrong, with the answers of the reference implementation
# (publicsuffixlist, same snapshot): the parent of a "*." rule is itself a public suffix. A
# sample of the 281 differing names; scratch tooling compares all 43,322 generated names.
REFERENCE_WILDCARD_PARENTS = [
    ('airflow.ap-southeast-1.on.aws', 'airflow.ap-southeast-1.on.aws', None),
    ('airflow.eu-central-2.on.aws', 'airflow.eu-central-2.on.aws', None),
    ('aivencloud.com', 'aivencloud.com', None),
    ('ap-east-1.airflow.amazonaws.com', 'ap-east-1.airflow.amazonaws.com', None),
    ('ap-east-1.rds.amazonaws.com', 'ap-east-1.rds.amazonaws.com', None),
    ('cn-northwest-1.airflow.amazonaws.com.cn', 'cn-northwest-1.airflow.amazonaws.com.cn', None),
    ('compute.amazonaws.com.cn', 'compute.amazonaws.com.cn', None),
    ('developer.app', 'developer.app', None),
    ('inbrowser.link', 'inbrowser.link', None),
    ('nagoya.jp', 'nagoya.jp', None),
    ('pa.crm.dev', 'pa.crm.dev', None),
    ('paywhirl.com', 'paywhirl.com', None),
    ('r.appspot.com', 'r.appspot.com', None),
    ('rds.cn-north-1.amazonaws.com.cn', 'rds.cn-north-1.amazonaws.com.cn', None),
    ('s.brave.dev', 's.brave.dev', None),
    ('us-west-2.cs.amazonlightsail.com', 'us-west-2.cs.amazonlightsail.com', None),
    ('webpaas.ovh.net', 'webpaas.ovh.net', None),
    ('kawasaki.jp', 'kawasaki.jp', None),
    ('a.kawasaki.jp', 'a.kawasaki.jp', None),
    ('b.a.kawasaki.jp', 'a.kawasaki.jp', 'b.a.kawasaki.jp'),
    ('city.kawasaki.jp', 'kawasaki.jp', 'city.kawasaki.jp'),
]


@pytest.mark.parametrize(("host", "suffix", "registrable"), REFERENCE_WILDCARD_PARENTS)
def test_wildcard_rule_parents_are_public_suffixes_as_in_the_reference(host, suffix, registrable):
    assert public_suffix(host) == suffix
    assert registrable_domain(host) == registrable


@pytest.mark.parametrize("host", [
    "amazonaws.com", "compute.amazonaws.com", "0e.vc", "kawasaki.jp", "on.aws", "crm.dev",
    "co.uk", "github.io", "com",
])
def test_a_wildcard_or_root_spanning_public_suffixes_is_refused(host):
    assert psl.spans_public_suffix(host)
    refusal = psl.public_suffix_refusal(host, wildcard=True)
    assert refusal and ("is a public suffix" in refusal or "covers the public suffix" in refusal)
    with pytest.raises(PublicSuffixError):
        require_registrable_or_below(host, wildcard=True)
    with pytest.raises(PublicSuffixError):
        parse_domain(host)


def test_a_name_with_a_suffix_below_is_fine_as_an_exact_host_only():
    # amazonaws.com is Amazon's own host; *.amazonaws.com would cover s3.amazonaws.com tenants.
    assert registrable_domain("amazonaws.com") == "amazonaws.com"
    assert not is_public_suffix("amazonaws.com")
    assert psl.suffix_below("amazonaws.com")
    assert require_registrable_or_below("amazonaws.com") == "amazonaws.com"
    assert "covers the public suffix" in psl.public_suffix_refusal("amazonaws.com", wildcard=True)


@pytest.mark.parametrize("host", ["example.com", "example.co.uk", "user.github.io", "www.ck",
                                  "city.kawasaki.jp", "b.a.kawasaki.jp", "bucket.s3.amazonaws.com"])
def test_names_owned_by_one_registrant_do_not_span(host):
    assert not psl.spans_public_suffix(host)
    assert require_registrable_or_below(host, wildcard=True)


@pytest.mark.parametrize(("raw", "normalized"), [
    ("example.com。", "example.com"), ("EXAMPLE.COM．", "example.com"),
    ("example｡com", "example.com"), ("bücher.de。", "xn--bcher-kva.de"),
])
def test_ideographic_and_fullwidth_dots_normalize(raw, normalized):
    assert registrable_domain(raw) == normalized
    assert parse_domain(raw) == normalized


@pytest.mark.parametrize("host", ["a..example.com", ".example.com", "example.com..", "..", "127.1", "1.2.3.4.5"])
def test_empty_labels_and_numeric_tlds_never_widen_scope(host):
    assert registrable_domain(host) is None
    assert is_public_suffix(host) and psl.spans_public_suffix(host)
    with pytest.raises(PublicSuffixError):
        parse_domain(host)
