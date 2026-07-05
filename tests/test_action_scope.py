import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from action_scope import evaluate_scope, receipt_to_dict  # noqa: E402


def blocked_by(url: str, **kwargs):
    return set(evaluate_scope(url, **kwargs).blocked_by)


def test_allows_exact_allowed_https_host():
    receipt = evaluate_scope(
        "https://app.example.com/path",
        allowed_hosts=["app.example.com"],
        environment="production",
    )

    assert receipt.verdict == "allowed"
    assert receipt.normalized_scope["host"] == "app.example.com"
    assert not receipt.blocked_by


def test_blocks_malformed_and_scheme_relative_urls():
    assert "malformed_url" in blocked_by("app.example.com/path", allowed_hosts=["app.example.com"])
    assert "scheme_relative_url" in blocked_by("//app.example.com/path", allowed_hosts=["app.example.com"])


def test_blocks_userinfo_trailing_dot_and_unicode_hosts():
    assert "userinfo" in blocked_by("https://user:pass@app.example.com/", allowed_hosts=["app.example.com"])
    assert "trailing_dot_host" in blocked_by("https://app.example.com./", allowed_hosts=["app.example.com"])
    assert "unicode_or_punycode_confusion" in blocked_by("https://xn--e1awd7f.com/", allowed_root_domains=["xn--e1awd7f.com"])


def test_blocks_private_and_loopback_outside_lab():
    assert "loopback_or_private_range" in blocked_by("http://127.0.0.1:8080/", allowed_hosts=["127.0.0.1"])
    assert "loopback_or_private_range" in blocked_by("http://10.0.0.5/", allowed_hosts=["10.0.0.5"])
    lab = evaluate_scope("http://127.0.0.1:8080/", allowed_hosts=["127.0.0.1"], environment="lab")
    assert lab.verdict == "allowed"


def test_blocks_broad_cidr_and_out_of_scope_hosts():
    assert "broad_cidr" in blocked_by("https://10.0.0.0/8")
    assert "host_out_of_allowed_scope" in blocked_by(
        "https://evil.example.net/",
        allowed_root_domains=["example.com"],
    )


def test_redirect_destinations_must_stay_in_scope():
    receipt = evaluate_scope(
        "https://app.example.com/login",
        allowed_root_domains=["example.com"],
        redirect_urls=["https://app.example.com/callback", "https://evil.example.net/callback"],
    )

    assert receipt.verdict == "blocked"
    assert "redirect_out_of_scope" in receipt.blocked_by
    assert receipt.redirect_destinations[1]["verdict"] == "blocked"


def test_no_allowed_scope_needs_approval_not_allowed():
    receipt = evaluate_scope("https://app.example.com/path")

    assert receipt.verdict == "needs_approval"
    assert "no_allowed_scope_supplied" in receipt.warnings


def test_receipt_dict_is_serializable_shape():
    payload = receipt_to_dict(evaluate_scope("https://app.example.com/path", allowed_hosts=["app.example.com"]))

    assert payload["receipt_id"]
    assert payload["verdict"] == "allowed"
    assert payload["checks"]
    assert "execution_enabled" not in payload
