"""Subfinder runs all sources and uses operator provider keys without ever exposing them.

Subfinder ran with its default sources only (no ``-all``) and the image wired no provider keys,
so the key-backed sources never answered. Both paths that run it -- the canonical
``subdomains.discover`` capability and the Targets-page discovery job -- now pass ``-all`` and,
when keys are configured, a private provider config rendered for the run. Fixture runners only;
no subfinder process and no network.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from api.capabilities.network import NetworkExecutionAdapter, SubdomainsDiscoverAdapter
from api.hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import ScanPolicy, TargetBinding
from scanner.scanner_tools import subdomain_discovery, subfinder, subfinder_providers

KEY_A = "sk-test-securitytrails-0123456789"
KEY_B = "censys-id:censys-secret-ABCDEF"
KEY_C = "shodan-test-key-777"
SECRETS = (KEY_A, KEY_B, KEY_C)
INLINE = f"securitytrails={KEY_A};censys={KEY_B}"


@pytest.fixture(autouse=True)
def _no_operator_keys(monkeypatch):
    monkeypatch.delenv(subfinder_providers.PROVIDERS_ENV, raising=False)
    monkeypatch.delenv(subfinder_providers.PROVIDER_CONFIG_ENV, raising=False)


TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",), scope_receipt_id="scope-1",
)
POLICY = ScanPolicy(subdomain_discovery=True)


class Recorder:
    """A fixture command runner that captures argv and the rendered config while it exists."""

    def __init__(self, stdout='{"host":"api.example.test","source":"crtsh"}\n'):
        self.stdout = stdout
        self.argv: list[str] = []
        self.config_text: str | None = None
        self.config_mode: int | None = None
        self.directory_mode: int | None = None
        self.config_path: str | None = None

    def capture(self, argv):
        self.argv = list(argv)
        if "-pc" in self.argv:
            path = Path(self.argv[self.argv.index("-pc") + 1])
            self.config_path = str(path)
            self.config_text = path.read_text()
            self.config_mode = stat.S_IMODE(path.stat().st_mode)
            self.directory_mode = stat.S_IMODE(path.parent.stat().st_mode)

    async def streaming(self, argv, **_kwargs):
        self.capture(argv)
        return SimpleNamespace(
            stdout=self.stdout, stderr="", returncode=0, timed_out=False, partial=False,
            stdout_truncated=False, cancelled=False,
        )

    async def run(self, cmd, timeout=60, **_kwargs):
        self.capture(cmd)
        return self.stdout, "", 0


def _run_capability(recorder):
    parser = SubdomainsDiscoverAdapter()
    prepared = parser.prepare(target=TARGET, args={}, policy=POLICY)

    async def heartbeat():
        return None

    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("subdomains.discover"),
            target=TARGET, requested_budget=dict(prepared.estimated_budget),
        ),
        NetworkExecutionAdapter(
            prepared=prepared, parser=parser, command_runner=recorder.streaming,
            max_stdout_bytes=10_000, max_stderr_bytes=1_000,
        ),
        heartbeat=heartbeat, cancelled=lambda: False,
    ))
    return prepared, result


def _dump(value) -> str:
    return json.dumps(value, default=lambda item: getattr(item, "__dict__", repr(item)))


# --------------------------------------------------------------------- canonical capability


def test_the_capability_queries_all_sources_and_passes_no_config_when_none_is_configured():
    recorder = Recorder()
    prepared, result = _run_capability(recorder)
    assert "-all" in prepared.commands[0].argv
    assert "-all" in recorder.argv
    assert "-pc" not in recorder.argv
    assert result.status == "success"
    assert result.observations[0]["source"] == "crtsh"


def test_configured_keys_reach_subfinder_only_through_a_private_file(monkeypatch, capsys):
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, INLINE)
    recorder = Recorder()
    prepared, result = _run_capability(recorder)

    assert "-pc" in recorder.argv
    assert recorder.config_mode == 0o600
    assert recorder.directory_mode == 0o700
    assert KEY_A in recorder.config_text and KEY_B in recorder.config_text
    # Deleted when the run ends.
    assert not os.path.exists(recorder.config_path)
    assert not os.path.exists(os.path.dirname(recorder.config_path))

    captured = capsys.readouterr()
    exposed = " ".join(recorder.argv) + _dump(prepared) + _dump(result) + captured.out + captured.err
    for secret in SECRETS:
        assert secret not in exposed


def test_a_provider_config_file_is_rendered_and_merged_with_inline_keys(monkeypatch, tmp_path):
    source = tmp_path / "provider-config.yaml"
    source.write_text(f"shodan:\n  - {KEY_C}\nvirustotal: []\nsecuritytrails:\n  - {KEY_A}\n")
    monkeypatch.setenv(subfinder_providers.PROVIDER_CONFIG_ENV, str(source))
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, f"censys={KEY_B}")
    assert subfinder_providers.configured_provider_keys() == {
        "shodan": [KEY_C], "securitytrails": [KEY_A], "censys": [KEY_B],
    }
    recorder = Recorder()
    _run_capability(recorder)
    import yaml

    assert yaml.safe_load(recorder.config_text) == {
        "censys": [KEY_B], "securitytrails": [KEY_A], "shodan": [KEY_C],
    }


@pytest.mark.parametrize("inline", [
    f"securitytrails {KEY_A}",            # no '='
    f"Bad Provider={KEY_A}",               # invalid provider name
    "securitytrails=",                     # no key
    f"securitytrails={KEY_A}\nshodan=x",   # control character inside a value
])
def test_an_invalid_configuration_is_reported_by_code_and_the_run_proceeds_keyless(
    monkeypatch, capsys, inline,
):
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, inline)
    recorder = Recorder()
    _prepared, result = _run_capability(recorder)
    assert "-pc" not in recorder.argv and "-all" in recorder.argv
    assert result.status == "success"
    err = capsys.readouterr().err
    assert subfinder_providers.INVALID_CONFIG in err
    assert KEY_A not in err


def test_an_unreadable_config_file_names_no_path_content(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(subfinder_providers.PROVIDER_CONFIG_ENV, str(tmp_path / "missing.yaml"))
    recorder = Recorder()
    _run_capability(recorder)
    assert "-pc" not in recorder.argv
    assert subfinder_providers.UNREADABLE_CONFIG in capsys.readouterr().err


# ---------------------------------------------------------------------- Targets-page path


def test_the_targets_page_runner_uses_all_sources_and_the_same_private_config(monkeypatch, capsys):
    recorder = Recorder(stdout="\n".join([
        '{"host":"a.example.test","source":"crtsh"}',
        '{"host":"a.example.test","source":"hackertarget"}',
        '{"host":"notexample.test","source":"crtsh"}',
        "b.example.test",
    ]))
    monkeypatch.setattr(subfinder, "run", recorder.run)
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, INLINE)

    result = asyncio.run(subfinder.subfinder_scan("example.test"))
    assert recorder.argv[:4] == ["/opt/tools/subfinder", "-d", "example.test", "-all"]
    assert "-pc" in recorder.argv and recorder.config_mode == 0o600
    assert not os.path.exists(recorder.config_path)
    assert result["subdomains"] == ["a.example.test", "b.example.test"]
    assert result["sources"] == {"a.example.test": ["crtsh", "hackertarget"]}
    captured = capsys.readouterr()
    for secret in SECRETS:
        assert secret not in " ".join(recorder.argv) + json.dumps(result) + captured.err


def test_a_keyed_failure_keeps_only_the_exit_status(monkeypatch):
    async def fails(cmd, timeout=60, **_kwargs):
        return "", f"source error: https://api.example/v1?apikey={KEY_A}", 1

    monkeypatch.setattr(subfinder, "run", fails)
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, INLINE)
    result = asyncio.run(subfinder.subfinder_scan("example.test"))
    assert result["error"] == "subfinder_exit_1"


def test_targets_page_discovery_keeps_subfinder_upstream_sources_as_evidence(monkeypatch):
    async def subfinder_scan(domain):
        return {
            "subdomains": ["a.example.test", "b.example.test"],
            "sources": {"a.example.test": ["certspotter"], "b.example.test": ["hackertarget"]},
        }

    async def crtsh(domain, **_kwargs):
        return {"subdomain_discovery": {"subdomains": ["b.example.test"]}}

    monkeypatch.setattr(subdomain_discovery, "subfinder_scan", subfinder_scan)
    monkeypatch.setattr(subdomain_discovery, "check_certificate_transparency", crtsh)
    result = asyncio.run(subdomain_discovery.discover_subdomains("example.test", use_gungnir=False))
    assert result["name_sources"] == {
        "a.example.test": ["subfinder", "subfinder:certspotter"],
        "b.example.test": ["crtsh", "subfinder", "subfinder:hackertarget"],
    }


# ---------------------------------------------------------------------- review hardening


@pytest.mark.parametrize(("inline", "expected"), [
    (r"censys=ID:SECRET;shodan=K1,K2", {"censys": ["ID:SECRET"], "shodan": ["K1", "K2"]}),
    (r"x=a\;b\,c", {"x": ["a;b,c"]}),
    (r"x=a\=b", {"x": ["a=b"]}),
    (r"x=back\\slash,next", {"x": ["back\\slash", "next"]}),
])
def test_inline_keys_honour_escapes(inline, expected):
    assert subfinder_providers._inline_keys(inline) == expected


def test_a_trailing_escape_is_invalid():
    with pytest.raises(subfinder_providers.ProviderConfigError):
        subfinder_providers._inline_keys("x=abc\\")


def test_an_invalid_configuration_reaches_the_run_results_not_only_stderr(monkeypatch):
    monkeypatch.setenv(subfinder_providers.PROVIDERS_ENV, "not-a-valid-entry")
    _prepared, result = _run_capability(Recorder())
    assert subfinder_providers.INVALID_CONFIG in result.errors

    async def run(cmd, timeout=60, **_kwargs):
        return '{"host":"a.example.test"}', "", 0

    monkeypatch.setattr(subfinder, "run", run)
    scanned = asyncio.run(subfinder.subfinder_scan("example.test"))
    assert scanned["provider_config_error"] == subfinder_providers.INVALID_CONFIG

    async def subfinder_scan(domain):
        return {"subdomains": [], "provider_config_error": subfinder_providers.INVALID_CONFIG}

    monkeypatch.setattr(subdomain_discovery, "subfinder_scan", subfinder_scan)
    discovered = asyncio.run(subdomain_discovery.discover_subdomains(
        "example.test", use_gungnir=False, use_crtsh=False,
    ))
    assert discovered["by_source"]["subfinder"]["error"] == subfinder_providers.INVALID_CONFIG


def test_a_keyed_run_withholds_stderr_from_its_subprocess_receipt(monkeypatch):
    from scanner.scanner_tools import common

    common.reset_subprocess_receipts()
    with common.stderr_withheld_from_receipts():
        common._record_subprocess_receipt(
            ["/opt/tools/subfinder", "-d", "example.test"], timeout_seconds=10, exit_code=1,
            timed_out=False, started_at=0.0,
            stderr=f"error: https://api.example/v1?apikey={KEY_A}",
        )
    common._record_subprocess_receipt(
        ["/opt/tools/subfinder"], timeout_seconds=10, exit_code=1, timed_out=False,
        started_at=0.0, stderr="ordinary failure",
    )
    withheld, ordinary = common.snapshot_subprocess_receipts()[-2:]
    assert KEY_A not in json.dumps(withheld)
    assert "withheld" in withheld["stderr_preview"]
    assert ordinary["stderr_preview"] == "ordinary failure"


# What the redactor change does to a URL corpus, versus origin/main: main already masked a
# userinfo password after a user name; the only change is the empty-user-name form. Query parameters named ``key``/``auth`` (a SKU, an SSO mode,
# a DAST payload in ``key=``) stay visible; keyed subfinder stderr never reaches a receipt anyway.
REDACTION_CORPUS = (
    # (input, now, main) -- main computed from origin/main scanner/redaction.py
    ('https://shop.example.test/item?key=sku-123',
     'https://shop.example.test/item?key=sku-123',
     'https://shop.example.test/item?key=sku-123'),
    ('https://app.example.test/login?auth=sso',
     'https://app.example.test/login?auth=sso',
     'https://app.example.test/login?auth=sso'),
    ('https://app.example.test/search?key=%3Cscript%3Ealert(1)%3C/script%3E',
     'https://app.example.test/search?key=%3Cscript%3Ealert(1)%3C/script%3E',
     'https://app.example.test/search?key=%3Cscript%3Ealert(1)%3C/script%3E'),
    ('https://api.shodan.io/dns/domain/x.test?key=SHODANKEY',
     'https://api.shodan.io/dns/domain/x.test?key=SHODANKEY',
     'https://api.shodan.io/dns/domain/x.test?key=SHODANKEY'),
    ('https://api.example.test/v1?token=TOKEN0123&secret=SECRET0123',
     'https://api.example.test/v1?token=***&secret=***',
     'https://api.example.test/v1?token=***&secret=***'),
    ('https://api.example.test/v1?api_key=APIKEY0123',
     'https://api.example.test/v1?api_key=***',
     'https://api.example.test/v1?api_key=***'),
    ('https://search.example.test/a?keyword=dns',
     'https://search.example.test/a?keyword=dns',
     'https://search.example.test/a?keyword=dns'),
    ('https://CENSYSID:CENSYSSECRET@search.censys.io/api/v2',
     'https://CENSYSID:***@search.censys.io/api/v2',
     'https://CENSYSID:***@search.censys.io/api/v2'),
    ('redis://:s3cret@redis:6379/0',
     'redis://:***@redis:6379/0',
     'redis://:s3cret@redis:6379/0'),
    ('postgresql://scanner:pw0rd@postgres:5432/scanner',
     'postgresql://scanner:***@postgres:5432/scanner',
     'postgresql://scanner:***@postgres:5432/scanner'),
    ('https://user@example.test/path',
     'https://user@example.test/path',
     'https://user@example.test/path'),
    ('http://example.test:8080/a@b',
     'http://example.test:8080/a@b',
     'http://example.test:8080/a@b'),
    ('monkey=banana; sort key=value',
     'monkey=banana; sort key=value',
     'monkey=banana; sort key=value'),
)


@pytest.mark.parametrize(("text", "expected", "main"), REDACTION_CORPUS)
def test_the_redactor_changes_exactly_empty_username_userinfo_versus_main(text, expected, main):
    from scanner.redaction import redact_text

    assert redact_text(text) == expected
    changed = {row[0] for row in REDACTION_CORPUS if row[1] != row[2]}
    # The only difference from main: a userinfo password with an empty user name.
    assert changed == {"redis://:s3cret@redis:6379/0"}


def test_the_sweep_removes_only_stale_own_provider_directories(tmp_path):
    stale = tmp_path / "shakerscan-subfinder-stale"
    fresh = tmp_path / "shakerscan-subfinder-fresh"
    other = tmp_path / "unrelated-dir"
    for directory in (stale, fresh, other):
        directory.mkdir()
        (directory / "provider-config.yaml").write_text("x: [y]\n")
    old = 1_000_000.0
    os.utime(stale, (old, old))
    os.utime(other, (old, old))
    now = old + subfinder_providers._STALE_AFTER_SECONDS + 1
    os.utime(fresh, (now - 5, now - 5))
    removed = subfinder_providers.sweep_stale_provider_configs(
        directory=str(tmp_path), now=now,
    )
    assert removed == 1
    assert not stale.exists() and fresh.exists() and other.exists()


def test_the_first_render_in_a_process_sweeps_once(monkeypatch):
    calls = []
    monkeypatch.setattr(subfinder_providers, "_SWEPT", False)
    monkeypatch.setattr(
        subfinder_providers, "sweep_stale_provider_configs", lambda **_kw: calls.append(1) or 0,
    )
    for _ in range(3):
        with subfinder_providers.provider_config({}) as (path, error):
            assert path is None and error is None
    assert calls == [1]
