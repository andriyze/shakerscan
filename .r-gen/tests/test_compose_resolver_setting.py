"""The documented DoH resolver setting reaches every process that resolves DNS posture."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query"
EXPECTED = "SHAKERSCAN_DNS_DOH_RESOLVERS=${SHAKERSCAN_DNS_DOH_RESOLVERS-" + DEFAULT + "}"


def _environment(compose, service):
    env = yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))["services"][service].get("environment") or []
    return env if isinstance(env, list) else [f"{key}={value}" for key, value in env.items()]


def test_local_and_release_stacks_pass_the_resolver_setting_to_api_and_workers():
    for compose in ("docker-compose.yml", "docker-compose.release.yml"):
        for service in ("api", "worker", "agent-tool-worker"):
            assert EXPECTED in _environment(compose, service), (compose, service)


def test_the_broker_worker_passes_the_resolver_setting():
    assert EXPECTED in _environment("docker-compose.broker-worker.yml", "worker")


def test_an_explicit_blank_disables_and_unset_keeps_the_default():
    # ${VAR-default} substitutes only when VAR is unset; an explicit empty value stays empty,
    # which the capability reads as "no DoH resolver". ${VAR:-default} would erase that choice.
    assert "${SHAKERSCAN_DNS_DOH_RESOLVERS:-" not in EXPECTED
