"""Deployment-level policy: safe defaults, explicit opt-ins, and the crawler memory bound."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import deployment_policy as policy  # noqa: E402


def test_private_network_targets_are_refused_unless_explicitly_allowed():
    assert policy.private_network_targets_policy({}) == "refuse"
    assert policy.private_network_targets_policy({policy.PRIVATE_NETWORK_TARGETS_ENV: "no"}) == "refuse"
    assert policy.private_network_targets_policy({policy.PRIVATE_NETWORK_TARGETS_ENV: "refuse"}) == "refuse"
    assert policy.private_network_targets_policy({policy.PRIVATE_NETWORK_TARGETS_ENV: "allow"}) == "allow"
    assert policy.private_network_targets_allowed({policy.PRIVATE_NETWORK_TARGETS_ENV: "true"})


def test_fleet_memory_declaration_is_optional_and_positive():
    assert policy.fleet_memory_declaration_gb({}) is None
    assert policy.fleet_memory_declaration_gb({policy.FLEET_MEMORY_GB_ENV: "garbage"}) is None
    assert policy.fleet_memory_declaration_gb({policy.FLEET_MEMORY_GB_ENV: "0"}) is None
    assert policy.fleet_memory_declaration_gb({policy.FLEET_MEMORY_GB_ENV: "32"}) == 32.0


def test_crawler_memory_limit_defaults_to_two_gib_and_zero_disables():
    assert policy.crawler_memory_limit_bytes({}) == 2048 * 1024 * 1024
    assert policy.crawler_memory_limit_bytes({policy.CRAWLER_MEMORY_LIMIT_MB_ENV: "1024"}) == 1024 * 1024 * 1024
    assert policy.crawler_memory_limit_bytes({policy.CRAWLER_MEMORY_LIMIT_MB_ENV: "0"}) == 0
    assert policy.crawler_memory_limit_bytes({policy.CRAWLER_MEMORY_LIMIT_MB_ENV: "x"}) == 2048 * 1024 * 1024


def test_crawler_bound_applies_to_the_static_crawler_on_linux_only():
    found = lambda name: "/usr/bin/prlimit" if name == "prlimit" else None  # noqa: E731
    assert policy.crawler_memory_bound_argv("katana", limit_bytes=2**31, platform="linux", which=found) == [
        "/usr/bin/prlimit", f"--data={2**31}", "--",
    ]
    assert policy.crawler_memory_bound_argv("katana_headless", limit_bytes=2**31, platform="linux", which=found) == []
    assert policy.crawler_memory_bound_argv("httpx", limit_bytes=2**31, platform="linux", which=found) == []
    assert policy.crawler_memory_bound_argv("katana", limit_bytes=2**31, platform="darwin", which=found) == []
    assert policy.crawler_memory_bound_argv("katana", limit_bytes=0, platform="linux", which=found) == []
    assert policy.crawler_memory_bound_argv("katana", limit_bytes=2**31, platform="linux", which=lambda _n: None) == []


def test_go_out_of_memory_is_recognised_on_stderr():
    assert policy.crawler_memory_bound_exceeded(b"fatal error: runtime: out of memory\n")
    assert policy.crawler_memory_bound_exceeded("mmap: cannot allocate memory")
    assert not policy.crawler_memory_bound_exceeded(b"context deadline exceeded")
