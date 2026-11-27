"""Subfinder invocation shared by every discovery path, with operator-supplied provider keys.

Subfinder without ``-all`` queries only its default sources, and without provider keys skips
every source that needs one (SecurityTrails, Shodan, Censys, Chaos, VirusTotal, ...). Both paths
that run it -- the Targets-page discovery job and the canonical ``subdomains.discover`` capability --
now pass ``-all`` and, when the operator configured keys, a provider config file rendered at run
time.

Keys come from either (both may be set; their keys are merged):

* ``SHAKERSCAN_SUBFINDER_PROVIDERS`` -- inline in ``.env``, ``provider=key[,key...]`` entries
  separated by ``;`` (for example ``securitytrails=KEY;censys=ID:SECRET;shodan=K1,K2``); a key
  containing ``;`` or ``,`` escapes it with a preceding backslash (a doubled backslash is one);
* ``SHAKERSCAN_SUBFINDER_PROVIDER_CONFIG`` -- the path of a subfinder ``provider-config.yaml``
  (``provider: [key, ...]``), mounted read-only into the worker.

The rendered file is written with mode 0600 inside a fresh 0700 temporary directory, passed with
``-pc``, and deleted when the run ends. Key values never reach argv, logs, receipts or errors: an
invalid configuration is reported by a fixed code and the run proceeds without keys.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
import re
import shutil
import tempfile
from typing import Iterator, Mapping

PROVIDERS_ENV = "SHAKERSCAN_SUBFINDER_PROVIDERS"
PROVIDER_CONFIG_ENV = "SHAKERSCAN_SUBFINDER_PROVIDER_CONFIG"

# Subfinder's own bounds: seconds per source request, and minutes for the whole enumeration.
# ``-all`` adds sources, not time: they run concurrently inside the same ``-max-time``, which
# stays at the 2 minutes the capability registry's 120 s tool wall is sized for.
SOURCE_TIMEOUT_SECONDS = 10
MAX_TIME_MINUTES = 2

INVALID_CONFIG = "subfinder_provider_config_invalid"
UNREADABLE_CONFIG = "subfinder_provider_config_unreadable"

_PROVIDER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_MAX_PROVIDERS = 64
_MAX_KEYS_PER_PROVIDER = 20
_MAX_KEY_LENGTH = 512
_MAX_CONFIG_BYTES = 64 * 1024


class ProviderConfigError(ValueError):
    """The configured keys are unusable. The message is a fixed code, never a value."""


def _valid_key(value: object) -> str:
    key = str(value if value is not None else "").strip()
    if (
        not key or len(key) > _MAX_KEY_LENGTH
        or any(ord(character) < 33 or ord(character) == 127 for character in key)
    ):
        raise ProviderConfigError(INVALID_CONFIG)
    return key


def _merge(target: dict[str, list[str]], provider: object, keys: object) -> None:
    name = str(provider or "").strip().lower()
    if not _PROVIDER.fullmatch(name):
        raise ProviderConfigError(INVALID_CONFIG)
    values = keys if isinstance(keys, (list, tuple)) else [keys]
    bucket = target.setdefault(name, [])
    for value in values:
        key = _valid_key(value)
        if key not in bucket:
            bucket.append(key)
    if not bucket or len(bucket) > _MAX_KEYS_PER_PROVIDER or len(target) > _MAX_PROVIDERS:
        raise ProviderConfigError(INVALID_CONFIG)


def _inline_entries(raw: str) -> list[tuple[str, list[str]]]:
    r"""One pass over ``provider=key[,key...];...`` honouring backslash escapes.

    ``\;`` and ``\,`` put a separator inside a key, ``\\`` is a literal backslash, and ``\=`` an
    equals sign; any other escape keeps its backslash. A trailing lone backslash is invalid.
    """
    entries: list[tuple[str, list[str]]] = []
    provider: str | None = None
    values: list[str] = []
    current: list[str] = []
    escaped = False

    def close_entry() -> None:
        nonlocal provider, values, current
        text = "".join(current)
        if provider is None:
            if text.strip():
                raise ProviderConfigError(INVALID_CONFIG)
        else:
            entries.append((provider, [*values, text]))
        provider, values, current = None, [], []

    for character in raw:
        if escaped:
            current.append(character if character in {";", ",", "\\", "="} else "\\" + character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ";":
            close_entry()
        elif character == "=" and provider is None:
            provider, current = "".join(current), []
        elif character == "," and provider is not None:
            values.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise ProviderConfigError(INVALID_CONFIG)
    close_entry()
    return entries


def _inline_keys(raw: str) -> dict[str, list[str]]:
    keys: dict[str, list[str]] = {}
    for provider, items in _inline_entries(raw):
        _merge(keys, provider, [item for item in items if item.strip()])
    return keys


def _file_keys(path: str) -> dict[str, list[str]]:
    import yaml

    try:
        with open(path, "rb") as handle:
            content = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ProviderConfigError(UNREADABLE_CONFIG) from None
    if len(content) > _MAX_CONFIG_BYTES:
        raise ProviderConfigError(INVALID_CONFIG)
    try:
        document = yaml.safe_load(content.decode("utf-8")) if content.strip() else {}
    except (UnicodeDecodeError, yaml.YAMLError):
        raise ProviderConfigError(INVALID_CONFIG) from None
    if document is None:
        document = {}
    if not isinstance(document, Mapping):
        raise ProviderConfigError(INVALID_CONFIG)
    keys: dict[str, list[str]] = {}
    for provider, values in document.items():
        if values in (None, [], ""):
            continue  # subfinder's generated template lists every provider with no keys
        _merge(keys, provider, values)
    return keys


def configured_provider_keys(environ: Mapping[str, str] | None = None) -> dict[str, list[str]]:
    """Every configured provider and its keys; empty when none are configured."""
    env = os.environ if environ is None else environ
    keys: dict[str, list[str]] = {}
    path = str(env.get(PROVIDER_CONFIG_ENV) or "").strip()
    if path:
        for provider, values in _file_keys(path).items():
            _merge(keys, provider, values)
    inline = str(env.get(PROVIDERS_ENV) or "").strip()
    if inline:
        for provider, values in _inline_keys(inline).items():
            _merge(keys, provider, values)
    return keys


def _render(keys: Mapping[str, list[str]]) -> str:
    import yaml

    return yaml.safe_dump(
        {provider: list(values) for provider, values in sorted(keys.items())},
        default_flow_style=False, sort_keys=True,
    )


@contextmanager
def provider_config(environ: Mapping[str, str] | None = None) -> Iterator[tuple[str | None, str | None]]:
    """``(path, error_code)``: a private rendered provider config for one run, or none.

    The path is None when no keys are configured or the configuration is invalid (then
    ``error_code`` says which, without any value). The directory is removed on exit.
    """
    global _SWEPT
    if not _SWEPT:
        _SWEPT = True
        sweep_stale_provider_configs()
    try:
        keys = configured_provider_keys(environ)
    except ProviderConfigError as exc:
        yield None, str(exc)
        return
    if not keys:
        yield None, None
        return
    directory = tempfile.mkdtemp(prefix=_CONFIG_DIR_PREFIX)
    try:
        os.chmod(directory, 0o700)
        path = os.path.join(directory, "provider-config.yaml")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_render(keys))
        yield path, None
    finally:
        shutil.rmtree(directory, ignore_errors=True)


_CONFIG_DIR_PREFIX = "shakerscan-subfinder-"
# Older than any run can last (subfinder's -max-time plus the process timeout's slack), so a
# sweep never removes the directory of a run another worker process has in flight.
_STALE_AFTER_SECONDS = MAX_TIME_MINUTES * 60 + 300
# Whether this process already swept (once per process, before its first render).
_SWEPT = False


def sweep_stale_provider_configs(
    *, directory: str | None = None, now: float | None = None,
) -> int:
    """Remove rendered provider-config directories a killed run left behind; return how many.

    A process that dies mid-run never reaches the cleanup in ``provider_config``, leaving a 0600
    key file in the temporary directory. ``provider_config`` -- the only producer of these
    directories -- runs this once per process before it renders, so every process that can
    write one (worker, agent-tool-worker, the scanner CLI) also clears what an earlier one left.
    Only this user's own, stale ``shakerscan-subfinder-*`` directories are touched.
    """
    import time

    root = directory or tempfile.gettempdir()
    current = time.time() if now is None else now
    removed = 0
    try:
        entries = list(os.scandir(root))
    except OSError:
        return 0
    for entry in entries:
        if not entry.name.startswith(_CONFIG_DIR_PREFIX):
            continue
        try:
            info = entry.stat(follow_symlinks=False)
            if (
                not entry.is_dir(follow_symlinks=False)
                or info.st_uid != os.getuid()
                or current - info.st_mtime < _STALE_AFTER_SECONDS
            ):
                continue
        except OSError:
            continue
        shutil.rmtree(entry.path, ignore_errors=True)
        removed += 1
    return removed


def subfinder_arguments(domain: str) -> tuple[str, ...]:
    """The server-owned subfinder argv after the binary, without the per-run config path."""
    return (
        "-d", domain, "-all", "-silent", "-json", "-disable-update-check",
        "-timeout", str(SOURCE_TIMEOUT_SECONDS), "-max-time", str(MAX_TIME_MINUTES),
    )


def with_provider_config(argv: tuple[str, ...] | list[str], path: str | None) -> list[str]:
    """``argv`` with ``-pc <path>`` when a rendered config exists."""
    return [*argv, "-pc", path] if path else list(argv)


__all__ = [
    "INVALID_CONFIG", "MAX_TIME_MINUTES", "PROVIDERS_ENV", "PROVIDER_CONFIG_ENV",
    "ProviderConfigError", "SOURCE_TIMEOUT_SECONDS", "UNREADABLE_CONFIG",
    "sweep_stale_provider_configs",
    "configured_provider_keys", "provider_config",
    "subfinder_arguments", "with_provider_config",
]
