import json
import sys
from typing import Any

from .common import run, stderr_withheld_from_receipts
from .discovered_names import subdomain_of
from .subfinder_providers import (
    MAX_TIME_MINUTES, provider_config, subfinder_arguments, with_provider_config,
)

# Subfinder stops itself at ``-max-time``; the process timeout only catches a hang beyond it.
_PROCESS_TIMEOUT_SECONDS = MAX_TIME_MINUTES * 60 + 30


async def subfinder_scan(domain: str) -> dict[str, Any]:
    """Run subfinder (all sources, operator provider keys when configured) for ``domain``.

    ``sources`` maps each accepted name to the upstream sources subfinder reported for it.
    """
    result: dict[str, Any] = {"subdomains": [], "count": 0, "sources": {}, "error": None}

    try:
        with provider_config() as (config_path, config_error):
            if config_error:
                # A fixed code, never a key: discovery still runs, on the keyless sources, and
                # the run result says the configured keys were not used.
                print(f"[subfinder] provider keys ignored: {config_error}", file=sys.stderr)
                result["provider_config_error"] = config_error
            cmd = with_provider_config(
                ["/opt/tools/subfinder", *subfinder_arguments(domain)], config_path,
            )
            keyed = config_path is not None
            if keyed:
                # A keyed source can echo its request URL (key in the query) on stderr.
                with stderr_withheld_from_receipts():
                    stdout, stderr, rc = await run(cmd, timeout=_PROCESS_TIMEOUT_SECONDS)
            else:
                stdout, stderr, rc = await run(cmd, timeout=_PROCESS_TIMEOUT_SECONDS)

        if rc == 0 and stdout.strip():
            sources: dict[str, set[str]] = {}
            for line in stdout.strip().splitlines():
                upstream = None
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    row = None
                if isinstance(row, dict):
                    raw = row.get("host") or row.get("input")
                    if isinstance(row.get("source"), str):
                        upstream = row["source"].strip().lower()[:64] or None
                else:
                    raw = line
                sub = subdomain_of(raw, domain)
                if sub:
                    bucket = sources.setdefault(sub, set())
                    if upstream:
                        bucket.add(upstream)
            unique = sorted(sources)
            result["subdomains"] = unique
            result["count"] = len(unique)
            result["sources"] = {
                name: sorted(items) for name, items in sorted(sources.items()) if items
            }
        elif stderr:
            # A source error can echo a request URL, and some providers take the key in the
            # query string: with keys configured, keep only the exit status.
            result["error"] = f"subfinder_exit_{rc}" if keyed else stderr.strip()[:2000]
    except Exception as e:  # pragma: no cover - defensive
        result["error"] = type(e).__name__

    return result
