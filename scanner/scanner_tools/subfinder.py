from typing import Any

from .common import run


async def subfinder_scan(domain: str) -> dict[str, Any]:
    """Run subfinder to discover subdomains."""
    result: dict[str, Any] = {"subdomains": [], "count": 0, "error": None}

    try:
        cmd = ["/opt/tools/subfinder", "-d", domain, "-silent"]
        stdout, stderr, rc = await run(cmd, timeout=120)

        if rc == 0 and stdout.strip():
            subdomains: list[str] = []
            for line in stdout.strip().splitlines():
                sub = line.strip()
                if sub and sub != domain:
                    subdomains.append(sub)
            unique = sorted(list(set(subdomains)))
            result["subdomains"] = unique
            result["count"] = len(unique)
        elif stderr:
            result["error"] = stderr.strip()
    except Exception as e:  # pragma: no cover - defensive
        result["error"] = str(e)

    return result
