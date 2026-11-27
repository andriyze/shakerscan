"""Whether a device posture scan covered enough to resolve the findings it no longer reports."""

from __future__ import annotations

from typing import Any, Mapping


def device_missing_resolution(result: Mapping[str, Any], options: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """``(resolve_posture_missing, resolve_web_missing)`` for ``save_device_findings``.

    Posture rows a scan no longer reports resolve only after a complete all-ports TCP sweep; web
    rows only when, on top of that, every requested web DAST child completed untruncated.
    """
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    completeness = posture.get("completeness") if isinstance(posture.get("completeness"), dict) else {}
    web_children = posture.get("web_dast_children") if isinstance(posture.get("web_dast_children"), dict) else {}
    resolve_posture_missing = bool(
        completeness.get("complete")
        and completeness.get("tcp_scope") == "all_65535"
    )
    resolve_web_missing = bool(
        resolve_posture_missing
        and not completeness.get("web_probe_truncated")
        and (options or {}).get("include_web_dast")
        and web_children.get("enabled")
        and int(web_children.get("failed") or 0) == 0
        and int(web_children.get("truncated") or 0) == 0
        and int(web_children.get("completed") or 0) == int(web_children.get("requested") or 0)
    )
    return resolve_posture_missing, resolve_web_missing


__all__ = ["device_missing_resolution"]
