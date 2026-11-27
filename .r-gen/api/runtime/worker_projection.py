"""Pure projections shared by the worker's persistence and receipt paths."""

from __future__ import annotations

from typing import Any
import urllib.parse


AI_GATE_RUN_KINDS = frozenset({
    "ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget",
})
MODEL_INTAKE_RUN_KINDS = frozenset({"model_intake"})


def truthy_module_output(value: Any) -> bool:
    if isinstance(value, dict):
        return any(item not in (None, "", [], {}) for item in value.values())
    if isinstance(value, list):
        return bool(value)
    return value not in (None, "", [], {})


def subprocess_parser_error_reason(
    tool_name: str, receipt: dict[str, Any],
) -> str | None:
    """Conservatively identify parser/output failures from bounded previews."""
    tool = str(tool_name or "").strip().lower()
    if tool not in {
        "httpx", "katana", "subfinder", "ffuf", "nuclei", "dalfox",
        "sqlmap", "nmap", "sslyze", "testssl", "playwright",
    }:
        return None
    if str(receipt.get("status") or "").strip() == "timeout" or receipt.get("timed_out"):
        return None
    combined = " ".join(
        str(receipt.get(key) or "") for key in ("stderr_preview", "stdout_preview")
    ).lower()
    if not combined:
        return None
    for marker in (
        "json: cannot unmarshal", "invalid character",
        "unexpected end of json input", "failed to parse json",
        "failed parsing json", "json parse error", "parse error",
        "could not parse", "cannot parse", "malformed json", "invalid json",
        "unmarshal type error",
    ):
        if marker in combined:
            return marker
    return None


def runtime_destination_records(
    result: dict[str, Any], options: dict[str, Any],
) -> list[dict[str, Any]]:
    """Project bounded destination evidence without performing network work."""
    run_kind = str((options or {}).get("run_kind") or "").strip()
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        label: str,
        url: Any,
        final_url: Any = None,
        *,
        source: str | None = None,
        redirect_urls: Any = None,
        resolved_ips: Any = None,
        resolved_host: Any = None,
    ) -> None:
        raw_url = str(url or "").strip()
        raw_final = str(final_url or raw_url).strip()
        if not raw_url and not raw_final:
            return
        key = (label, raw_url, raw_final)
        if key in seen:
            return
        seen.add(key)
        record: dict[str, Any] = {"label": label, "url": raw_url or raw_final}
        if raw_final:
            record["final_url"] = raw_final
        if source:
            record["source"] = source
        if isinstance(redirect_urls, (list, tuple)):
            record["redirect_urls"] = [
                str(item) for item in redirect_urls if str(item or "").strip()
            ]
        if isinstance(resolved_ips, (list, tuple)):
            record["resolved_ips"] = [
                str(item) for item in resolved_ips if str(item or "").strip()
            ]
        elif str(resolved_ips or "").strip():
            record["resolved_ips"] = [str(resolved_ips).strip()]
        if str(resolved_host or "").strip():
            record["resolved_host"] = str(resolved_host).strip()
        records.append(record)

    if run_kind in {"device_posture", "device_probe"}:
        posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
        probe = result.get("device_probe") if isinstance(result.get("device_probe"), dict) else {}
        locator = str(result.get("target") or "").strip()
        resolved = str(result.get("resolved_target") or posture.get("resolved_target") or "").strip()
        if locator:
            formatted = f"[{locator}]" if ":" in locator and not locator.startswith("[") else locator
            port = probe.get("port") if probe else None
            add(
                "device_target",
                f"http://{formatted}{f':{int(port)}' if port else ''}/",
                source=run_kind,
                resolved_ips=[resolved] if resolved else None,
                resolved_host=locator,
            )
        for item in posture.get("runtime_destinations") or ():
            if isinstance(item, dict):
                add(
                    str(item.get("label") or "device_web_child"),
                    item.get("url"), item.get("final_url"),
                    source=item.get("source") or "device_web_dast",
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        return records

    if run_kind in AI_GATE_RUN_KINDS:
        payload = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        fallback_label = "ai_gate"
    elif run_kind in MODEL_INTAKE_RUN_KINDS:
        payload = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        fallback_label = "model_intake"
    else:
        payload = None
        fallback_label = ""
    if payload is not None:
        for item in payload.get("runtime_destinations") or ():
            if isinstance(item, dict):
                add(
                    str(item.get("label") or fallback_label),
                    item.get("url"), item.get("final_url"),
                    source=item.get("source"),
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        return records

    runtime_destinations = result.get("runtime_destinations")
    if isinstance(runtime_destinations, list):
        for item in runtime_destinations:
            if isinstance(item, dict):
                add(
                    str(item.get("label") or "dast_action"),
                    item.get("url"), item.get("final_url"),
                    source=item.get("source") or "canonical_action_observation",
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        if records:
            return records

    http = result.get("http") if isinstance(result.get("http"), dict) else {}
    final_url = str(http.get("final_url") or "").strip()
    final_host = urllib.parse.urlparse(final_url).hostname if final_url else None
    add(
        "dast_http", http.get("request_url") or final_url, final_url,
        source="http_observation", redirect_urls=http.get("redirect_chain"),
        resolved_ips=http.get("remote_ip"), resolved_host=final_host,
    )
    return records
