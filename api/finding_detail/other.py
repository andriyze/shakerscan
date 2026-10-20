"""GraphQL, DNS takeover, template (CVE / default login / misconfiguration), AI and generic findings."""

from __future__ import annotations

import os
import re
from typing import Any, Mapping

from .common import command, fact, facts, integer, join_limited, origin_of, q, record, strings, text, visible_scalar_facts

try:
    from capabilities.graphql_probe import (
        ALIAS_COUNT, DUPLICATE_FIELD_COUNT, GRAPHQL_REQUEST_HEADERS, INTROSPECTION_QUERY, alias_query,
        duplicate_field_query, endpoint_of, is_graphql_name, reserved_probe_query,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.graphql_probe import (
        ALIAS_COUNT, DUPLICATE_FIELD_COUNT, GRAPHQL_REQUEST_HEADERS, INTROSPECTION_QUERY, alias_query,
        duplicate_field_query, endpoint_of, is_graphql_name, reserved_probe_query,
    )

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# The probe's own counts bound what a copyable command repeats; a stored count outside them did
# not come from this probe. At those counts the command stays whole (commands are cut at 2,000
# characters) for any endpoint up to about 360 characters.
_MAX_REPEATED_FIELDS = max(ALIAS_COUNT, DUPLICATE_FIELD_COUNT)
_LIMITS_FIX = "Limit {what}, depth and cost per query (graphql-armor {plugin} / maxDepth / costLimit, or your server's validation rules)."


def _graphql_get(endpoint: str, document: str) -> str:
    """The request the probe sent: a GET whose only query parameter is ``document``."""
    headers = " ".join(f"-H {q(f'{name}: {value}')}" for name, value in GRAPHQL_REQUEST_HEADERS)
    return f"curl -sS -G {q(endpoint)} {headers} --data-urlencode {q('query=' + document)}"


def _repeat_count(value: Any, default: int) -> int:
    count = integer(value)
    return count if count is not None and 1 <= count <= _MAX_REPEATED_FIELDS else default


def build_graphql_introspection(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Introspection is a server setting on a live API: checked by asking for the schema, never by a status."""
    endpoint = endpoint_of(text(evidence.get("request_url") or finding.get("url"), 600))
    status = evidence.get("response_status")
    request = _graphql_get(endpoint, INTROSPECTION_QUERY)
    excerpt = text(evidence.get("redacted_excerpt"), 1200)
    via = text(evidence.get("discovered_via"), 80)
    return {
        "class": "exposure.graphql_introspection_enabled", "class_label": "GraphQL introspection enabled",
        "summary": f"{endpoint} answered an anonymous introspection query with its schema" + (f" (HTTP {status})" if status else "") + ".",
        "where": facts(fact("Endpoint", endpoint, mono=True), fact("Origin", origin_of(endpoint), mono=True)),
        "observed": facts(fact("Response status", status, mono=True), fact("Content type", evidence.get("content_type"), mono=True)),
        "excerpt": {"label": "Response excerpt (masked by the scanner)", "text": excerpt} if excerpt else None,
        "expected": ["An error instead of the schema: introspection disabled for anonymous clients, with the API itself still answering."],
        "context": ["Anyone can list every type, query and mutation, including internal or admin operations."]
                   + ([f"The scanner reached this endpoint via {via.replace('_', ' ')}."] if via else []),
        "reproduce": command(request, expect='"data" with a "__schema" object that lists the types'),
        "verify": command(request, expect='an "errors" list and no "__schema" (an HTTP 200 or 400 error answer both mean it is off)'),
        "fix": ["Disable introspection in production (Apollo Server: introspection: false; graphql-java: NO_INTROSPECTION_FIELD_VISIBILITY).",
                "Do not block the endpoint's path at the web server: that takes the whole API offline."],
    }


def build_graphql(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    check = text(evidence.get("check"), 60)
    endpoint = endpoint_of(text(evidence.get("endpoint") or finding.get("url"), 400))
    if check == "field_suggestions":
        fields = strings(evidence.get("suggested_fields"), 10, 80)
        names = [name.strip() for name in str(evidence.get("misspelling") or "").split(",")[:20]]
        names = [name for name in names if is_graphql_name(name)]
        document = "query{" + " ".join(names) + "}" if names else reserved_probe_query()
        request = _graphql_get(endpoint, document)
        return {
            "class": "graphql.field_suggestions", "class_label": "GraphQL field suggestions",
            "summary": f"{endpoint} answers a misspelled field ({join_limited(names, 8) or text(evidence.get('misspelling'), 80)}) with \"Did you mean …\" hints that reveal real field names: {join_limited(fields, 6)}.",
            "where": facts(fact("Endpoint", endpoint, mono=True), fact("Root type", evidence.get("root_type"), mono=True)),
            "observed": facts(fact("Misspelled field sent", join_limited(names, 20) or evidence.get("misspelling"), mono=True), fact("Fields revealed", join_limited(fields, 10), mono=True)),
            "expected": ["A generic validation error without suggestions."],
            "context": ["Suggestions let anyone rebuild the schema even with introspection disabled."],
            "reproduce": command(request, expect="\"Did you mean\" in the error"),
            "verify": command(request, expect="a validation error without \"Did you mean\""),
            "fix": ["Disable suggestions in production (graphql-armor blockFieldSuggestion; Apollo: mask validation errors)."],
        }
    if check == "alias_limit_absent":
        count = _repeat_count(evidence.get("alias_count"), ALIAS_COUNT)
        request = _graphql_get(endpoint, alias_query(count))
        return {
            "class": f"graphql.{check}", "class_label": "No GraphQL aliases limit",
            "summary": f"{endpoint} executed one query with {count} aliases; nothing limits how much work a single request can ask for.",
            "where": facts(fact("Endpoint", endpoint, mono=True)),
            "observed": facts(fact("Aliases accepted", count), fact("Response status", evidence.get("response_status"), mono=True)),
            "expected": ["A validation error once a query exceeds a small alias limit (e.g. 15 aliases)."],
            "context": ["Unbounded aliasing lets one request multiply expensive resolvers (resource exhaustion) or batch password/OTP guesses past rate limits."],
            "reproduce": command(request, expect=f"{count} aliased __typename results in one response, without errors"),
            "verify": command(request, expect="an error rejecting the query, not data"),
            "fix": [_LIMITS_FIX.format(what="aliases", plugin="maxAliases")],
        }
    if check == "duplicate_field_limit_absent":
        count = _repeat_count(evidence.get("duplicate_count"), DUPLICATE_FIELD_COUNT)
        request = _graphql_get(endpoint, duplicate_field_query(count))
        return {
            "class": f"graphql.{check}", "class_label": "No GraphQL duplicate fields limit",
            "summary": f"{endpoint} executed one query that repeats a field {count} times; nothing limits how much work a single request can ask for.",
            "where": facts(fact("Endpoint", endpoint, mono=True)),
            "observed": facts(fact("Duplicate fields accepted", count), fact("Response status", evidence.get("response_status"), mono=True)),
            "expected": ["A validation error once a query repeats a field more than a small limit."],
            "context": ["The server parses, validates and merges every repeated copy; without a limit one request can carry thousands of copies and tie up the server (resource exhaustion)."],
            "reproduce": command(request, expect="data with __typename and no errors"),
            "verify": command(request, expect="an error rejecting the query, not data"),
            "fix": [_LIMITS_FIX.format(what="repeated fields (or tokens)", plugin="maxTokens")],
        }
    return {}


def build_takeover(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    host = text(evidence.get("host"), 255)
    chain = strings(evidence.get("cname_chain"), 10, 255)
    terminal = text(evidence.get("terminal"), 255)
    service = text(evidence.get("service"), 80)
    verified = evidence.get("check") == "subdomain_takeover"
    return {
        "class": "dns.takeover" if verified else "dns.dangling_cname",
        "class_label": "Subdomain takeover" if verified else "Dangling CNAME",
        "summary": (f"{host} is a CNAME to {terminal}, a {service} resource nobody has claimed: whoever registers it serves content on {host}."
                    if verified else f"{host} is a CNAME to {terminal}, which does not exist."),
        "where": facts(fact("Name", host, mono=True), fact("CNAME chain", " → ".join([host] + chain), mono=True)),
        "observed": facts(fact("Terminal status", evidence.get("terminal_status"), mono=True), fact("Service", service),
                          fact("Service signature", evidence.get("service_signature"), mono=True),
                          fact("Independent resolver confirmed NXDOMAIN", "yes" if evidence.get("terminal_nxdomain_confirmed") else "")),
        "expected": ["Every CNAME points at a resource the organization controls."],
        "context": ["A claimed subdomain can serve phishing pages and set cookies for the parent domain."],
        "reproduce": command(f"dig +short CNAME {q(host)}; dig +short {q(terminal or host)}", expect=f"the CNAME to {terminal}, and no address for it"),
        "verify": command(f"dig +short CNAME {q(host)}", expect="no CNAME (record removed) or one pointing at a resource you own"),
        "fix": [f"Delete the DNS record for {host}, or re-create the {service or 'target'} resource it points to under your account first."],
    }


def _snapshot_rows(cve: str) -> list[Mapping[str, Any]]:
    try:
        try:
            from scanner_tools import device_advisories
        except ModuleNotFoundError:
            from scanner.scanner_tools import device_advisories
        snapshot = device_advisories.load_verified_snapshot(
            os.environ.get("DEVICE_INTEL_DB_PATH"), os.environ.get("DEVICE_INTEL_DB_SHA256"))
    except Exception:  # an unavailable snapshot leaves only the template's own metadata
        return []
    rows = snapshot.get("_advisories_by_id") if isinstance(snapshot.get("_advisories_by_id"), Mapping) else None
    if rows is not None:
        return list(rows.get(cve) or [])[:20]
    return [row for row in snapshot.get("advisories") or () if isinstance(row, Mapping)
            and str(row.get("advisory_id") or row.get("cve") or "").upper() == cve][:20]


def cve_context(cve: str) -> dict[str, Any]:
    """Affected ranges, fixed versions, KEV and EPSS for one CVE from the pinned offline snapshot."""
    out: dict[str, Any] = {"id": cve, "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    ranges: list[str] = []
    for row in _snapshot_rows(cve):
        product = text(row.get("product"), 60)
        start = text(row.get("version_start_including"), 40)
        end_ex = text(row.get("version_end_excluding"), 40)
        end_in = text(row.get("version_end_including"), 40)
        exact = text(row.get("version"), 40)
        span = (f"{start} ≤ " if start else "") + ("version" if (start or end_ex or end_in) else "")
        span += f" < {end_ex}" if end_ex else f" ≤ {end_in}" if end_in else ""
        entry = f"{product} {exact}" if exact and exact not in {"*", "-"} else f"{product} {span}".strip()
        if entry and entry not in ranges:
            ranges.append(entry)
        if end_ex:
            out.setdefault("fixed_in", []).append(f"{product} {end_ex}".strip())
        kev = record(row.get("known_exploited"))
        if kev and "known_exploited" not in out:
            out["known_exploited"] = {"date_added": text(kev.get("date_added"), 10), "ransomware": kev.get("ransomware") is True}
        epss = record(row.get("epss"))
        if isinstance(epss.get("score"), (int, float)) and "epss" not in out:
            out["epss"] = {"score": float(epss["score"]), "percentile": epss.get("percentile")}
        if row.get("title") and "title" not in out:
            out["title"] = text(row.get("title"), 200)
    if ranges:
        out["affected"] = ranges[:6]
    if out.get("fixed_in"):
        out["fixed_in"] = sorted(set(out["fixed_in"]))[:6]
    return out


def build_template(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    template = text(evidence.get("template_id"), 120)
    matched = text(evidence.get("matched_at") or finding.get("url"), 600)
    tags = [tag.lower() for tag in strings(evidence.get("template_tags"), 12, 40)]
    cves = [cve for cve in (value.upper() for value in strings(evidence.get("cve_ids"), 5, 30)) if _CVE.match(cve)]
    description = text(evidence.get("template_description"), 600)
    remediation = text(evidence.get("template_remediation"), 600)
    lengths = [n for n in evidence.get("extracted_result_lengths") or () if isinstance(n, int)]
    title = text(finding.get("title"), 200)
    observed = facts(
        fact("Template", template, mono=True), fact("Matcher", evidence.get("matcher_name"), mono=True),
        fact("Template CVSS", evidence.get("cvss_score")), fact("CVSS vector", evidence.get("cvss_metrics"), mono=True),
        fact("EPSS", evidence.get("epss_score")), fact("CPE", evidence.get("cpe"), mono=True),
        fact("Extracted values", f"{len(lengths)} value(s) of length {', '.join(map(str, lengths))} (values not stored)" if lengths else ""),
    )
    out: dict[str, Any] = {
        "where": facts(fact("Matched at", matched, mono=True), fact("Origin", origin_of(matched), mono=True)),
        "observed": observed,
        "reproduce": command(f"nuclei -u {q(matched)} -id {q(template)}", note="Runs the same template against the same URL.") if template else None,
        "verify": command(f"nuclei -u {q(matched)} -id {q(template)}", expect="no match") if template else None,
        "references": strings(evidence.get("template_references"), 5, 300),
        "context": [],
        "fix": [remediation] if remediation else [],
    }
    if cves:
        contexts = [cve_context(cve) for cve in cves[:3]]
        out["cves"] = contexts
        kev = next((c["known_exploited"] for c in contexts if c.get("known_exploited")), None)
        fixed = [v for c in contexts for v in c.get("fixed_in", [])]
        out.update({
            "class": "vuln.cve", "class_label": "Known vulnerability (CVE)",
            "summary": f"{matched} matched the check for {', '.join(cves)}" + (f": {description}" if description else "."),
            "expected": ["A version outside the affected range, or the vendor's fix applied."],
        })
        if kev:
            out["context"].append(f"CISA lists {cves[0]} as known exploited (added {kev.get('date_added') or 'date not recorded'})" + (", used in ransomware campaigns." if kev.get("ransomware") else "."))
        if fixed:
            out["fix"] = [f"Upgrade to a fixed release: {join_limited(fixed, 4)}."] + out["fix"]
        out["fix"].append("If you cannot upgrade now, apply the vendor's mitigation and restrict access to the affected path.")
    elif "default-login" in tags or "default-credentials" in tags:
        out.update({
            "class": "auth.default_credentials", "class_label": "Default credentials accepted",
            "summary": f"{matched} accepted a vendor default username and password ({title}).",
            "expected": ["The default account disabled or its password changed; login with the vendor default refused."],
            "context": ["Default credentials are published in vendor manuals; anyone can sign in with them, usually as an administrator."],
        })
        out["fix"] = ["Change the password of the default account (or disable it) and create named accounts.",
                      "Restrict the management interface to administrator networks."] + out["fix"]
    else:
        out.update({
            "class": f"template.{template}" if template else "template", "class_label": title or "Template match",
            "summary": description or f"{matched} matched the {template or 'scanner'} template.",
            "expected": [],
        })
    if description and out.get("class") == "auth.default_credentials":
        out["context"].insert(0, description)
    return out


def build_ai(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    family = text(evidence.get("probe_family") or evidence.get("family"), 60)
    markers = strings(evidence.get("matched_markers"), 6, 120)
    description = text(finding.get("description"), 1200)
    title = text(finding.get("title"), 200)
    return {
        "class": f"ai.{family}" if family else "ai",
        "class_label": title or "AI finding",
        "summary": description if description and description != title else f"The model's response matched the {family.replace('_', ' ') or 'probe'} check.",
        "where": facts(fact("Endpoint", finding.get("ai_target_url") or finding.get("url"), mono=True), fact("Probe", evidence.get("probe_id"), mono=True)),
        "observed": facts(fact("Judged by", text(evidence.get("judge_layer")).replace("_", " ")), fact("Matched markers", join_limited(markers, 6), mono=True),
                          fact("Turns", join_limited([str(n) for n in evidence.get("turn_indices") or () if isinstance(n, int)], 8))),
        "expected": ["A refusal or a response without the protected content."],
        "context": ["Model output varies between runs: one matched response shows the guardrail can fail, not that it always does."],
        "reproduce": command("# Use Retest (same probe) on this page: it replays the stored prompt against the same endpoint.",
                             note="The probe and the model's response are shown under Recorded evidence."),
        "fix": [],
    }


def build_generic(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    description = text(finding.get("description"), 1200)
    title = text(finding.get("title"), 300)
    url = text(finding.get("url"), 600)
    return {
        "class": "generic",
        "class_label": title or "Finding",
        "summary": description if description and description != title else "",
        "where": facts(fact("URL", url, mono=True)),
        "observed": visible_scalar_facts(evidence),
        "expected": [],
        "context": [],
        "fix": [],
    }


__all__ = [
    "build_ai", "build_generic", "build_graphql", "build_graphql_introspection", "build_takeover", "build_template",
    "cve_context",
]
