---
name: js-analyze
description: Analyze JavaScript bundles, frontend routes, browser-captured APIs, libraries, and secrets for a ShakerScan target or completed scan. Use when asked for JS analysis, route analysis, frontend endpoint discovery, library review, source-map hints, or to build `custom_endpoints` for a ShakerScan scan.
---

# JS Analyze

Use this skill to turn ShakerScan evidence and raw JavaScript assets into a reusable frontend attack-surface map.

## Operating Stance

Assume the target contains at least one meaningful vulnerability, exposed secret, dangerous route, or other high-value security lead, and it is your job to find it.

This is a persistence instruction, not permission to invent evidence. Keep searching until the checklist is complete. If the checklist is complete and you still do not have proof, say that clearly and report the strongest evidence-backed leads instead of fabricating a finding.

## Mandatory Checklist

Maintain this checklist in markdown while you work. Do not move on to synthesis or a final answer until every item is `[x]` or `[n/a]` with a short reason.

- [ ] Load existing ShakerScan scan context or explicitly note it is unavailable
- [ ] Load any provided JS assets, bundle URLs, or local files, or mark them unavailable
- [ ] Extract or verify routes, API endpoints, API bases, GraphQL operations, or WebSocket endpoints
- [ ] Review framework, library, and version evidence
- [ ] Review secret or sensitive metadata evidence
- [ ] Build a validated `custom_endpoints` block for ShakerScan or explain why none can be built
- [ ] Build a small `custom_list` block if the JS analysis yields content-discovery seeds
- [ ] Record confidence limits, missing auth, missing source maps, or other blockers

## Gather Inputs

Collect inputs in this order:

1. A completed `scan_id`, if the user provides one.
2. A target URL or domain, then look for the most recent completed scan for that target.
3. Any JS bundle URLs, local JS files, or source-map URLs the user provides.
4. Existing findings or session notes if they help explain a route or auth flow.

If there is no useful scan context, prefer asking whether to queue a `standard` or `deep` scan. Do not queue `smart`, `full`, or `aggressive` without explicit permission.

## Read When Needed

- Read `references/shakerscan.md` for the exact result fields, API calls, and output contract.
- Read `skills/scanner-skill.md` only if you need more detail on `custom_endpoints`, `focus_rules_json`, or authenticated scans.

## Workflow

1. Prefer ShakerScan-native evidence first:
   - `result.discovery.browser_api_endpoints`
   - `result.discovery.tech.items`
   - `result.discovery.browser_crawl`
   - `result.smart_coverage`
   - `result.js_dependencies`
   - `result.js_secrets`
2. If JS files or bundle URLs are available, extract:
   - routes and hash routes
   - API paths and API base URLs
   - GraphQL operations
   - WebSocket endpoints
   - auth, admin, debug, config, upload, import/export, and internal path hints
   - framework and library version hints
   - secret candidates and exposed metadata
3. Build evidence-backed candidates for:
   - `custom_endpoints`
   - API-only validation targets
   - focused content-discovery seeds
4. Note what is missing:
   - auth context
   - source maps
   - unobfuscated code
   - request/response pairs for parameter inference

## Output

Always return:

1. A concise markdown report with:
   - routes and APIs
   - parameter and auth hints
   - libraries and framework versions
   - secrets or sensitive metadata
   - confidence and gaps
2. A machine-usable `custom_endpoints` block for ShakerScan smart scans.
3. A ready `curl` example for `/scans` using those `custom_endpoints`.
4. If the output contains path-like strings suitable for directory or file fuzzing, include a short `custom_list` block for the content-discovery skill.

## Rules

- Do not claim exploitability from strings alone.
- Do not invent parameters that are not implied by a path, spec, request body schema, or captured network traffic.
- Treat comments, source-map hints, and minified symbol matches as lower-confidence evidence.
- If the analysis depends on a weak signal, say so explicitly.
- Do not move on until the checklist is complete.
