---
name: shakerscan
description: Operate the ShakerScan web, API, and AI security platform. Use when asked to start or diagnose ShakerScan; scan an authorized website or API; manage targets, workers, schedules, findings, evidence, or Continuous ASM; test AI Gate or Model Intake targets; run interactive security sessions; or create and drive bounded research episodes and Deep Hunt campaigns.
---

# ShakerScan

Use ShakerScan through its local REST API and operational wrapper. ShakerScan owns execution,
target binding, approvals, budgets, evidence, and finding proof.

## Establish Context

1. Run from the ShakerScan runtime or source checkout.
2. Use `http://localhost:8080` for API calls executed on the ShakerScan host.
3. Set `UI_BASE` to the UI URL printed by `./scanner.sh status` and use it for user-facing links. Do
   not hardcode localhost links for a remote VPS.
4. Check health before an operation:

   ```bash
   curl -s http://localhost:8080/health
   ```

5. If the scanner is stopped, offer `./scanner.sh start`; use `./scanner.sh start --remote` only when
   the user needs remote access over Tailscale.

## Choose The Workflow

| User intent | ShakerScan surface |
|---|---|
| Quick, standard, deep, full, aggressive, or smart DAST | `POST /scans` |
| Multiple targets | `POST /scans/batch` |
| Authenticated or two-user testing | `POST /scans` with auth options |
| Targets and subdomains | `/targets`, `/domains`, `/discovery` |
| Continuous endpoint coverage | `/targets/{id}/asm/*` |
| Findings, cleanup, triage, or retest | `/findings*`, `/retests*` |
| Finding exceptions and deployment policies | `/finding-exceptions*`, `/policy-profiles*` |
| AI chat, RAG, agent, MCP, or widget testing | `/ai/targets*` |
| Model artifact intake | `/model-intake/*` |
| Schedules and safe automation defaults | `/schedules*`, `/settings/automation` |
| Evidence export or retention | `/evidence/*` |
| Mission timeline and campaigns | `/timeline`, `/arsenal/campaigns*` |
| Natural-language operation preview | `/ai/ops/route` |
| Interactive browser or BOLA/IDOR workflow | Use the `ai-security-session` skill |
| JS or frontend attack-surface analysis | Use the `js-analyze` skill |
| Content-discovery seeds | Use the `content-discovery` skill |
| Bounded adaptive investigation | Use the `research-agent` skill |
| Health, queue, and workers | `/health`, `/queue/stats`, `/workers` |
| Exhaustive operation or schema lookup | Read `AGENTS.md` and the live `/openapi.json` |

## Apply Safety Gates

- Never scan a target without ownership or explicit authorization.
- Ask for explicit confirmation before `full`, `aggressive`, or `smart`; these modes send active
  probes.
- Treat credentials, auth headers, cookies, API keys, and approval receipts as secrets. Do not echo
  them in reports.
- Production AI Gate scans require their production confirmation.
- Auth checks require a primary auth context. BOLA/IDOR requires a provably distinct second
  principal plus the applicable deep-intent and approval gates.
- Do not bypass a rejected scope, approval, risk, or budget decision.
- Do not call a finding verified from a title, status code, reflection, or model judgment alone.
  Use ShakerScan proof and retest records.

## Execute

For a normal scan:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://app.example.test","options":{"scan_type":"quick"}}'
```

After any action queues a scan, ASM job, AI Gate run, Model Intake run, or finding retest:

1. Report the returned ID and accepted/queued state.
2. Report the UI link `${UI_BASE}/scans/{scan_id}` when a scan ID exists.
3. Stop. Do not poll unless the user explicitly asks later.

For batch submissions, report `queued_count`, `failed_count`, and per-target errors. Never report the
requested count as successfully queued when the response is partial.

## Read Results

Use:

```bash
curl http://localhost:8080/scans/{scan_id}
curl http://localhost:8080/scans/{scan_id}/result
curl "http://localhost:8080/scans/{scan_id}/logs?limit=200"
curl "http://localhost:8080/findings?status=active&limit=50"
```

Keep these distinctions visible:

- reported or suspected versus exploit-verified
- completed coverage versus attempted, skipped, timed out, or stale coverage
- DAST, AI Gate, AI session, autonomous, Model Intake, ASM, and manual sources
- partial results from failed scans versus complete reports

Prefer concise summaries with IDs and links. Include proof, confidence, coverage gaps, and next
actions when they affect the user's decision.

## Research Planning

Use `planner_mode: "agent"` by default when the session was launched by
`shakerscan agent codex|claude|opencode`. Read the current immutable observation and submit exactly
one decision through `/research/episodes/{id}/decisions`.

Use `configured_ai` only when the user explicitly wants the stored provider and unattended server
autopilot. Use `local_codex` only when the user wants separate isolated Codex processes.

When a research decision queues linked work, report it and stop. Continue the episode or campaign
when the user asks again.

## Read Detailed References

- Read `AGENTS.md` for exact request bodies, filters, authentication options, and operational rules.
- Read `skills/ai-security-session/references/api.md` for interactive session schemas.
- Use `http://localhost:8080/openapi.json` when an API contract may have changed.
- In a source checkout, use `docs/functionality-reference.md` for the exhaustive product map.
