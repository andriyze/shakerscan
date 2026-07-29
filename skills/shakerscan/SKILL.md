---
name: shakerscan
description: Operate ShakerScan. Route scan requests to Web DAST, Deep Hunt requests to the keyless AI investigator, and manual browser work to Interactive Testing; also manage targets, Continuous ASM, findings, AI Gate, Model Intake, evidence, schedules, local workers, and opt-in Linux fleets.
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
| “Scan this target” with no type | Quick Web DAST (`POST /scans`, `scan_type=quick`) |
| Quick, standard, deep, full, aggressive, or smart DAST | `POST /scans` |
| Deep Hunt, autonomous hunt, or investigate autonomously | Use the `research-agent` skill and `/agent/hunt/*` |
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
| Mission timeline and read-only campaign ledger | `/timeline`, `/arsenal/campaigns*` |
| Natural-language operation preview | `/ai/ops/route` |
| Interactive browser or BOLA/IDOR workflow | Use the `ai-security-session` skill (Interactive Testing) |
| JS or frontend attack-surface analysis | Use the `js-analyze` skill |
| Content-discovery seeds | Use the `content-discovery` skill |
| Deep Hunt | Use the `research-agent` skill |
| Health, queue, and workers | `/health`, `/queue/stats`, `/workers` |
| Multi-node fleet setup or operations | Check `/workers.fleet`, then use `shakerscan fleet *`, `shakerscan join`, and `/fleet/*` only when supported/enabled |
| Exhaustive operation or schema lookup | Read `AGENTS.md` and the live `/openapi.json` |

## Apply Safety Gates

- Never scan a target without ownership or explicit authorization.
- Ask for explicit confirmation before `full`, `aggressive`, or `smart`; these modes send active
  probes.
- Deep Hunt performs AI-driven exploration and bounded active exploitation. Confirm target
  authorization, create a target-bound credential-tier approval, and let ShakerScan enforce the
  request/action ceilings. The phrase “Deep Hunt” requests the workflow but is not itself a claim
  that the user owns the target.
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

## Manage Multi-Node Fleet

Fleet is optional and Linux-hosted. Before offering remote placement or calling protected Fleet
routes, inspect the non-secret capability state:

```bash
curl -s http://localhost:8080/workers | jq '.fleet, .execution_capacity'
```

- `fleet.status=unsupported`: do not attempt initialization or join on this host. macOS can run
  standalone ShakerScan; use Linux VPSs or Linux VMs for Fleet control-plane and worker roles.
- `fleet.status=disabled`: this is a normal standalone install. Do not describe remote workers as
  unavailable or zero; Fleet does not exist yet. Use `shakerscan fleet preflight` and
  `shakerscan fleet init` only when the user asks to enable multi-node operation.
- `fleet.status=enabled`: the Fleet UI, remote counts, remote placement, and protected lifecycle APIs
  are available. Keep local `POST /workers` scaling distinct from remote `POST /fleet/scale` or
  per-node desired-state changes.

For setup, read `docs/multi-node-guide.md` before mutating the host. Run the aggregated read-only
preflight first. Treat the fleet operator token, join tokens, node credentials, connection bundles,
and private CA material as secrets. Join tokens are single-use by default; when the operator needs
one command for several machines, mint a short-lived bounded `--max-uses N` token for the exact host
count, distribute it through an approved secret channel, and revoke unused capacity immediately.

Use node-level placement, not a worker-container identity. `node_id=local` selects control-plane
workers; a Fleet UUID selects any healthy replica on that remote node. Keep automatic placement as
the default because it preserves failover.

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
- DAST, Deep Hunt, Interactive, AI Gate, Model Intake, ASM, and Manual sources
- partial results from failed scans versus complete reports

Prefer concise summaries with IDs and links. Include proof, confidence, coverage gaps, and next
actions when they affect the user's decision.

## Natural-language routing

Keep these intents distinct:

- `scan`, `quick scan` → Quick DAST by default.
- `standard scan`, `deep scan`, `full scan`, `aggressive scan`, `smart scan` → that exact DAST type.
- `deep hunt`, `autonomous hunt`, `investigate autonomously` → Deep Hunt, never DAST and never the
  legacy `/research/campaigns/launch` path.
- `verify this finding` → the bounded deterministic finding verification/retest path.
- `test manually`, `interactive testing`, `browser session` → Interactive Testing.

For Deep Hunt, use the current coding-agent session as the planner. Start
`POST /agent/hunt/{target_id}/session` with `mode:"deep_hunt"` and the approved receipt, then drive
one reply at a time only while the run is `awaiting_planner`. ShakerScan executes every tool and
remains authoritative for scope, credentials, active-tool access, evidence, and proof.

## Read Detailed References

- Read `AGENTS.md` for exact request bodies, filters, authentication options, and operational rules.
- Read `skills/ai-security-session/references/api.md` for interactive session schemas.
- Use `http://localhost:8080/openapi.json` when an API contract may have changed.
- Use the public
  `https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md` for the
  exhaustive product map. A source checkout also has it at `docs/functionality-reference.md`.
