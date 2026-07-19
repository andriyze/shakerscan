---
name: research-agent
description: Create and drive bounded adaptive ShakerScan research episodes, keyless session-driven ReAct deep hunts, and Deep Hunt campaigns. Use when asked to investigate an authorized target, run an autonomous/keyless deep hunt, verify one finding, close Continuous ASM gaps, continue an awaiting-planner episode, or run a multi-episode campaign while preserving target scope, budgets, approvals, and deterministic proof gates.
---

# Bounded Research Agent

Use ShakerScan's research episode controller for adaptive investigation. The agent chooses one action at a time; ShakerScan remains authoritative for scope, command allowlists, budgets, approvals, execution, evidence, and finding promotion.

Use a single episode for a bounded investigation. Use a campaign when the user explicitly wants
Deep Hunt to continue across multiple bounded episodes under shared time and episode ceilings.

## Keep The Product Terms Straight

- **Autonomous Hunt** is the UI front door under the **AI Investigator** navigation group.
- A **research episode** is one bounded observation/decision loop.
- A **Deep Hunt run/research campaign** chains bounded episodes under shared ceilings.
- `/campaigns` is a separate read-only mission-action ledger. Do not send users there to start or
  control a Deep Hunt; use `/settings/research-agent` and its run pages.

## Choose The Planner

- **Current agent session (default):** launch with `planner_mode: "agent"` and `autopilot: false`, then read the current observation and submit exactly one decision to `/research/episodes/{id}/decisions`. When `SHAKERSCAN_RESEARCH_PLANNER_MODE=agent` is present (set by `shakerscan agent codex|claude|opencode`), always use this mode unless the user explicitly asks for a stored provider or isolated local Codex. No ShakerScan AI provider configuration is required.
- **Isolated local Codex:** launch or switch with `planner_mode: "local_codex"` and run `./scanner.sh research <episode-id> [max-decisions]`. This starts separate ephemeral, read-only Codex planner processes with tools disabled. It uses the host Codex authentication, not the current conversation state.
- **Configured AI provider:** launch with `planner_mode: "configured_ai"` or call `POST /research/episodes/{id}/plan-step`. This uses the provider and model from `/settings/ai`, including OpenRouter, and is the only mode that runs unattended through server autopilot.
- **Claude or another agent as the brain:** read `GET /research/episodes/{id}`, construct exactly one decision from the current observation, and submit it to `POST /research/episodes/{id}/decisions`. Never execute the proposed operation outside ShakerScan.

## Workflow

1. Check `GET /health` and identify a registered web/API `target_id`.
2. Create a `shadow` or `read_only` episode first. Use `gated` only with valid scope and approval receipts. For Deep Hunt campaigns started by the current coding agent, set `planner_mode: "agent"`; this is also the API default.
3. Inspect the current immutable observation and its `proposable_commands`.
4. Select exactly one action, request operator input, or stop.
5. For an action, state a concrete `expected_signal` and `falsifier`.
6. Submit the decision to ShakerScan and use the next observation returned by the controller.
7. Stop when the objective is met, evidence falsifies the lead, the budget is exhausted, or operator input is required.

For a campaign launched in `agent` mode, drive the returned first episode immediately when it is
awaiting a planner. If launch queued a readiness/preflight scan, report that scan and stop as usual;
on the user's next request, find the campaign's non-terminal episode and continue it. After any
decision queues a scan or retest, report the linked work and stop rather than polling.

For a durable campaign:

1. Confirm the target, authorization, intensity, and requested time/episode ceilings.
2. Use `planner_mode: "agent"` unless the user explicitly chooses another planner.
3. Launch with `POST /research/campaigns/launch`.
4. If a readiness scan is queued, report its scan ID and stop.
5. Otherwise drive the returned awaiting-planner episode one decision at a time.
6. Use `POST /research/campaigns/{campaign_id}/control` with `pause`, `resume`, or `cancel`.

## Hard Rules

- Use only the current observation's entries with `proposable: true`.
- Copy `observation_id` and `context_hash` exactly.
- Do not supply credentials, receipt contents, confirmation flags, raw shell, code, or a different target.
- Do not claim a vulnerability is verified. Only ShakerScan proof contracts can promote findings.
- Do not bypass a rejected decision. Read its validation errors and choose a new bounded step.
- Active work requires a `gated` episode, receipts, the execution feature flag, and existing command-specific checks.
- `experiment.http_diff` may use only relative same-origin paths, anonymous headers, and
  `GET`/`HEAD`/`OPTIONS`. Use two to four steps with the first as the control; never place credentials
  or receipt data in a step.
- A step may use `json_body` or `form_body`, extract a non-sensitive scalar with `extract`, and reference it in later steps as `${name}`. Use `role: verify` and `compare_to` for before/after side-effect checks.
- Use `experiment.workflow` only when managed target principals are already configured. Supply two
  to twelve typed HTTP/browser steps, principal slots, checkpoints, and the identifiers required by
  the current projected schema; never supply credential material. Cross-principal runs fail closed
  unless ShakerScan can prove distinct profiles and account identities.
- Credential-tier Deep Hunt may expose typed `PUT`/`PATCH`/`DELETE` workflow steps only when later
  cleanup/rollback and restoration assertions are present. Do not remove those steps or weaken the
  predicates supplied by the server-selected family template.
- Workflow browser actions are limited to same-origin navigate, click, non-sensitive fill, submit, bounded wait, and scalar extract. Use `POST /experiments/workflows/{workflow_id}/cancel` to stop an active run; partial output remains unverified.
- Treat HTTP-differential results as leads. A workflow may produce a verified finding only when
  ShakerScan independently re-executes it, derives the deterministic family predicates, and passes
  the promotion gate. Never infer that outcome from planner prose or an HTTP status alone.
- A server-materialized create-based mass-assignment test can leave labeled test objects when the
  target has no discovered delete route. Use it only when the current observation/template offers
  it, and surface that cleanup limitation in the final outcome.

## API Skeleton

```bash
API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}

curl -X POST "$API_BASE/research/episodes" \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"TARGET_UUID","objective":"Investigate the highest-value unexplained gaps","execution_mode":"read_only","max_risk_tier":"read_only","max_steps":5}'

./scanner.sh research EPISODE_UUID 5

# Or use the configured provider:
curl -X POST "$API_BASE/research/episodes/EPISODE_UUID/plan-step" \
  -H 'Content-Type: application/json' \
  -d '{"execute":true,"timeout_seconds":90,"max_tokens":3000}'
```

## Keyless ReAct Deep Hunt (session-driven — the no-key autonomous path)

This is a **separate, newer engine** from the menu-planner episodes above. Instead of selecting one
`proposable` command per turn, the current agent session drives a full ReAct loop: the server seeds a
redacted context pack, suspends each turn, and the session replies with a fenced
` ```json {"tool_calls":[...]} ``` ` block; the server executes the tools and returns the next
observation. No AI provider key is required — the current Claude/Codex/OpenCode session IS the planner.
Prefer this when the user asks for an **autonomous / keyless deep hunt** to discover NET-NEW bugs DAST
missed. Findings land in the **SUSPECTED** tier only (read-only surface); the deterministic
`family_proof` **VERIFIED** moat is never touched by the loop.

### Prerequisites for an authenticated target
`as_principal` reads credentials server-side (never model-visible), so configure managed principals
+ credential profiles on the target FIRST, or the hunt runs anonymous-only:
`POST /targets/{id}/principals` bound (by name) to `POST /targets/{id}/credential-profiles`
(`auth_kind:"authorization_header"`, secret = full `Bearer <jwt>`). Tokens that expire (crAPI-style
JWTs, ~7 days) must be re-minted and rotated:
`POST /targets/{id}/credential-profiles/{profile_id}/rotate {"secret":"Bearer <jwt>"}`.

### Drive loop
1. `POST /agent/hunt/{target_id}/session {"objective":"...","max_iterations":12}` → `run_id` + first
   observation. **That first observation is a full system prompt** (tool arsenal, RECON→PLAN→EXECUTE→
   EVIDENCE→SELF-CRITIQUE cadence, exact debrief schema) — read it; the harness self-describes the
   contract each turn.
2. Reply one turn at a time with `POST /agent/hunt/session/{run_id}/reply {"reply":"```json\n{\"tool_calls\":[...]}\n```"}`.
   Tools: `http_request` (with `as_principal`), `query_kb`, `diff`, `note`, `run_tool`. Batch multiple
   `tool_calls` per turn. Each `http_request` returns a `resp_N` ref; parse responses with lenient JSON
   (bodies are control-char heavy).
3. To test access control, replay the same request as different principals and `diff` the refs.
4. Finish with a debrief turn: `{"done":true,"findings":[...],"abstained":false}`.
5. Keep calling `/reply` until `status: completed`. Inspect: `GET /agent/hunt/session/{run_id}`;
   `POST .../cancel`. Two-tier view: `GET /agent/findings/{target_id}`.

### The evidence contract (do not get this wrong)
A debrief finding proves itself ONLY via **`evidence_refs`** — the `resp_N` refs from prior
`http_request` calls. The server resolves them into tool-output evidence for the provenance gate.
**Inline `evidence`/`details` prose is NOT evidence; a prose-only finding fails the gate and is
silently dropped (nothing persists).** Finding shape:
`{"title","severity","family","predicate","route","method","cwe","details","evidence_refs":["resp_1"],"remediation"}`.

### What "auto mode" means here
Keyless = the coding-agent session drives each turn in a loop (it must keep replying). There is **no
fully hands-off keyless mode**. For unattended server autopilot use `planner_mode:"configured_ai"`
(needs a key in `/settings/ai`) or a `configured_ai` `agent_loop` deep-hunt campaign. Writes/active
scanners still require a `gated` episode with an approval receipt; the SUSPECTED→VERIFIED promotion
only ever happens through the server's `family_proof` re-execution, never from planner prose.

```bash
# Start + one recon turn + debrief (read-only, SUSPECTED tier)
curl -X POST "$API_BASE/agent/hunt/TARGET_UUID/session" -H 'Content-Type: application/json' \
  -d '{"objective":"Find a net-new access-control or data-exposure bug DAST missed and prove it","max_iterations":12}'
curl -X POST "$API_BASE/agent/hunt/session/RUN_UUID/reply" -H 'Content-Type: application/json' \
  -d '{"reply":"```json\n{\"tool_calls\":[{\"name\":\"http_request\",\"arguments\":{\"method\":\"GET\",\"path\":\"/api/feed\",\"as_principal\":\"user1\"}}]}\n```"}'
curl -X POST "$API_BASE/agent/hunt/session/RUN_UUID/reply" -H 'Content-Type: application/json' \
  -d '{"reply":"```json\n{\"done\":true,\"findings\":[{\"title\":\"...\",\"severity\":\"medium\",\"family\":\"data_exposure\",\"evidence_refs\":[\"resp_1\"]}],\"abstained\":false}\n```"}'
```
