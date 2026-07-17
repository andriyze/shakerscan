---
name: research-agent
description: Create and drive bounded adaptive ShakerScan research episodes and Deep Hunt campaigns. Use when asked to investigate an authorized target, verify one finding, close Continuous ASM gaps, continue an awaiting-planner episode, or run a multi-episode campaign while preserving target scope, budgets, approvals, and deterministic proof gates.
---

# Bounded Research Agent

Use ShakerScan's research episode controller for adaptive investigation. The agent chooses one action at a time; ShakerScan remains authoritative for scope, command allowlists, budgets, approvals, execution, evidence, and finding promotion.

Use a single episode for a bounded investigation. Use a campaign when the user explicitly wants
Deep Hunt to continue across multiple bounded episodes under shared time and episode ceilings.

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
- `experiment.http_diff` may use only relative same-origin paths and anonymous headers. Use two to four steps with the first as the control; never place credentials or receipt data in a step.
- A step may use `json_body` or `form_body`, extract a non-sensitive scalar with `extract`, and reference it in later steps as `${name}`. Use `role: verify` and `compare_to` for before/after side-effect checks.
- Use `experiment.workflow` only when managed target principals are already configured. Supply a caller-generated `workflow_id`, two to twelve typed HTTP/browser steps, principal slots, and checkpoints; never supply credential material. Cross-principal runs fail closed unless ShakerScan can prove distinct profiles and account identities.
- Workflow browser actions are limited to same-origin navigate, click, non-sensitive fill, submit, bounded wait, and scalar extract. Use `POST /experiments/workflows/{workflow_id}/cancel` to stop an active run; partial output remains unverified.
- Treat HTTP experiment differences as leads. Route them to a deterministic family verifier before describing a vulnerability as proven.

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
