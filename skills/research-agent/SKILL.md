---
name: research-agent
description: Create and drive bounded adaptive ShakerScan research episodes. Use when asked to investigate unexplained security gaps iteratively with Codex or another agent while preserving target scope, budgets, approvals, and deterministic proof gates.
---

# Bounded Research Agent

Use ShakerScan's research episode controller for adaptive investigation. The agent chooses one action at a time; ShakerScan remains authoritative for scope, command allowlists, budgets, approvals, execution, evidence, and finding promotion.

## Choose The Planner

- **Current Codex as the brain:** create an episode through the API, then run `./scanner.sh research <episode-id> [max-decisions]`. This starts isolated, ephemeral, read-only Codex planner processes with tools disabled. Each process receives one bounded observation and returns one structured decision.
- **Configured AI provider:** call `POST /research/episodes/{id}/plan-step`. This uses the provider and model from `/settings/ai`, including OpenRouter. The UI at `/settings/research-agent` uses this path.
- **Claude or another agent as the brain:** read `GET /research/episodes/{id}`, construct exactly one decision from the current observation, and submit it to `POST /research/episodes/{id}/decisions`. Never execute the proposed operation outside ShakerScan.

## Workflow

1. Check `GET /health` and identify a registered web/API `target_id`.
2. Create a `shadow` or `read_only` episode first. Use `gated` only with valid scope and approval receipts.
3. Inspect the current immutable observation and its `proposable_commands`.
4. Select exactly one action, request operator input, or stop.
5. For an action, state a concrete `expected_signal` and `falsifier`.
6. Submit the decision to ShakerScan and use the next observation returned by the controller.
7. Stop when the objective is met, evidence falsifies the lead, the budget is exhausted, or operator input is required.

## Hard Rules

- Use only the current observation's entries with `proposable: true`.
- Copy `observation_id` and `context_hash` exactly.
- Do not supply credentials, receipt contents, confirmation flags, raw shell, code, or a different target.
- Do not claim a vulnerability is verified. Only ShakerScan proof contracts can promote findings.
- Do not bypass a rejected decision. Read its validation errors and choose a new bounded step.
- Active work requires a `gated` episode, receipts, the execution feature flag, and existing command-specific checks.

## API Skeleton

```bash
API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}

curl -X POST "$API_BASE/research/episodes" \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"TARGET_UUID","objective":"Investigate the highest-value unexplained gaps","execution_mode":"read_only","max_risk_tier":"read_only","max_steps":5}'

./scanner.sh research EPISODE_UUID 5

# Or use the configured provider used by the UI:
curl -X POST "$API_BASE/research/episodes/EPISODE_UUID/plan-step" \
  -H 'Content-Type: application/json' \
  -d '{"execute":true,"timeout_seconds":90,"max_tokens":3000}'
```

