# ShakerScan walkthrough

This guide follows the current first-run flow through an AI coding agent and the web UI. It uses
text and live routes so it does not drift with historical screenshots.

## 1. Install and open ShakerScan

```bash
curl -fsSL https://install.shakerscan.com | sh
```

The installer starts the Docker stack on local interfaces. Open:

- UI: [http://localhost:3000](http://localhost:3000)
- API health: [http://localhost:8080/health](http://localhost:8080/health)

For remote access over Tailscale, use:

```bash
shakerscan start --remote
shakerscan status
```

Use the browser URLs printed by `status`; API commands running on the ShakerScan host still use
`http://localhost:8080`.

## 2. Start an agent in the runtime

```bash
shakerscan agent codex
# or: shakerscan agent claude
# or: shakerscan agent opencode
```

Starting inside `~/.shakerscan` lets the agent load AGENTS, CLAUDE, and the task-specific skills.
Try:

```text
Check whether ShakerScan is healthy.
Run a quick scan on https://app.example.test.
Show active critical and high findings.
```

The agent checks health, submits work through ShakerScan, reports the returned ID and UI link, and
stops instead of waiting for a long-running scan.

## 3. Run a first scan in the UI

1. Open **New Scan**.
2. Enter a target you own or are explicitly authorized to test.
3. Choose **Quick** for DNS, TLS, headers, and basic posture.
4. Keep the default Balanced coverage budget.
5. Submit and open the returned Scan Detail page.

Scan Detail shows progress, current phase, logs, partial-result warnings, coverage, findings, proof
state, deployment decision, and the final report.

Full, Aggressive, and Smart modes send active probes. Confirm authorization with the agent before it
submits one, and follow the warnings in the UI. Do not use active modes on third-party systems
without explicit permission.

## 4. Review and verify findings

Open **Findings** to filter by source, severity, status, target, verification mode, or last-seen
window. Finding Detail separates the reported issue from its evidence and verification history.

Use:

- **Retest** to queue deterministic verification with optional AI escalation;
- **Evidence** to inspect durable evidence objects and content-free exports;
- status actions for resolved, false-positive, or accepted-risk triage;
- **Verify finding** for a bounded deterministic proof attempt on an authorized, target-linked web finding.

A title, HTTP 200, reflection, or model opinion is not proof. Look for the server-derived proof state,
deterministic replay, principal/control comparison, and linked evidence.

## 5. Choose the next workflow

| Goal | UI area |
|---|---|
| Maintain endpoint inventory and close coverage gaps | **Continuous ASM** |
| Review assets, relationships, and attack paths | **Exposure** |
| Test chat, RAG, agent, widget, or MCP endpoints | **AI Gate** (preview) |
| Check a model artifact before deployment | **Model Intake** (preview) |
| Reproduce browser/auth workflows manually | **Interactive Testing** |
| Review evidence cleanup or exports | **Evidence** |
| Follow scans, scheduled work, investigations, and exports | **Timeline** |
| Start an AI-driven investigation with bounded active testing | **Hunt** |
| Preview a natural-language operation without executing it | **AI Operations Router** |

The **Campaigns** page is a read-only mission-action ledger. Start an investigation from **Hunt**,
then continue its keyless turn loop from the coding-agent session. The UI shows the current
transcript, evidence-backed suspected findings, and deterministic verification results. Gated
execution is enabled in standard installs, so no extra server setting or stored LLM key is needed;
the target authorization and expiring approval prompts still apply.

## 6. Useful agent requests

```text
Show ShakerScan status and use the correct remote UI URL.
Run a standard scan on my authorized staging application.
Explain the proof and coverage gaps for scan <id>.
Show active Hunt findings for this target.
What should Continuous ASM test next?
Run Hunt on this authorized registered target.
Check this model artifact without executing it.
```

See the [README](README.md) for installation, workflow selection, CLI, and troubleshooting. The
[Functionality Reference](docs/functionality-reference.md#16-ui-cli-skills-and-agent-surfaces)
contains the exhaustive UI/API/CLI/skill map.
