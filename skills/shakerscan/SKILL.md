---
name: shakerscan
description: Operate ShakerScan. Route deterministic assessment to one budgeted Scan, adaptive investigation of web or device targets to Hunt, and manual browser work to Interactive Testing; also manage targets, Continuous ASM, findings, AI Gate, Model Intake, evidence, schedules, workers, and fleets.
---

# ShakerScan

Use ShakerScan through its local REST API and operational wrapper. ShakerScan owns execution,
target binding, approvals, budgets, evidence, and finding proof.

## Establish Context

1. Run from the ShakerScan runtime or source checkout.
2. Use `http://localhost:8080` for a loopback-bound install. If `./scanner.sh status` reports a
   Tailscale or other host-published API URL, use that URL even for commands executed on the host;
   remote mode may not publish the API on `127.0.0.1`.
3. Set `UI_BASE` to the UI URL printed by `./scanner.sh status` and use it for user-facing links. Do
   not hardcode localhost links for a remote VPS.
   Set `API_BASE` to the API URL from the same status output.
4. Check health before an operation:

   ```bash
   curl -s "$API_BASE/health"
   ```

5. If the scanner is stopped, offer `./scanner.sh start`; use `./scanner.sh start --remote` only when
   the user needs remote access over Tailscale.

## Choose The Workflow

| User intent | ShakerScan surface |
|---|---|
| “Scan this target” | `POST /scans` with budget and policy; no scan type |
| Legacy quick/standard/deep/full/aggressive/smart request | Map to Scan V2 and surface the deprecation warning |
| Hunt, autonomous investigation, web or device security hunt | Use the `hunt` skill and `/hunts/*` |
| Explain, compare, or triage a connected device without traffic | Use the `device-triage` skill |
| Multiple targets | `POST /scans/batch` |
| Authenticated or two-user testing | `POST /scans` with auth options |
| Targets and subdomains | `/targets`, `/domains`, `/discovery` |
| Continuous endpoint coverage | `/targets/{id}/asm/*` |
| Connected-device inventory, policy, credentials, and posture | `/devices*`, `/device-policies*` |
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
| Health, queue, and workers | `/health`, `/queue/stats`, `/workers` |
| Multi-node fleet setup or operations | Check `/workers.fleet`, then use `shakerscan fleet *`, `shakerscan join`, and `/fleet/*` only when supported/enabled |
| Exhaustive operation or schema lookup | Read `AGENTS.md` and the live `/openapi.json` |

Web Scan and Hunt use one durable target per host. Different HTTP(S) schemes and ports share
findings, inventory, credentials, and history, while each scan or hunt keeps its exact concrete
origin. Model Intake artifacts remain exact-subject targets.

## Apply Safety Gates

- Never scan a target without ownership or explicit authorization.
- Active Scan policy and active Hunt capabilities require explicit target authorization. A larger
  budget changes ceilings only; it does not grant active permission.
- Hunt is one target-kind-aware workflow. Confirm authorization for the exact web or device target;
  keep immutable scope, worker-only credentials, device fragility/circuit-breaker controls, and
  separately confirmed SSH plans intact.
- Treat credentials, auth headers, cookies, API keys, and approval receipts as secrets. Do not echo
  them in reports.
- Production AI Gate scans require their production confirmation.
- Auth checks require a primary auth context. BOLA/IDOR requires a provably distinct second
  principal plus the applicable deep-intent and approval gates.
- Do not bypass a rejected scope, approval, risk, or budget decision.
- Do not call a finding verified from a title, status code, reflection, or model judgment alone.
  Use ShakerScan proof and retest records.
- Keep Model Intake preflight and admission structurally distinct. `POST /model-intake/scan` is always
  non-deployable technical preflight. When the user asks whether a model may enter a corporate supply
  chain, use the controlled `/model-intake/submissions/*` workflow and read
  `skills/shakerscan/references/model-intake.md` before acting.
- Never replace unavailable Firecracker/KVM execution with the semantic container sandbox, QEMU, Docker,
  or an agent claim. Report `NOT_READY`/`INCOMPLETE`. The optional Model Intake coding-agent loop is
  advisory only and cannot approve, freeze evidence, change policy, sign, promote, or suppress a non-pass.
- Connected-device scans are a separate namespace. Require exact-device authorization; never guess
  credentials, discover a whole LAN, or route Device findings through Web DAST replay. Use encrypted
  device credential profiles only with `authenticated_active`; the planner never receives secrets.

## Execute

For a normal scan:

```bash
curl -X POST "$API_BASE/scans" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://app.example.test","budget_profile":"balanced","policy":{"active_testing":false}}'
```

After any action queues a scan, ASM job, AI Gate run, Model Intake run, or finding retest:

1. Report the returned ID and accepted/queued state.
2. Report the UI link `${UI_BASE}/scans/{scan_id}` when a scan ID exists.
3. Stop. Do not poll unless the user explicitly asks later.

For batch submissions, report `queued_count`, `failed_count`, and per-target errors. Never report the
requested count as successfully queued when the response is partial.

### Model Intake routing

- “Inspect/scan this model” means provider-neutral technical preflight unless the user explicitly asks for
  corporate admission or deployment approval.
- For the ordinary one-link request, call `/model-intake/resolve` with the pasted reference, take the
  server-returned `scan_payload`, and queue it with complete artifact acquisition, complete repository
  snapshot, generated scanners, and dynamic sandbox enabled. Do not ask the user to choose an artifact file
  when the resolver already selected one. Report unavailable runtime/signing/evaluation controls as gaps.
- “Can we use/admit/approve/deploy this model?” means the authenticated controlled workflow: submission,
  completed static scan binding, exact-subject Firecracker evidence, frozen evidence, separated human
  approvals, deterministic policy, and isolated signer promotion.
- For a complete review, inspect the License BOM and Third-Party Notices draft as well as the SBOM/AIBOM.
  Trivy is the sole external license scanner. Unknown, custom, reciprocal, dataset-related, conflicting, or
  use-case-dependent terms remain `LEGAL REVIEW REQUIRED` until a distinct legal reviewer approves the latest
  frozen evidence; never translate `NO LEGAL BLOCKER DETECTED` into legal approval.
- Inspect `/model-intake/scanners/readiness` and `/model-intake/runners/readiness` before promising coverage.
  Missing required tools or physical KVM is a non-pass, not a reason to omit the control.
- The Firecracker microVM tier is **opt-in and not installed by default**, so `NOT_READY` on a KVM-capable
  host usually means "never installed", not "broken". Check `./scanner.sh model-intake-runner status` or
  `/model-intake/runners/install-plan`, then hand the operator the exact returned command. Production uses
  `sudo ./scanner.sh model-intake-runner install --signer kms:<key-id> --confirm`; local PEM is limited to
  development/test/staging. The command verifies the staged kernel/rootfs, refreshes the service and API,
  and registers the purpose-scoped runner trust anchor. Installing takes root on the host: never run it
  yourself, and never route it through the API or the Docker socket.
- Named model examples are conformance cases, never allowlist branches. Resolve any supported
  Hugging Face/HTTP/cloud/OCI/MLflow source through the same format- and fact-selected controls.
- After queueing a preflight scan or runner job, report its ID and stop unless the user explicitly asked to
  monitor or complete an end-to-end admission run.
- Read `skills/shakerscan/references/model-intake.md` for exact endpoints, authority boundaries, bounded
  planner actions, telemetry fields, stop conditions, and the passed/failed/not-run report contract.

## Manage Multi-Node Fleet

Fleet is optional and Linux-hosted. Before offering remote placement or calling protected Fleet
routes, inspect the non-secret capability state:

```bash
curl -s "$API_BASE/workers" | jq '.fleet, .execution_capacity'
```

- `fleet.status=unsupported`: do not attempt initialization or join on this host. macOS can run
  standalone ShakerScan; use Linux VPSs or Linux VMs for Fleet control-plane and worker roles.
- `fleet.status=disabled`: this is a normal standalone install. Do not describe remote workers as
  unavailable or zero; Fleet does not exist yet. Use `shakerscan fleet preflight` and
  `shakerscan fleet init` only when the user asks to enable multi-node operation.
- `fleet.status=enabled`: the Fleet UI, remote counts, remote placement, and protected lifecycle APIs
  are available. Keep local `POST /workers` scaling distinct from remote `POST /fleet/scale` or
  per-node desired-state changes.

For setup, read the public
[Multi-Node Fleet Guide](https://github.com/andriyze/shakerscan/blob/main/docs/multi-node-guide.md)
before mutating the host (a source checkout also has it at `docs/multi-node-guide.md`). Run the
aggregated read-only preflight first. Treat the fleet operator token, join tokens, node credentials, connection bundles,
and private CA material as secrets. Join tokens are single-use by default; when the operator needs
one command for several machines, mint a short-lived bounded `--max-uses N` token for the exact host
count, distribute it through an approved secret channel, and revoke unused capacity immediately.
Host-side `shakerscan fleet` commands resolve the API bind persisted by `scanner.sh`; do not force
loopback after a Tailscale-only `--remote` start unless the operator explicitly overrides
`--local-api`.

For the 0.8.17 release boundary, initialize and join production fleets with `--network broker` and
`--transport broker`. The outbound-only HTTPS broker transport has passed physical multi-host
acceptance. WireGuard fleet transport is implemented preview code but is not a supported 0.8.17
production topology; do not present it as release-accepted until its separate physical matrix passes.

Use node-level placement, not a worker-container identity. `node_id=local` selects control-plane
workers; a Fleet UUID selects any healthy replica on that remote node. Keep automatic placement as
the default because it preserves failover. A verified `shakerscan-fleet-local:*` node remains
schedulable for development but must continue to report image drift and `local_build_active=true`;
never use it as production-current or benchmark evidence. For worker-host logs, use the per-node
Compose project derived from the first eight characters of `.shakerscan-fleet/node/state.json`'s
`node_id`, as shown in the guide; plain `docker compose logs` may select an unrelated standalone
project on the same host.

## Read Results

Use:

```bash
curl "$API_BASE/scans/{scan_id}"
curl "$API_BASE/scans/{scan_id}/result"
curl "$API_BASE/scans/{scan_id}/logs?limit=200"
curl "$API_BASE/findings?status=active&limit=50"
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

- `scan` → Scan V2. Choose a resource budget and explicit active-testing permission.
- legacy scan-type wording → the equivalent V2 budget/policy with a deprecation warning; never Hunt.
- `hunt`, `deep hunt`, `device hunt`, `autonomous hunt`, `investigate autonomously` → Hunt V2,
  never Scan and never the legacy `/research/campaigns/launch` path.
- `verify this finding` → the bounded deterministic finding verification/retest path.
- `test manually`, `interactive testing`, `browser session` → Interactive Testing.
- `investigate/hunt this TV, camera, printer, router, or device` → Hunt with the registered device
  target; target-kind policy preserves device-specific safety.
- `explain/triage/compare this device` → `device-triage` unless the user explicitly authorizes new traffic.

For Hunt, use the current coding-agent session as planner and the `hunt` skill. Start `POST /hunts`,
then query context, call only returned capabilities, record evidence-backed candidates, and request
deterministic verification through the same API. ShakerScan remains authoritative for scope,
credentials, active authority, budgets, evidence, and proof.

## Read Detailed References

- Read `AGENTS.md` for exact request bodies, filters, authentication options, and operational rules.
- Read `skills/ai-security-session/references/api.md` for interactive session schemas.
- Read `skills/shakerscan/references/model-intake.md` before corporate Model Intake admission, Firecracker,
  conversion, or Codex-guided Model Intake operations.
- Use `$API_BASE/openapi.json` when an API contract may have changed.
- Use the public
  `https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md` for the
  exhaustive product map. A source checkout also has it at `docs/functionality-reference.md`.
