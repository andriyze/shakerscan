# AGENTS.md — ShakerScan agent operating guide

ShakerScan is an open-source application-security platform operated through deterministic
**Scans** and agent-driven **Hunts**. This always-loaded file contains policy and judgment, not an
API catalogue.

## Authoritative references

Use the smallest source that answers the question:

- **This file:** architectural invariants, safety gates, workflow decisions, and interpretation.
- **Live API:** `GET /openapi.json`, `GET /scan/contracts`, and `GET /hunts/contract` for current
  schemas, limits, enum values, and routes.
- **Generated catalogue:** `docs/functionality-reference.md` in a source checkout, or the
  [public functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md),
  for exhaustive UI, API, CLI, registry, skill, adapter, and durable-state coverage.
- **Operator help:** `README.md`, the UI at `/docs`, and `shakerscan --help`.

Do not copy large API schemas or endpoint catalogues back into this file. When documentation and
the live contract disagree about mechanics, verify code/OpenAPI and fix the stale document. This
file remains authoritative for safety and judgment rules that schemas cannot express.

## AI-native architecture invariants

ShakerScan has one deterministic Scan and one AI-driven Hunt. Preserve these boundaries:

1. Do not add a DAST scan type. Resource presets define ceilings; active testing is permission,
   not scan identity.
2. Do not add target-specific Hunt engines. Target kind filters the shared Hunt runtime.
3. Do not expose arbitrary shell commands or planner-supplied argv as capabilities.
4. Every network action uses runtime target binding and scope/destination validation.
5. Every executable capability has one canonical registry entry declaring risk, budgets,
   placement, parser/output schema, and evidence contract.
6. Reserve multidimensional budget before execution and reconcile actual use afterward.
7. AI may create notes, observations, and evidence-backed candidates; only deterministic proof
   contracts may mark findings verified.
8. Adaptive strategy belongs in Hunt skills or the external planner. Safety, protocol, evidence,
   and correctness stay server-side.
9. Preserve trustworthy partial output on timeout. Cancellation is distinct and stops execution.
10. Reuse core concepts instead of adding parallel registries, ledgers, scope paths, candidate
    models, proof paths, or orchestration engines.

## Environment and startup

The local stack normally exposes UI at `http://localhost:3000` and API at
`http://localhost:8080`, backed by PostgreSQL, Redis, DAST workers, and optional specialized
workers. Check the launcher before assuming those URLs:

```bash
./scanner.sh status
curl -sS http://localhost:8080/health
```

If stopped, use `./scanner.sh start`. Use `./scanner.sh start --remote` for a VPS reached over
Tailscale and then use its printed URLs. Without Tailscale, public binding is acceptable only behind
a firewall, VPN, or reverse proxy with exact browser origins in the CORS allowlist.

After a curl install, run agents from the installed runtime so this guide and shipped skills exist:

```bash
shakerscan agent codex       # or claude, or opencode
# equivalent: cd ~/.shakerscan && codex
```

If the launcher is not yet on `PATH`, use `~/.local/bin/shakerscan`. Never invent removed wrapper
commands; inspect `shakerscan --help` or `./scanner.sh help`.

## Default agent behavior

- Inspect before mutating. Use the API for product operations and the launcher for lifecycle work.
- Stay within the targets, systems, and people the user placed in scope.
- Ask for authorization before active, state-changing, network-discovery, device, or otherwise
  intrusive testing unless explicit target-specific authorization already exists.
- Never infer that a public hostname is authorized merely because it is reachable.
- Do not turn an audit into a scan, Hunt, cleanup, or external message without authorization.
- Use current server contracts instead of client-side copies of families or ceilings.
- Preserve unrelated worktree changes and use non-destructive repository operations.

### Submission terminal condition

After submitting any Scan, device scan, AI Gate run, Model Intake scan, discovery run, or queued ASM
action, report its ID and browser-facing UI link, then stop. Do **not** poll or wait unless the user
explicitly asks to monitor or check later. Jobs may take minutes or hours.

For batches, report `queued_count`, `failed_count`, and per-target errors. Never claim the requested
count was queued; `status: partial` means only some submissions succeeded.

## Authorization, authority, and secrets

- Active testing requires persisted policy permission and, where required, a current target-bound
  approval receipt. A UI checkbox or planner statement cannot replace server checks.
- State-changing HTTP, direct-origin access, OOB callbacks, network discovery, and device-fragility
  spend are independent permissions and budget dimensions.
- Known endpoints, imported traffic, skills, methodologies, and prior evidence never expand scope.
- High-risk BOLA/IDOR requires explicit active/deep intent and two distinct principals.
- A passive methodology does not fence a Hunt. Persisted policy and the capability manifest do.

Reusable secrets belong only in encrypted exact-target profiles or request collections:

- Scan and Hunt requests carry opaque profile/selection IDs, never tokens, cookies, passwords,
  private keys, client secrets, secret headers, or raw environment values.
- Workers decrypt only after target, capability, approval, version, expiry, and policy validation.
- APIs, planner context, logs, and receipts remain metadata-only or redacted unless the user
  deliberately requests a raw sensitive export.
- Primary, secondary, service, and SSH slots are distinct. BOLA needs distinct principals.
- `basic_auth`, `form_login`, and `oauth_password` may contain only username or only secret; at
  least one is required. Execution decides whether the target flow can use it.
- Never use the deprecated raw-auth compatibility bridge for new work.

## Deterministic Scan

There is one Scan. `fast`, `balanced`, and `thorough` select hard ceilings; they are not identities.
Historical rows may display `quick`, `standard`, `deep`, `full`, `aggressive`, or `smart`, but new
work must not submit legacy `scan_type` or call removed `scan-full`/`scan-smart` shims.

Read `GET /scan/contracts` before presenting advanced options. Advanced values may only lower the
selected profile ceiling. Zero is meaningful only for contract-declared zeroable dimensions.
Family selection narrows capabilities; it cannot grant authority.

Known endpoints seed discovery without expanding scope. Preserve body-spec syntax such as
`POST /api/search json:{"query":"test"}` so bodies never become part of the URL. Saved request
collections are immutable selections supplied by opaque ID.

```bash
curl -sS -X POST "$API_BASE/scans" -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com","budget_profile":"balanced","policy":{"active_testing":false}}'
```

For active work, first establish explicit authorization and provide the policy plus any required
target-bound approval. Never silently upgrade a passive request.

### Build freshness and repeatability

Never measure DAST quality on a stale fleet. Check `GET /workers`: fingerprints are authoritative,
`build_current` must be true, stale count zero, and the expected denominator present. Rebuild before
validation and use `require_current_workers: true` for quality gates.

For repeatable scorecards, use one Scan with the benchmark's fixed V2 policy and budget. Parallel
coverage is a compound workload, not another scan type.

```bash
python3 scripts/benchmark_targets.py juice_shop --auth --submit-only
python3 scripts/benchmark_targets.py juice_shop --scan-id <scan-id>
```

Fixtures are `juice_shop`, `crapi`, and `honey`. Verified BOLA requires persisted distinct-principal
evidence and successful owner/attacker responses; a finding label cannot pass it.

### HTTP transaction archives

DAST calls live at `/scans/{id}/http-transactions`; Hunt calls at
`/hunts/{id}/http-transactions`. Redacted ShakerScan JSON is the normal portable export. HAR is raw
sensitive traffic: label it clearly and require explicit confirmation before exposure/download.
Never imply historical capture is complete when it was partial or introduced after the run.

## Scoring and interpretation

Current reports use `risk_and_assurance/v8` with independent axes:

- **Observed risk:** `risk_score` (0–100, higher is better) and `risk_grade` (A–F) summarize only
  deterministic evidence observed. Compatibility `score`/`grade` mirror this axis.
- **Assurance:** `assurance_score` and `assurance_band`
  (`none|weak|limited|adequate|strong`) describe examination strength, breadth, principals,
  placement, required work, and proof attempts. It is not blended into risk.
- **Assessment:** `risk_assessment_state=not_examined` or `application_observed=false` means the
  application was not reached. Never present its number as a clean bill of health.
- **Reliability:** `grade_reliable=false`, reliability reasons, and `assurance_gaps` qualify the
  grade. Completed execution can still provide weak or unauthenticated coverage.

Lead with the evidence-based conclusion, then observed risk, then examination strength. A shallow
clean run should read “No material vulnerability confirmed; limited examination—not a clean bill
of health,” not an unlabeled perfect score.

Posture deductions apply only when application responses established posture. DNS, TLS, HTTP,
discovery, CSP, headers, technology, and attack chains are evidence, not scan types. Attack chains
are offline correlations, never proof of new network execution; partial chains remain partial.

ASM coverage is independent of DAST risk. Its inventory is an informational worklist; imported or
scanner-generated candidates are not confirmed routes without response/reachability evidence.
Never score WHOIS, DNS neighbors, reverse-IP data, hosting metadata, or target intelligence.

## Findings, evidence, and proof

Severities are `critical`, `high`, `medium`, `low`, and `info`. Triage states are `active`,
`resolved`, `false_positive`, and `accepted_risk`; none creates technical proof.

- Render server `proof_state`/verification fields verbatim; do not create another proof predicate.
- Confidence, AI judgment, labels, or successful HTTP status are not deterministic proof.
- AI may create candidates/notes; only deterministic proof promotes verified findings.
- Hunt may create/update/delete only its own evidence-linked unverified findings, citing same-Hunt
  completed/partial evidence. It cannot set proof, verification, target, raw request/response, or
  ownership fields, or modify findings with verification history.
- Finding lists may omit heavy fields. Respect `details_included` and `omitted_detail_fields`.
- Do not reinterpret inconclusive retests as fixed or verified.

Evidence retention cleanup is destructive and interactive-only. It starts with a target-scoped
dry-run preview, binds an immutable snapshot, uses a one-use dangerous approval for that preview,
revalidates under lock, and remains idempotent. Never schedule deletion or bypass preview/approval.

## Hunt workflow

Hunt is one target-kind-aware runtime. The current coding-agent session plans; ShakerScan owns
target binding, scope, policy, approval, budget, capability execution, evidence, and proof. A Hunt
does not investigate in the background unless an external planner actively drives it.

Start from `GET /hunts/contract`. Invoke only capabilities returned in the run manifest through
`POST /hunts/{id}/capabilities/{name}`. Never supply argv or use a shell escape.

### Progressive methodologies

The 31 web methodologies live under `skills/web/`; `skills/web/README.md` is the compact catalogue.
Do not preload them all or spend the context window on an index dump.

1. Start with no methodology.
2. When objective/stack evidence exists, call `/hunts/{id}/skills/suggestions` with concise signals.
3. Consider at most three metadata-only suggestions.
4. Read exactly one relevant methodology through `/skills/{skill_id}/read`.
5. Bind only when used and record usage/completion/deferral.

These are descriptive context controls. They never grant, remove, narrow, widen, or resize scope,
capabilities, policy, approval, or budget. Binding validates that all required capabilities already
survived policy filtering; missing requirements reject it. Do not claim a passive methodology
fences an otherwise broader run.

### Context, accounting, and completion

Use `/hunts/{id}/query` for compact prior evidence before spending traffic. Prefer falsification and
existing evidence. Artifact/JavaScript inspection uses bounded capabilities, not raw execution.

Count attempted, admitted/executed, successful, rejected, and indeterminate actions separately. A
missing/malformed result is not success. Report settled actual usage separately from ceilings.

Budget exhaustion must still preserve the final debrief, unresolved leads, and reason. Cancellation
is distinct. `GET /hunts` is durable searchable history; `/hunts/{id}/record` exports the explicit
decision record and debrief, never hidden chain-of-thought. Requests-only export stays separate.

## Product boundaries

### Targets and cohorts

Targets are exact assets. Cohorts (`production`, `staging`, `lab`, `demo`, `calibration`, `internal`,
`unclassified`) organize views; they never change results or grant authority. Model artifacts and
devices do not belong in web target metrics.

### Connected devices

Devices use separate inventory/workers. Confirm ownership/authorization. All-TCP examination is
possible, so silence is inconclusive and receives no score. Imported Postman/HAR/OpenAPI never
executes scripts, external references, or arbitrary destinations; requests stay pinned to observed
origins. Untrusted HTTPS may be observed, but secrets require explicit risk authorization.

SSH plans are immutable and inert until the user separately confirms exact commands. Device Hunt
uses the shared runtime; do not revive retired device-agent writes. Capacity is opt-in through
`./scanner.sh devices start|stop|status|logs` and must not consume ordinary DAST slots silently.

### Continuous ASM

Prefer recommendations from `/targets/{id}/asm/gaps` or `/asm/improve`; do not invent campaign
logic or duplicate pending/running work. Auth checks need primary credentials. BOLA needs deep
intent and two identities. Stale, partial, auth-blocked, rate-limited, and error attempts are not
current completed coverage. Distinguish routes, variants, attempts, fresh examination, historical
completion, and proof-bearing variants.

### AI Gate

AI Gate tests chat, RAG, agent-trace, and MCP surfaces. It is preview: deterministic real-stack
smoke exists, while planned policy/exception and deterministic-judge seams are not automatically
release-gated. Production targets require explicit confirmation. AI judgment enriches but cannot
replace proof.

### Model Intake

Model Intake owns model repositories/artifacts; never create web Targets for them or mix them into
DAST/ASM. Core API/workers must not import publisher code. Strict profiles fail closed without
authoritative acquisition, trust, required scanners, or runtime evidence.

The Firecracker runner is opt-in host infrastructure requiring possible root mutation and large
downloads. Agents must not install it or route installation through API/Docker. `UNSUPPORTED_HOST`
and `NOT_READY` differ and both fail closed.

Use `make e2e-model-intake` for the real path and `make e2e-model-intake-fixture` only when external
network is intentionally unavailable. Truncation is `known_unverified_truncated`, never verified or
a false hash mismatch.

## Compatibility boundaries

- Removed `/interactive`, `/exceptions`, and `/settings/ai-ops-router` UI pages retain APIs only
  because Command Arsenal consumes them; do not present them as primary products.
- Historical `/agent/hunt/*`, `/device-agent/*`, `/research/*`, and `/deep-hunt/*` may be readable
  or redirect. New investigations use `/hunts`.
- Deprecated writes fail closed and never advertise arbitrary tool execution.
- Evidence cleanup stays interactive; legacy retention schedules remain disabled.
- Old scan labels are display history, not new-submission guidance.

## Fleet and deployment

Managed Fleet is Linux-only and opt-in. Check the non-secret `fleet` object from `/health` or
`/workers` before offering placement. Standalone/macOS must not display unavailable controls. The
supported production transport is outbound-only HTTPS broker; WireGuard is preview.

Remote lifecycle actions use explicit operator credentials retained only for the browser session.
Do not claim physical acceptance without the content-free multi-node fault/reclaim receipt.

## Development and verification

- Search with `rg`/`rg --files`; edit with `apply_patch`.
- Preserve user changes and avoid destructive Git commands.
- Generate public contracts from the app instead of hand-copying them.
- Add behavioral tests that fail without the fix; source-string assertions alone are insufficient.
- Do not weaken a gate to make it pass. Fix code or deliberately update characterized contracts.

`scripts/check_module_size.py` is blocking in CI. Extract cohesive modules rather than raising
ratchets. Run API/capability inventory checks when routes, registries, skills, CLI, or types change.

### Rebuild semantics

UI, API, scanner, and workers share one release identity. Use `./scanner.sh rebuild`; do not bypass
launcher trust with raw compose. UI-only changes can retain cached heavy layers even when services
are recreated to publish one coherent identity.

After rebuild verify readiness, revision/fingerprint, current workers, specialized pools, restart
counts, migration/crash logs, and the affected workflow through API and UI.

```bash
make test
npm --prefix ui test
python3 scripts/check_module_size.py
python3 scripts/generate_capability_inventory.py --check
```

Use proportional release/E2E gates. Do not launch external acceptance scans without authorization.
Unit tests do not replace migration, live API, and UI verification when those surfaces changed.

## Minimal command reference

Set `API_BASE` and `UI_BASE` from `./scanner.sh status`. Use OpenAPI for bodies not shown here.

```bash
./scanner.sh start
./scanner.sh status
./scanner.sh logs -f
./scanner.sh rebuild
./scanner.sh restart
./scanner.sh scan https://example.com --budget-profile balanced

curl -sS "$API_BASE/openapi.json"
curl -sS "$API_BASE/scan/contracts"
curl -sS "$API_BASE/hunts/contract"
curl -sS "$API_BASE/workers"
curl -sS "$API_BASE/scans?limit=10"
curl -sS "$API_BASE/findings?status=active&limit=50"
```

The normal scan list hides shards, internal ASM rows, and Model Intake evidence scans. Include them
only for debugging/evidence selection via OpenAPI flags. Use `/scans/{id}` and `/result` for current
results, bounded logs for raw activity, and canonical cancel routes only for pending/running work.

That is the intentional limit of this quick reference. Discover all other operations from the live
contract or generated catalogue instead of expanding this always-loaded file.
