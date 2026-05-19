# AI Red-Teaming and Model Intake - Engineering Onboarding

This is the onboarding reference for the AI-security parts of ShakerScan:

- **AI Gate**: red-team style testing for AI application surfaces such as chat APIs, RAG endpoints, agent traces, MCP traces, and browser widgets.
- **Model Intake**: static model artifact and governance checks before a model is approved for deployment.

The goal of this document is to help a new engineer understand what exists, how users are expected to use it, how the implementation fits together, and where the current system still falls short.

ShakerScan is still a generic DAST and AI security tool. Honey is only a demo/lab companion. Normal users should be able to scan their own AI targets and model artifacts without knowing Honey exists.

---

## 1. Product Map

ShakerScan has three major product areas:

1. **DAST**: classic web application and API scanning.
2. **AI Gate**: live testing of AI application behavior and AI control evidence.
3. **Model Intake**: model artifact and model supply-chain review.

AI Gate and Model Intake reuse the same core scan plumbing as DAST:

- A row is created in `scans`.
- A Redis job is queued.
- A worker dispatches the scan by `options.run_kind`.
- Results and findings are persisted.
- The regular scan detail and findings UI render the output.

Important `run_kind` values:

| Run kind | Product | Engine |
|---|---|---|
| `ai_api` | AI Gate chat/API target | `run_ai_target_scan` |
| `ai_rag` | AI Gate RAG target | `run_ai_target_scan` |
| `ai_trace` | AI Gate agent trace target | `run_ai_target_scan` |
| `ai_mcp` | AI Gate MCP trace target | `run_ai_target_scan` |
| `ai_widget` | AI Gate browser widget target | `run_ai_target_scan` |
| `model_intake` | Model Intake artifact check | `run_model_intake_scan` |

Core files:

| Area | Files |
|---|---|
| AI Gate API and orchestration | `api/api.py`, `api/ai_gate_scan.py`, `api/worker.py` |
| AI Gate probes and planning | `api/ai_gate/probe_registry.py`, `api/ai_gate/planner.py`, `api/ai_gate/adaptive.py` |
| AI Gate target adapters | `api/ai_gate/targets/rest_json.py`, `api/ai_gate/targets/widget_playwright.py` |
| AI Gate runner | `api/ai_gate/runner.py` |
| AI controls | `api/ai_control_requirements.py` |
| AI learning/export/report artifacts | `api/ai_redteam_artifacts.py` |
| Scenario templates | `api/ai_demo_scenarios.py` |
| Model Intake engine | `scanner/scanner_tools/model_intake.py` |
| AI Gate UI | `ui/src/app/settings/ai-gate/page.tsx` |
| Model Intake UI | `ui/src/app/settings/model-intake/page.tsx` |
| Shared report UI | `ui/src/components/ReportView.tsx` |
| AI settings UI | `ui/src/components/AISettingsPanel.tsx` |

---

## 2. What Users Can Do Today

This section is the feature inventory. If a user asks "what AI functionality does ShakerScan already have?", start here.

### Feature 1: Create AI Gate targets

Users can save AI targets from `/settings/ai-gate` or through `POST /ai/targets`.

Supported target types:

| Target type | What it represents |
|---|---|
| `api_chat` | Chat/completion style JSON endpoint |
| `rag` | RAG answer endpoint with retrieved documents, citations, or document context |
| `agent_trace` | Agent trace/replay API that returns tool calls, approvals, actions, or memory events |
| `mcp_trace` | MCP-compatible trace or HTTP/SSE endpoint |
| `widget` | Browser-based AI widget driven through Playwright |

Example user flow:

1. Open `/settings/ai-gate`.
2. Add a target named `Support RAG`.
3. Set target type to `rag`.
4. Set endpoint URL to `https://staging.example.com/api/rag/answer`.
5. Set request template to include `{{prompt}}`.
6. Set response path to the answer field, for example `$.answer`.
7. Save and run `shaker-rag-lite`.

Critical limitation: ShakerScan does not automatically discover AI endpoints. The user must describe the target API accurately.

### Feature 2: Model target requests, responses, auth, and safety limits

An AI target stores enough information for the scanner to send probes safely and repeatedly.

Important target fields:

| Field | Purpose |
|---|---|
| `name` | Human-readable target name |
| `target_type` | Chat, RAG, agent trace, MCP trace, or widget |
| `endpoint_url` | URL the scanner calls |
| `method` | HTTP method |
| `headers_template` | Headers sent with each probe |
| `request_template` | JSON/body template; usually contains `{{prompt}}` |
| `response_path` | JSONPath-like field for assistant output |
| `streaming_mode` | `json` or `sse` |
| `rate_limit_rps` | Outbound request throttle |
| `request_budget` | Max probe requests |
| `token_budget` | Approximate token budget |
| `production_mode` | Requires explicit production confirmation |
| `metadata_json` | Controls, scan hints, custom probes, and governance evidence |
| `credential` | Auth configuration stored separately from the target body |

Supported auth styles include bearer token, API-key header, custom header, basic auth, cookie, multi-header auth, and query parameter auth.

Critical limitation: wrong templates, response paths, or auth values usually fail at scan time. A dedicated "test connectivity" target action would improve this.

### Feature 3: Run AI probe packs

AI Gate ships with multiple probe packs.

| Pack | Focus | Typical use |
|---|---|---|
| `shaker-ai-smoke` | Broad quick probes | Fast sanity check |
| `shaker-owasp-llm` | OWASP LLM-style prompt, leakage, and output risks | General LLM app assessment |
| `shaker-rag-lite` | RAG leakage, poisoned content, citation, and retrieval-boundary checks | Internal document assistant |
| `shaker-agent-abuse` | Tool abuse, approval bypass, delegated identity, unsafe action patterns | Agents that call APIs/tools |
| `shaker-mcp-security` | MCP/OAuth/scope/tool/resource boundary checks | MCP servers and connector flows |

Supported scan profiles:

| Profile | Intended depth |
|---|---|
| `smoke` | Fast single-turn coverage |
| `trace` | Trace-oriented single-turn coverage |
| `standard` | Multi-turn/adaptive coverage |
| `deep` | Broader multi-turn/adaptive coverage |

Example user flow:

1. Create a RAG target.
2. Select `shaker-rag-lite`.
3. Use `smoke` for a quick check or `standard` for better coverage.
4. Queue the scan.
5. Open `/scans/{scan_id}` when complete.

Critical limitation: these packs are useful and growing, but they are not a complete replacement for dedicated red-team frameworks such as PyRIT, garak, promptfoo, Giskard, or Inspect AI.

### Feature 4: RAG security testing

AI Gate includes probes and detectors for RAG-specific failure modes.

Implemented RAG themes:

- Cross-tenant retrieval leakage
- Document inventory disclosure
- Hidden document instruction leakage
- Revoked/deleted document recall
- Poisoned document influence
- Citation/source behavior
- Retrieval boundary issues
- Tenant isolation markers

Example user flow:

1. Build a dummy corpus with public, confidential, revoked, and malicious documents.
2. Create a RAG target that queries that corpus.
3. Run `shaker-rag-lite`.
4. Review whether the target leaked cross-user or revoked content.

Critical limitation: AI Gate observes API behavior. It does not directly inspect the vector database or prove ACL implementation quality unless that behavior is visible through the target response or supplied control metadata.

### Feature 5: Agent and tool security testing

AI Gate includes agent/tool abuse probes.

Implemented themes:

- Approval bypass
- Dangerous tool execution
- Dry-run becoming real action
- Stale approval replay
- Unapproved memory write
- Overbroad tool scope indicators
- Cross-tenant trace leakage
- Tool metadata injection
- Remote agent trust issues
- Missing audit/approval patterns

Example user flow:

1. Create an `agent_trace` target backed by an agent trace replay endpoint.
2. Run `shaker-agent-abuse`.
3. Inspect whether the trace shows unsafe tool calls or missing approvals.

Critical limitation: the current implementation is strongest when the target exposes structured trace behavior. It does not yet deeply parse every possible agent framework trace format.

### Feature 6: MCP and connector testing

AI Gate includes MCP-focused probes.

Implemented themes:

- OAuth audience confusion
- Wildcard audience issues
- PKCE downgrade indicators
- Overbroad scopes
- Scope expansion
- Tool/resource oversharing
- Tool schema disclosure
- Shadow server rebinding
- Local command consent bypass
- Resource disclosure

Example user flow:

1. Create an `mcp_trace` target.
2. Run `shaker-mcp-security`.
3. Review findings for token audience, scope, consent, and resource exposure issues.

Critical limitation: MCP is changing quickly. Probe coverage and expected controls need to be reviewed regularly.

### Feature 7: Deterministic AI classification

AI Gate does not rely only on an LLM judge. The scanner has deterministic detectors for known markers and structured evidence.

Implemented detector sources:

- Regex markers for secrets, tokens, PII, internal URLs, tenant IDs, and unsafe output patterns.
- Text markers for prompt leakage, policy leakage, system instruction disclosure, and role confusion.
- Structured signals from target responses.
- Heuristics that reduce obvious false positives.

Example user flow:

1. Run an AI Gate scan with no AI provider configured.
2. ShakerScan still produces findings from deterministic evidence.
3. The UI shows `ai_verdict`, confidence, rationale, and recommendations using deterministic fallback analysis.

Critical limitation: deterministic markers are explainable and repeatable, but they can still miss nuanced failures or flag ambiguous text. Important findings still need manual validation.

### Feature 8: Semantic and rubric judging

When an AI provider is configured in `/settings`, AI Gate can ask a configured model to review transcripts and findings.

There are two provider-backed review paths:

- **Semantic judge**: reviews probe transcripts and determines whether the target complied with the attack objective.
- **Rubric judge**: scores findings against a severity/confidence rubric when explicitly enabled.

The output fields are stored on findings:

- `ai_verdict`
- `ai_confidence`
- `ai_rationale`
- `ai_recommendations`
- `ai_classification_source`

If provider judging fails, ShakerScan keeps deterministic analysis and marks findings with `ai_judging_unavailable`.

Critical limitation: provider-backed judging is advisory. It costs money, adds latency, and can be wrong. It should improve triage, not replace human review.

### Feature 9: AI control evidence baseline

AI Gate can build a control evidence pack from target metadata.

The shared control catalog currently includes 25 controls:

- 5 controls that apply to all AI targets.
- 7 RAG controls.
- 13 agent/MCP/tool controls.

Examples:

- Asset owner
- Risk tier
- Data classification
- Model provider
- Prompt version
- Logging and retention
- Retrieval ACL matrix
- Vector tenant isolation
- Retrieved-content delimiters
- Source citations
- Tool inventory
- Tool scopes
- Delegated identity
- Token audience validation
- Approval for write/destructive actions
- Dry-run mode
- Transaction limits
- Sandboxing
- Audit logs
- Anomaly detection
- Kill switch

If `metadata_json.enforce_ai_control_baseline` is true, missing controls become findings.

Critical limitation: this validates that evidence was supplied, not that the control is truly effective. It is a design-review and governance aid, not proof of implementation.

### Feature 10: AI deployment decision

AI Gate computes a deployment-style decision based on findings and context.

Possible decisions:

- `allow`
- `needs_approval`
- `block`

Example user flow:

1. Run a scan against a staging RAG endpoint.
2. A critical cross-tenant leakage finding is detected.
3. The scan result shows a blocking decision.

Critical limitation: the decision is advisory inside ShakerScan. There is no external CI/CD enforcement gate unless the user integrates the API into their own pipeline.

### Feature 11: AI evidence, transcripts, and reporting

Completed AI Gate scans expose evidence in the scan detail page.

Implemented evidence includes:

- Probe IDs
- Probe family and technique
- Prompt text
- Response excerpts
- HTTP status
- Detector hits
- Turn count
- Expected safe behavior
- Expected attack success
- Linked findings
- Semantic judge summary when present
- Control evidence summary

AI red-team report export is available through:

- `/scans/{scan_id}/ai-redteam-report?format=json`
- `/scans/{scan_id}/ai-redteam-report?format=markdown`

Critical limitation: reports are useful drafts and evidence packages. They still need a human reviewer before being used as professional assessment deliverables.

### Feature 12: Learning guide, test-case catalog, and external exports

ShakerScan exposes AI red-team learning and test artifacts.

Endpoints:

- `GET /ai/learning-guide`
- `GET /ai/test-cases`
- `GET /ai/test-cases/export?format=json`
- `GET /ai/test-cases/export?format=promptfoo`
- `GET /ai/test-cases/export?format=pyrit`
- `GET /ai/test-cases/export?format=garak`

Export formats:

- JSON
- promptfoo YAML
- PyRIT-style JSON
- garak-style JSONL/NDJSON

Critical limitation: exports are generated from the current probe catalog. They are not snapshotted to the exact scan that ran in the past.

### Feature 13: Custom probes and corpora

AI Gate can load additional inline probes from target metadata.

Users can supply `metadata_json.custom_probes` to add custom test cases for a target. The planner validates them and skips conflicts with built-in probe IDs.

Built-in corpus files live under `api/ai_gate/corpora/`.

Critical limitation: there is no admin UI or API for uploading new corpus files dynamically.

### Feature 14: Widget scanning

AI Gate has a Playwright-backed widget target adapter.

This supports browser-driven interaction with AI widgets where API-only testing is not enough.

Critical limitation: widget scanning is less mature than REST/trace targets. Treat it as API-supported with limited UI workflow.

### Feature 15: Model Intake artifact scanning

Model Intake inspects model artifacts without importing or executing model code.

Implemented artifact checks include:

- HTTP/HTTPS/local artifact fetch
- Download size limit
- Timeout handling
- SHA256 calculation
- Expected hash comparison
- Unsafe extension detection
- Pickle/joblib/PyTorch-style serialization risk markers
- Executable file extension detection
- ZIP/archive inspection
- Risky files inside archives
- Metadata URL fetch
- Inline metadata merge

Example user flow:

1. Open `/settings/model-intake`.
2. Submit a `.safetensors` artifact URL.
3. Provide expected SHA256 and metadata.
4. Queue the scan.
5. Review the Model Intake section in `/scans/{scan_id}`.

Critical limitation: Model Intake is static. It does not execute the model, sandbox inference, or prove runtime safety.

### Feature 16: Model supply-chain governance checks

Model Intake checks whether governance and supply-chain evidence is present.

Implemented evidence categories:

- Provenance
- Source repository
- Commit or version reference
- Training data reference
- Attestation URL
- Model card
- License evidence
- SBOM/dependency evidence
- Signature/signer evidence
- Malware scan evidence
- Security eval or red-team evidence
- Deployment restrictions
- Deployment approval
- Monitoring plan

Critical limitation: several checks are evidence-presence checks. ShakerScan does not yet cryptographically verify every signature, generate SBOMs, or run a real malware/YARA engine.

### Feature 17: Model Intake decisions

Model Intake returns a deploy decision:

- `allow`
- `review`
- `block`

Typical behavior:

- Unsafe serialization or hash mismatch blocks.
- Missing medium-severity governance evidence usually requires review.
- Low/info-only issues can allow with advisory context.

Critical limitation: unsupported registries such as Hugging Face, OCI, or S3 are not natively resolved yet. The scanner can flag unsupported schemes and still evaluate metadata, but it cannot fully inspect the remote artifact.

### Feature 18: Findings and exposure graph integration

AI findings are stored in the normal findings system.

Current behavior:

- AI Gate findings use AI source classification and can be filtered with `source_type=ai`.
- AI session findings also appear under `source_type=ai`.
- Model Intake findings currently appear under the DAST/non-AI side because there is not yet a separate Model Intake product filter.
- The exposure graph includes AI targets, MCP tools, model artifacts, scans, and findings when that data is present.

Critical limitation: AI Gate findings are not retested through the normal DAST retest flow. Rerun the AI Gate target instead.

---

## 3. AI Gate End-to-End Flow

When a user clicks **Run** on an AI target:

```text
UI
  POST /ai/targets/{target_id}/scan
    |
API
  Loads the saved target
  Validates production confirmation when needed
  Creates a scans row
  Stores the target snapshot and scan options
  Pushes a Redis job
    |
Worker
  Reads options.run_kind
  Dispatches to run_ai_target_scan
    |
AI Gate engine
  Builds the target adapter
  Plans the probe pack
  Runs probes through ConversationRunner
  Applies deterministic detectors
  Optionally runs semantic/rubric judging
  Builds control evidence
  Computes decision, score, and grade
    |
Worker persistence
  Stores result JSON
  Persists findings
    |
UI
  /scans/{scan_id} shows AI Gate result
  /findings?source_type=ai filters AI findings
```

The target snapshot is important. A scan should be understandable later even if the saved target is edited or deleted.

---

## 4. AI Target Adapters

AI Gate talks to targets through adapters.

| Adapter | Used for | Notes |
|---|---|---|
| `RestJsonConversationTarget` | Chat, RAG, agent trace APIs | Main adapter for JSON APIs |
| `SseConversationTarget` | SSE-style MCP or streaming targets | Used when streaming mode is SSE |
| `WidgetPlaywrightConversationTarget` | Browser widgets | Uses Playwright and widget manifest/safety policy |

For REST JSON targets, the request template must place probe text somewhere the target will process. Most targets use `{{prompt}}`.

Common examples:

```json
{
  "message": "{{prompt}}",
  "session_id": "{{session_id}}"
}
```

```json
{
  "question": "{{prompt}}",
  "user_id": "alice",
  "tenant_id": "tenant-a"
}
```

The response path tells ShakerScan where to find the assistant text:

- `$.answer`
- `$.message.content`
- `$.choices[0].message.content`
- `$.result.output`

---

## 5. Probe Packs, Profiles, and Adaptive Planning

A **probe** is one test case. A **pack** is a named group of probes. A **profile** controls scan depth.

Probe definitions include:

- Stable ID
- Family
- Title
- Prompt
- OWASP/MITRE-style reference where available
- Minimum profile
- Technique
- Expected safe behavior
- Expected attack success
- Severity if successful
- Optional multi-turn templates
- Production safety flag

For `standard` and `deep` profiles, AI Gate can use adaptive planning:

```text
recon -> exploit -> confirm
```

The planner tries initial probes, prioritizes families with signal, and confirms successes within request and token limits.

Target metadata can influence planning:

- `adaptive_max_family_budget`
- `adaptive_max_success_confirmation_attempts`
- `adaptive_family_priorities`
- `max_turns_per_conversation`

Critical engineering note: adaptive planning improves coverage efficiency, but it also makes scan behavior less obvious than a fixed probe list. The execution plan in the result should be checked when debugging missing probes.

---

## 6. Detection and AI Analysis

AI Gate finding generation is layered.

Detection layers:

1. **Regex and marker detectors** find secrets, PII, prompt leaks, internal references, unsafe output, tool-abuse markers, RAG leakage markers, and MCP indicators.
2. **Structured response signals** allow machine-readable target responses to become findings.
3. **Heuristic suppressors** reduce some obvious false positives.
4. **Semantic judge** optionally reviews transcripts with the configured AI provider.
5. **Rubric judge** optionally reviews findings against a severity rubric.
6. **Deterministic AI analysis** fills verdict/rationale fields when provider-backed judging is unavailable.

A typical AI Gate finding contains:

```json
{
  "id": "ai_gate:example:finding",
  "title": "Example AI Gate finding",
  "severity": "high",
  "category": "prompt_injection",
  "family": "prompt_injection",
  "tool": "ai_gate",
  "evidence": {
    "probe_id": "example-probe",
    "matched_markers": [],
    "detector_hits": []
  },
  "ai_verdict": "needs_review",
  "ai_confidence": 0.72,
  "ai_rationale": "Short explanation",
  "ai_recommendations": []
}
```

Important behavior:

- Semantic judge false-positive downgrades preserve the original severity in evidence.
- Provider errors are visible through `ai_judging_unavailable`.
- Deterministic analysis is still produced when no provider is configured.

Critical engineering note: never assume `ai_verdict=true_positive` is proof. It is a triage signal attached to evidence.

---

## 7. Control Evidence Baseline

The AI control baseline is implemented in `api/ai_control_requirements.py`.

The scanner reads target `metadata_json` and checks whether required evidence keys are present for the target type.

Examples:

```json
{
  "asset_owner": "security",
  "risk_tier": "high",
  "data_classification": "restricted",
  "retrieval_acl_matrix": "per-user-doc-acl",
  "vector_tenant_isolation": "tenant-namespaces",
  "tool_inventory": ["read_ticket", "create_ticket"],
  "write_action_approval": true,
  "audit_logs": "siem-ai-agent-events",
  "kill_switch": "agent-disable-runbook",
  "enforce_ai_control_baseline": true
}
```

The result includes:

- Required controls
- Present controls
- Missing controls
- Evidence values
- Framework mappings
- Summary counts

If `enforce_ai_control_baseline` is true, missing required controls are converted into findings.

Critical engineering note: framework mappings are display/evidence metadata. The scanner does not independently prove that a claimed NIST/ISO/OWASP mapping is correct.

---

## 8. Honey Demo Lab

Honey is a separate intentionally vulnerable demo/lab service used by the project for demos and regression learning.

For product clarity:

- Honey is not required for normal ShakerScan use.
- Demo mode is intended to be off by default.
- Demo URLs are intended to be empty by default.
- The AI Gate "Run Demo" control appears only when demo mode is enabled.
- Demo targets are tagged and hidden from the normal target list unless the user chooses to show them.

Settings live in `/settings` under **Calibration Lab**.

There are two Honey URLs:

| Setting | Purpose |
|---|---|
| Honey public URL | URL shown to the user/browser |
| Honey scanner URL | URL Docker workers can reach |

For a locally hosted Honey on the host machine, the browser might use:

```text
http://localhost:18080
```

The scanner container may need:

```text
http://host.docker.internal:18080
```

Critical engineering note: avoid making Honey concepts visible in normal AI Gate flows. ShakerScan should feel like a generic AI security scanner, not a demo-only tool.

---

## 9. Model Intake End-to-End Flow

When a user queues a Model Intake scan:

```text
UI
  POST /model-intake/scan
    |
API
  Validates request
  Creates scans row with run_kind=model_intake
  Pushes Redis job
    |
Worker
  Dispatches to run_model_intake_scan
    |
Model Intake engine
  Fetches metadata if provided
  Merges inline metadata
  Fetches artifact when supported
  Calculates hash
  Inspects extension and archive entries
  Sniffs unsafe serialization markers
  Checks governance evidence
  Computes score, grade, and decision
    |
UI
  /scans/{scan_id} shows Model Intake result
```

Model Intake is intentionally non-executing. It should never import or load model code just to inspect an artifact.

---

## 10. Model Intake Inputs

`POST /model-intake/scan` accepts:

| Field | Purpose |
|---|---|
| `artifact_url` | Artifact reference to inspect |
| `metadata_url` | Optional JSON metadata document |
| `metadata_json` | Inline metadata; overrides remote metadata |
| `expected_sha256` | Pinned expected digest |
| `signature_url` | Detached signature or signature evidence URL |
| `model_card_url` | Model card URL |
| `deployment_approved` | Whether deployment has been approved |
| `require_signature` | Require signature/signer evidence |
| `require_hash` | Require expected hash |
| `require_deployment_approval` | Require approval evidence |
| `require_model_governance` | Require governance evidence |
| `timeout_seconds` | Fetch timeout |
| `max_download_bytes` | Artifact download cap |

Supported artifact fetches today:

- `http`
- `https`
- local paths in allowed environments

Unsupported registry-like schemes are reported as findings rather than silently ignored.

---

## 11. Model Intake Checks

Artifact and format checks:

- Fetch failure
- Oversized download
- SHA256 mismatch
- Missing checksum
- Missing signature/signer evidence
- Unsafe serialization extension
- Pickle-like magic bytes or opcode markers
- Executable files inside archives
- Risky serialized objects inside archives
- Unknown/unclassified format

Governance checks:

- Missing provenance
- Missing model card
- Missing deployment approval
- Missing license review
- Missing SBOM/dependency evidence
- Missing malware scan evidence
- Missing security evaluation evidence
- Missing deployment restrictions
- Missing monitoring plan

Recognized risky extensions include:

```text
.pkl .pickle .joblib .pt .pth .ckpt .bin .mar
```

Safer static formats include:

```text
.safetensors .onnx .tflite .gguf
```

Executable extensions include:

```text
.exe .dll .so .dylib .sh .bash .ps1 .bat .cmd
```

Critical engineering note: "safer static format" does not mean "safe model." It only means the file format is less prone to arbitrary code execution than pickle-like serialization.

---

## 12. Model Intake Result Shape

The result contains:

```json
{
  "schema_version": "2026-05-10.model-intake.v1",
  "scan_mode": "model_intake",
  "target": "<artifact_ref>",
  "model_intake": {
    "summary": {},
    "artifact": {},
    "metadata": {},
    "metadata_fetch": {},
    "checks": {}
  },
  "findings": [],
  "result": {
    "score": 100,
    "grade": "A",
    "decision": {
      "decision": "allow",
      "decision_reason": "..."
    }
  }
}
```

The decision can be:

- `allow`
- `review`
- `block`

Critical engineering note: Model Intake findings currently use `tool=model_intake` but do not have a separate top-level product filter in the findings UI. They are not AI Gate findings.

---

## 13. Findings, Reports, and Exposure Graph

AI-related output appears in several product areas:

| Area | Behavior |
|---|---|
| Scan detail | Shows AI Gate or Model Intake sections when present |
| Findings list | `source_type=ai` filters AI Gate and AI session findings |
| Finding detail | Shows AI verdict, confidence, rationale, and recommendations when present |
| AI red-team report | Exports scan evidence as JSON or Markdown |
| Exposure graph | Shows AI targets, MCP tools, model artifacts, scans, and findings when available |

Important distinction:

- **AI Gate findings** are behavioral AI security findings.
- **Model Intake findings** are model supply-chain and artifact review findings.
- **AI session findings** come from interactive/manual AI-assisted testing.

---

## 14. API Quick Reference

AI Gate:

| Method/path | Purpose |
|---|---|
| `GET /ai/targets` | List AI targets |
| `POST /ai/targets` | Create AI target |
| `PATCH /ai/targets/{target_id}` | Update AI target |
| `DELETE /ai/targets/{target_id}` | Soft-delete AI target |
| `POST /ai/targets/{target_id}/scan` | Queue AI Gate scan |
| `GET /ai/scans/{scan_id}/transcript` | Return probe transcripts |
| `GET /ai/test-scenarios` | Return target/scenario templates |
| `GET /ai/learning-guide` | Return AI learning guide data |
| `GET /ai/test-cases` | Return probe/test-case catalog |
| `GET /ai/test-cases/export` | Export test cases |

Model Intake:

| Method/path | Purpose |
|---|---|
| `POST /model-intake/scan` | Queue Model Intake scan |

Reports:

| Method/path | Purpose |
|---|---|
| `GET /scans/{scan_id}/ai-redteam-report?format=json` | Export AI report JSON |
| `GET /scans/{scan_id}/ai-redteam-report?format=markdown` | Export AI report Markdown |

Settings:

| Method/path | Purpose |
|---|---|
| `GET /settings/ai` | Read effective AI settings |
| `PUT /settings/ai` | Update AI settings |
| `POST /settings/ai/test` | Test AI provider settings |

Demo lab:

| Method/path | Purpose |
|---|---|
| `POST /ai/demo/run` | Queue demo AI scenarios when demo mode is enabled |

---

## 15. UI Tour

Primary pages:

| Page | Purpose |
|---|---|
| `/settings` | AI provider settings and Calibration Lab settings |
| `/settings/ai-gate` | Create AI targets, apply templates, queue AI Gate scans |
| `/settings/model-intake` | Queue Model Intake scans |
| `/scans/{scan_id}` | Review AI Gate or Model Intake result |
| `/findings` | Filter and triage findings |
| `/exposure` | Explore attack-surface graph including AI entities |

AI Gate page:

- Shows red-team resource links.
- Shows scenario templates.
- Lets users create targets.
- Lets users queue scans with selected pack/profile/environment.
- Shows saved targets and last scan links.
- Shows demo controls only when demo mode is enabled.

Model Intake page:

- Provides artifact and metadata inputs.
- Supports presets.
- Queues a model-intake scan.
- Sends the user to the regular scan detail page for results.

Scan detail:

- Shows AI Gate summary when the result contains AI Gate data.
- Shows transcripts and detector hits.
- Shows semantic judge summary when present.
- Shows AI control evidence when present.
- Shows Model Intake artifact/check summaries when present.

---

## 16. Known Gaps and Good Starter Projects

These are the highest-value improvement areas.

1. **Native registry support**: Model Intake should resolve Hugging Face, OCI, and S3 references instead of only flagging unsupported schemes.
2. **Cryptographic verification**: signature/signer evidence exists, but full model signing/provenance verification is not complete.
3. **Real malware scanning**: Model Intake records malware scan evidence but does not run a full AV/YARA engine itself.
4. **Model SBOM generation**: SBOM evidence is checked, not generated.
5. **Model Intake source filter**: findings should eventually have a first-class Model Intake product filter instead of appearing under the non-AI/DAST side.
6. **AI target connectivity test**: users need a test button before the first scan.
7. **Better metadata editor**: `metadata_json` is too easy to typo; a control picker/validator would reduce false missing-control findings.
8. **Structured agent/MCP trace ingestion**: current checks benefit from markers, but richer parsers would improve precision.
9. **Widget maturity**: browser widget testing needs more UI support and more reliable selector setup.
10. **Automatic AI endpoint discovery**: users currently describe AI targets manually.
11. **Export snapshotting**: test-case exports are generated from the current catalog, not the exact scan-time catalog.
12. **Provider-backed judging budgets**: UI should make semantic judge cost/latency limits more visible.
13. **External deploy gate integration**: ShakerScan computes decisions, but users need CI/CD integration to enforce them.
14. **Engine modularity**: `api/ai_gate_scan.py` carries too many responsibilities and should be split over time.
15. **Manual validation workflow**: UI can do more to help reviewers mark AI findings as validated, false positive, accepted risk, or retest-needed.

---

## 17. Troubleshooting Map

| Symptom | Start here |
|---|---|
| AI target does not queue | `api/api.py`, AI target scan handler |
| Worker does not run AI job | `api/worker.py`, `AI_GATE_RUN_KINDS` |
| Probes do not appear in result | `api/ai_gate/planner.py`, `api/ai_gate/adaptive.py` |
| Target request is malformed | `api/ai_gate/targets/rest_json.py` |
| Wrong detector output | `api/ai_gate_scan.py` detector/classifier functions |
| Semantic judging missing | AI settings, target metadata, judge config, execution plan |
| Missing controls not flagged | `api/ai_control_requirements.py`, control evidence builder |
| Custom probe rejected | `api/ai_gate/corpus_loader.py`, planner validation errors |
| Widget scan fails | `api/ai_gate/targets/widget_playwright.py` |
| Model artifact fetch fails | `scanner/scanner_tools/model_intake.py` fetch helpers |
| Model governance finding seems wrong | Model metadata merge and governance check logic |
| UI result missing AI section | `ui/src/components/ReportView.tsx` |

---

## 18. Glossary

- **AI Gate**: ShakerScan product for testing AI application behavior.
- **Model Intake**: ShakerScan product for static model artifact and supply-chain review.
- **AI target**: Saved configuration describing how to call an AI surface.
- **Probe**: One AI red-team test case.
- **Pack**: Named group of probes.
- **Profile**: Scan depth level.
- **Family**: Probe category used for planning and reporting.
- **Adaptive scan**: Scan that uses recon, exploit, and confirmation phases.
- **Transcript**: Captured prompt/response evidence from a probe.
- **Semantic judge**: Configured AI provider reviewing transcripts.
- **Rubric judge**: Configured AI provider scoring findings against a rubric.
- **Deterministic classifier**: Non-LLM detector/analysis logic.
- **Control evidence pack**: Metadata-derived evidence for AI security controls.
- **Honey**: Optional demo/lab companion service.
- **Deployment decision**: Advisory AI Gate or Model Intake result of allow, review/needs approval, or block.
