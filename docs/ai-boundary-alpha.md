# AI Gate boundary verification — alpha

**Status:** merge candidate for controlled-environment testing. The feature is selected with the `shaker-ai-boundary` probe pack and is intentionally refused for production targets. It verifies configured security invariants with synthetic fixtures and deterministic evidence; it is not a universal certification of an AI system.

## Purpose

AI red teaming often stops at asking a model adversarial questions and judging its text. This feature tests the **application boundary around the model**: authenticated identities, tenant isolation, retrieval, tool execution, approvals, indirect content and conversation state. A model saying that it read data or performed an action is never sufficient proof. ShakerScan looks for a private synthetic marker or independently reads the resulting application state.

## Implemented in this alpha

### Cross-customer data isolation

Two independently authenticated principals (`victim` and `attacker`) are verified through the application's identity endpoint. Each owns a separate synthetic record with a randomized private marker. ShakerScan establishes ownership through a non-chat endpoint, verifies that direct cross-customer access is denied, then attempts access through the AI application. A marker returned in the answer or returned JSON metadata is deterministic disclosure evidence.

A direct backend authorization failure is reported separately from an AI-mediated failure so an ordinary IDOR/BOLA is not misattributed to the model or agent.

### Verified state-changing actions

A contract may declare a synthetic forbidden action and a read-only verifier endpoint. ShakerScan establishes the initial state, sends the attack through the assistant, and reads the state afterward. A response such as `Refund completed` is not proof; the finding exists only when the configured postcondition is independently observed.

### Approval bypass

Approval-sensitive workflows can declare both the action state and approval state. A bypass is confirmed only when the sensitive action occurs while the independent approval read shows that the required approval remained absent. If the workflow legitimately obtains approval first, it is not classified as an approval bypass.

### Indirect prompt injection / RAG

The application harness may provision a synthetic retrieved document containing an untrusted instruction and a private randomized marker. ShakerScan verifies the document independently, triggers retrieval without putting the marker in the attacker request, and can confirm either disclosure of the document marker or a state-changing action caused through the retrieved content.

### Tool-principal boundary

For applications that return structured tool telemetry, the contract can identify the tool-call list, tool name, execution flag and execution principal. ShakerScan detects a tool executing under a principal different from the authenticated attack principal. State-changing tool findings additionally require an independently verified application postcondition.

This is **structured application tool telemetry**, not native MCP wire interception.

### Stateful multi-turn attacks

A contract may contain 2–8 attacker turns. All turns use one fresh conversation/session ID so ShakerScan can test attacks that require context accumulation rather than one-shot prompts. Per-turn prompt/response hashes preserve the attack chain. Multi-turn data disclosure is verified with the private marker; state-changing multi-turn attacks require the independent postcondition.

### Evidence, gating and safety properties

The alpha reuses AI Gate request/token budgets, credential hydration, gate decisions, evidence manifests and `proof-contract/v2`. It uses exact-origin scope controls, runtime DNS/address validation, redirect blocking, bounded responses, cancellation checks and secret/marker redaction. A completed clean scenario may return `allow`; incomplete or unsupported verification returns `needs_approval`; deterministic boundary violations return `block`.

The scanner does not provision or delete external customer records. The target application's test harness owns synthetic fixture creation and cleanup. Production execution is refused. Use test identities and isolate synthetic tools from real payments, email, destructive infrastructure and production data.

## Application contract

Configure an existing non-production AI target (`api_chat`, `rag`, `ai_rag`, or `agent_trace`) with separate `victim` and `attacker` credentials. Store the secret-free contract under:

`ai_target.metadata_json.boundary_contract`

The base contract declares identity and record endpoints plus strict response paths. Optional sections enable additional scenarios:

- `action` — independently verified forbidden state change.
- `approval` — action plus independent required-approval state.
- `indirect` — synthetic retrieved document and optional action verifier.
- `tool` — structured tool execution/principal telemetry and optional postcondition.
- `multiturn` — 2–8 prompts sharing one fresh session and optional postcondition.

The chat request template must contain `{{prompt}}` and `{{session_id}}`. `{{principal_id}}` and `{{principal_tenant_id}}` are also available. JSON response paths are strict dotted paths, not executable expressions.

The sample base contract is `examples/ai-boundary/customer-read-contract.json`.

## Running the synthetic developer demo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r scanner/requirements.lock

python scripts/ai_boundary_alpha.py validate examples/ai-boundary/customer-read-contract.json
python scripts/ai_boundary_alpha.py demo --mode secure --output boundary-secure.json
python scripts/ai_boundary_alpha.py demo --mode vulnerable --nested --output boundary-vulnerable.json
```

The secure demo exits `0`. The deliberately vulnerable demo returns a blocking finding and exits `1`. `needs_approval` exits `2`. These are deterministic loopback application simulations, not live-model benchmarks.

For a configured target, submit through the existing AI target API and normal credential approval path:

```bash
shakerscan api POST /ai/targets/<AI_TARGET_ID>/scan \
  '{"probe_pack":"shaker-ai-boundary","scan_profile":"standard","environment":"staging","approval_receipt_id":"<APPROVED_RECEIPT_ID>"}'
```

## What `passed` means

`passed` means the configured controls and attack scenarios completed and ShakerScan did not observe their declared deterministic failure condition. It does **not** mean the application is generally secure. Encoded or paraphrased data leakage can evade an exact canary test, and unconfigured tools/data sources are outside coverage.

## Planned after the alpha

The following are deliberately deferred so this branch can merge and begin real application testing:

1. **Native MCP transport verification.** Connect to MCP servers directly, observe protocol-level tool discovery/calls/results, bind sessions to authenticated principals and produce tool-side receipts rather than relying on application-returned telemetry.
2. **Streaming/SSE/WebSocket targets.** Extend deterministic response capture to streamed model and agent protocols while preserving budgets, cancellation and scope enforcement.
3. **Browser/GUI agents.** Verify browser-agent actions through DOM/network/postcondition evidence rather than assistant claims.
4. **Richer indirect sources.** Email, tickets, web pages, uploaded files and other untrusted context sources beyond the configured synthetic document endpoint.
5. **Adaptive attack planning.** Use AI reasoning to select and mutate scenarios while retaining deterministic success predicates. The model may propose attacks; it must not decide whether its own attack succeeded.
6. **Encoded/semantic leakage verification.** Add controlled transformations and stronger canary strategies for partial, encoded or paraphrased disclosure without creating high false-positive rates.
7. **Guided configuration UI.** Contract editor/wizard, fixture readiness checks, scenario preview and dedicated boundary-results visualization. The current alpha uses existing AI target/result surfaces.
8. **Real-system benchmark suite.** Run reproducible vulnerable and secure reference agents plus selected open-source AI applications to measure recall, precision, runtime and regression stability.
9. **Fixture lifecycle adapters.** Optional application-owned setup/cleanup hooks for disposable synthetic records, with explicit authorization and rollback semantics.
10. **Production-safe profile.** Only after real-world validation: define a strictly read-only subset with separate policy and explicit operator opt-in. The current alpha continues to refuse production.

## Merge/test acceptance

Before merging, the branch-specific `AI boundary alpha` workflow must pass. The pull request also runs the repository's complete Python/pre-merge checks. The focused verification command is:

```bash
PYTHONPATH=.:api:scanner python -m pytest -q \
  tests/test_ai_boundary.py \
  tests/test_ai_boundary_integration.py \
  tests/test_ai_boundary_admission.py \
  tests/test_ai_gate_judging.py \
  tests/test_ai_redteam_artifacts.py \
  tests/test_worker_handler_decomposition.py \
  tests/test_v2_module_boundaries.py

python scripts/check_module_size.py
```

After merge, the immediate goal is **controlled real-application testing**, not additional architecture expansion. Use disposable identities/fixtures, record false positives and unsupported target shapes, and feed those observations into the post-alpha roadmap above.
