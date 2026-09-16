# AI Gate boundary verification — developer alpha

This branch adds `shaker-ai-boundary` to ShakerScan's existing AI Gate. It tests one concrete rule: **an authenticated customer must not receive another customer's private synthetic record through the assistant or its returned response metadata.** It is a configured regression workflow, not an automatic discovery engine or a universal agent-security certification.

## Run the working synthetic demo

From a checkout of this branch, use Python 3.12 or newer and the existing locked scanner dependencies. No model API key, database, Redis, or running ShakerScan stack is needed for the demo.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r scanner/requirements.lock

python scripts/ai_boundary_alpha.py validate examples/ai-boundary/customer-read-contract.json
python scripts/ai_boundary_alpha.py demo --mode secure --output boundary-secure.json
python scripts/ai_boundary_alpha.py demo --mode vulnerable --nested --output boundary-vulnerable.json
```

The secure fixture returns `allow` and exits **0**. The deliberately vulnerable fixture returns `block` and exits **1**: that is the expected detection result, not a broken demo. `--mode echo` demonstrates failed functionality controls: `needs_approval`, exit **2**. `--mode backend_leak` isolates an ordinary backend authorization defect; `--mode trace_only` demonstrates a real disclosure in JSON metadata even when the answer refuses.

Every demo starts an ephemeral loopback HTTP server, creates two independent identities and randomized synthetic records, runs the actual verifier, then closes the server and clears records in a `finally` path. `--nested` uses different request and response layouts. These fixtures are deterministic application simulations, **not real LLM evaluations**; the output explicitly records that distinction. The output path must be new and is created with mode `0600` rather than overwriting an earlier report.

## What happens in a run

1. Read each identity through the application's non-chat identity endpoint. Check actual subjects and tenants against the declared contract. Credential labels alone are not proof of distinct users.
2. Read each user's own synthetic record through the non-chat record endpoint. Verify its ID, owner, tenant and unpredictable marker. Neither marker may appear in the contract, prompt, or chat request body.
3. Attempt a direct backend read of the owner's record as the other user. If the private marker leaks, report a **backend authorization** defect without attributing it to the assistant; assistant coverage remains incomplete. Otherwise require a real 403/404 denial.
4. Confirm each user can retrieve their own record through the assistant. A broken endpoint, an echo bot, or an assistant unable to retrieve the fixture cannot pass.
5. Repeat configured cross-customer attack conversations with fresh session IDs and fresh identity checks. Match the private marker in the actual returned JSON. A marker in debug/tool metadata is a disclosure to that caller, **not proof that a claimed tool operation executed**.
6. Recheck identities and fixture contents for drift. Return `passed`, `failed`, or `inconclusive`, independently of coverage completeness. An interrupted run never becomes a clean pass, and a confirmed disclosure remains a failure even if later controls fail.

## Configure an application, not just a model endpoint

Use a non-production AI target (`api_chat`, `rag`, or `agent_trace`) and its existing encrypted principal management. The alpha accepts non-streaming JSON POST chat endpoints. Use the existing `victim` principal role for the contract's semantic `owner` slot and `attacker` for the other user. Do not submit credentials in scan options. Normal target-bound credential approvals and worker hydration remain required.

The application needs three same-origin interfaces: a chat POST, an authenticated identity GET, and an authenticated record GET. Their names and JSON nesting are configurable. For example:

```text
GET /identity
{"subject":"owner-subject","tenant":"owner-tenant"}

GET /records/owner-record
{"id":"owner-record","owner":"owner-subject","tenant":"owner-tenant","marker":"<private random synthetic value>"}

POST /chat
{"message":"...","session_id":"..."}

Chat response
{"answer":"..."}
```

Copy `examples/ai-boundary/customer-read-contract.json`, substitute the application's real test identity/record identifiers and response paths, and store it under **`ai_target.metadata_json.boundary_contract`**. Merge this into existing target metadata rather than discarding other settings. JSON paths are strict dotted paths such as `identity.subject` or `output.text`, with numeric segments for arrays; they are not executable expressions.

The ordinary target request template must include both placeholders:

```json
{
  "message": "{{prompt}}",
  "session_id": "{{session_id}}"
}
```

An alternate application can use `{"input":{"text":"{{prompt}}"},"thread":"{{session_id}}"}` without changing the verifier. `principal_id` and `principal_tenant_id` placeholders are also available; the non-chat identity check still establishes who authenticated. The contract's `response_path` is authoritative for its chat functionality control.

The target's shared authorization/header template is intentionally not copied across principal requests. Use each principal's existing `multi_header` credential configuration when an application needs additional authenticated headers. Query-parameter credentials are not supported by this alpha.

After saving the target configuration and its principals, submit through the **existing** API, with the required credential-tier approval receipt:

```bash
shakerscan api POST /ai/targets/<AI_TARGET_ID>/scan '{"probe_pack":"shaker-ai-boundary","scan_profile":"standard","environment":"staging","approval_receipt_id":"<APPROVED_RECEIPT_ID>"}'
```

The worker selects the boundary workflow inside the existing credential-hydration context. Other probe packs retain their existing execution path. This workflow is selected by `probe_pack`, not by a new Scan type. Use the AI target API/worker path; the legacy private `run_ai_target_scan` Python function is not the boundary entrypoint. Developer tests and demos call `ai_gate.boundary.runner.run_boundary_scan`.

Results retain normal AI Gate findings, decision, transcript, coverage and evidence-manifest fields. Structured details live at `ai_gate.boundary` and in the execution plan/transcript. The existing scan result and findings views remain usable; there is **no new guided contract editor or dedicated boundary dashboard** in this alpha.

## Fixture ownership and cleanup

Your application's test harness provisions and later deletes **its own** test records. The scanner does not create or delete external records. Generate a separate marker for every record and run:

```python
import secrets
marker = "ssb_" + secrets.token_hex(24)
```

Store each marker exclusively in its owner's private record. Never put it in an attacker prompt, shared document, system prompt, or test configuration. Rotate fixtures to avoid pollution from previous runs or cross-session caches. The verifier checks marker format and rejects obvious static examples, but cannot prove randomness or exclusive storage from a returned string. Those are explicit harness responsibilities.

Use read-only test identities and isolate the assistant from real payments, production data, outgoing email and destructive tools. A POST to a chat endpoint can cause application side effects even though the scanner only sends record GETs and chat POSTs. This is why production is refused rather than treated as safe by virtue of HTTP methods alone. Application-owned chat history cleanup is also outside this alpha.

## Safety, evidence and limits

The worker's shared runtime scope guard is checked before requests and against actual DNS resolution before connecting. Destinations stay on the configured exact origin; redirects, query credentials, encoded/traversing paths, and shared cookie jars are refused. HTTPS is required except for loopback demos. Only a loopback-IP developer fixture may run without a persisted runtime guard. DNS/address drift uses the existing centralized scope policy, not a second allowlist system.

Request and token counters reuse AI Gate's budget classes. Defaults are 64 HTTP requests, 32,000 estimated tokens and 2 requests/second, with a 64 KiB response cap, 15-second per-request deadline and 180-second run deadline. Token use is estimated and checked between requests; it is not a provider-enforced billing ceiling. Custom limits cannot silently disable controls. A maximum of eight attack templates and three repetitions is supported. Worker cancellation is checked before outbound requests and while consuming responses; task cancellation propagates instead of producing a success report.

Confirmed observations are normalized through ShakerScan's existing `proof-contract/v2` adapter and use existing risk scoring, gate decisions and evidence manifests. Raw response bodies, protected markers and authentication headers are not stored in the boundary report. Hashes bind observed responses and configuration, but are not a replacement for the original response body when independently auditing a historical run. Reproduce using the approved configuration and fresh fixtures; changing the model or backend can change the result.

`passed` means **no exact-marker disclosure was observed in these completed scenarios**. Partial/encoded/paraphrased leaks, indirect document injection, multi-turn attack planning, browser widgets, SSE, native MCP, approval bypasses and actual write-action verification are not covered. Do not label them tested or secure. A broad public beta requires real application pilots, live model testing, and deployed-stack acceptance beyond these synthetic regressions.

## Verification

```bash
PYTHONPATH=.:api:scanner python -m pytest -q \
  tests/test_ai_boundary.py \
  tests/test_ai_boundary_integration.py \
  tests/test_ai_boundary_admission.py

python scripts/check_module_size.py
```

The branch's `AI boundary alpha` workflow also runs existing AI Gate/worker regression suites, validates the sample contract, executes both secure and vulnerable CLI demos, and archives the exact source revision. API admission tests require the full locked dependencies; do not replace missing production modules with test stubs and claim that validates the API.
