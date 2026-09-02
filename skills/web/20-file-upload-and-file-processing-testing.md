---
id: skill.web.file-upload-and-file-processing-testing
name: file-upload-and-file-processing-testing
title: 20. File Upload and File Processing Testing
description: Test upload authorization, filename/path handling, type validation, public delivery, overwrite,
  active content, signed URLs, parser pipelines, and resource controls without web shells or harmful files.
version: 2.0.0
kind: specialist
phase: active_testing
risk: high
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- browser.navigate
- candidate.verify
optional_capabilities: []
missing_capabilities:
- artifact.inspect
- file.generate_canary
- file.upload
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 160
  max_duration_seconds: 1500
  max_state_changing_requests: 15
  max_oob_interactions: 4
routing:
  triggers:
  - multipart_upload
  - presigned_upload
  - attachment
  - avatar_or_media
  - document_conversion
  - archive_processing
  - download_or_render
  indicators:
  - type_validation_gap
  - active_content_rendering
  - public_or_cross_tenant_access
  - unsafe_processor
  - filename_or_path issue
  - execution
  exclusions:
  - web_shell
  - malware
  - destructive_macro
  - decompression_bomb
  - uncontrolled_viewer
preconditions:
- compiled_scope_policy
- controlled_identity
- harmless_canary_file
techniques:
- extension-MIME-magic-consistency
- filename-and-path-handling
- storage-and-access-control
- active-content-rendering
- archive-and-converter-processing
- presigned-upload-policy
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 20-file-upload-and-file-processing-testing.md
---

# 20. File Upload and File Processing Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Assess the entire file lifecycle—from selection and upload through storage, scanning, transformation, preview, download, sharing, deletion, and expiry. Demonstrate boundary failures with harmless canaries only.

## Use this skill when

- The application accepts images, documents, archives, CSV/XML, media, avatars, attachments, imports, models, templates, or support files.
- Files are transformed, OCRed, converted, previewed, extracted, scanned, or passed to another service.
- Object storage and signed URLs are used.
- Upload behavior differs across web, API, mobile, GraphQL, or admin paths.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `multipart_upload`
- `presigned_upload`
- `attachment`
- `avatar_or_media`
- `document_conversion`
- `archive_processing`
- `download_or_render`

**Useful indicators**

- `type_validation_gap`
- `active_content_rendering`
- `public_or_cross_tenant_access`
- `unsafe_processor`
- `filename_or_path issue`
- `execution`

**Hard exclusions**

- `web_shell`
- `malware`
- `destructive_macro`
- `decompression_bomb`
- `uncontrolled_viewer`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_identity`
- `harmless_canary_file`

**Preferred preconditions**

- `processing_pipeline_map`
- `cleanup_method`
- `second_controlled_identity`

## Required context

- Controlled accounts, synthetic objects, approved file types, size limits, and owner-provided scratch storage.
- Allowed harmless fixtures: text, tiny image, benign SVG/HTML canary, tiny archive, and malformed-but-bounded documents.
- Expected authorization, retention, delivery, scanning, transformation, and cleanup behavior.
- Explicit prohibition on web shells, malware, executable persistence, decompression bombs, and parser DoS.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `file.generate_canary`
- `file.upload`
- `http.request`
- `browser.observe`
- `artifact.inspect`
- `state.verify`

**Optional adapters**

- `oob.allocate`
- `oob.observe`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 160 |
| `max_duration_seconds` | 1500 |
| `max_concurrency` | 2 |
| `max_state_changes` | 15 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 4 |
| `max_uploaded_bytes` | 10485760 |
| `max_cost_units` | 220 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `active_content_or_processor_probe` | canary may execute or reach a viewer/processor outside controlled accounts | `human_approval` |

**State access**

- Reads: `compiled_policy`, `file_processing_graph`, `identities`, `object_graph`, `request_corpus`
- Writes: `uploaded_test_artifacts`, `processing_stage_observations`, `access_control_observations`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Upload validation trusts extension, MIME, filename, or client metadata without validating content.
- Uploaded content is publicly accessible, executable, same-origin active, or delivered with unsafe headers.
- Filename/path handling permits overwrite, traversal, collision, or cross-tenant access.
- Downstream scanners/converters/parsers introduce SSRF, XXE, injection, or unsafe rendering.
- Signed URLs, share links, deletion, retention, or transformed variants have weaker authorization.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Never upload web shells, malware, credential stealers, destructive macros, executable payloads, or actual decompression bombs.
- Use small files with unique canaries and clean them up.
- Stored active-content tests must be visible only to controlled accounts.
- Do not assume rejection at upload means downstream processing is safe; map each stage.

## Agent workflow

### 1. Map the file lifecycle

- Capture upload initiation, multipart/direct-to-storage flow, metadata, scanning, processing, preview, download, share, expiry, delete, and transformed variants.
- Identify storage origin, object key, filename handling, content disposition/type, CDN/cache, and worker services.
- Classify every stage by identity, tenant, and network privilege.

### 2. Establish valid controls

- Upload a tiny approved file with a unique marker.
- Verify owner visibility, metadata, processing state, download headers, variants, deletion, and cleanup.
- Record server-generated object IDs and signed URL properties.

### 3. Test type and metadata validation

- Change one attribute at a time: extension, case, MIME, magic bytes, filename, Unicode, duplicate extension, and metadata.
- Use harmless polyglot-like fixtures only to test parser disagreement, not execution.
- Determine which component makes the final type decision.

### 4. Test delivery and active content

- Upload benign HTML/SVG/Markdown or filename canaries where allowed and render only in a controlled account.
- Check origin isolation, content disposition, content type, CSP, nosniff, sandboxing, and download behavior.
- Verify transformed previews do not reintroduce active content.

### 5. Test authorization and object storage

- Use paired users/tenants to read, replace, delete, share, or enumerate only synthetic files.
- Test signed URL expiry, scope, method, content type, object binding, and revocation.
- Check thumbnails, previews, original files, exports, and direct storage URLs separately.

### 6. Test downstream processing safely

- Use tiny bounded malformed documents, metadata, archive entries, XML/SVG references, and image/document dimensions.
- Observe callbacks, parser errors, processing logs, and status without causing resource exhaustion.
- Hand specific behavior to SSRF, XXE, injection, traversal, or resource skills.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `extension-MIME-magic-consistency` — Extension mime magic consistency. Select only when the matching trigger and evidence preconditions are present.
- `filename-and-path-handling` — Filename and path handling. Select only when the matching trigger and evidence preconditions are present.
- `storage-and-access-control` — Storage and access control. Select only when the matching trigger and evidence preconditions are present.
- `active-content-rendering` — Active content rendering. Select only when the matching trigger and evidence preconditions are present.
- `archive-and-converter-processing` — Archive and converter processing. Select only when the matching trigger and evidence preconditions are present.
- `presigned-upload-policy` — Presigned upload policy. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Type validation | Content and intended type are validated | Change one extension/MIME/magic property | Unsafe type accepted/processed |
| Active content | Uploads cannot execute in trusted origin | Self-visible benign HTML/SVG canary | Script/active behavior occurs |
| Object authorization | Files/variants are owner/tenant scoped | Access paired synthetic file as peer | Unauthorized read/write/delete |
| Signed URL | URL is narrow and revocable | Replay after expiry/revocation or alter controlled object | Access persists or retargets |
| Processor | Downstream parser is isolated and bounded | Tiny controlled malformed/reference fixture | Unsafe callback, error leak, or boundary crossing |

## Tool strategy

- Use small locally generated fixtures, browser verification, raw multipart requests, object-storage clients, and controlled OOB.
- Use file identification tools locally; do not rely on extension alone.
- Track every uploaded object and transformed variant for cleanup.
- Use disposable processing environments for deeper parser validation.

## Evidence required for a finding

- Original fixture hash, filename, declared/actual type, upload request, object ID, storage/delivery origin, and cleanup status.
- For active content, controlled browser execution in the target trust origin.
- For authorization, paired synthetic file evidence.
- For parser issues, exact stage and minimal safe callback/error/state proof.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/file-upload-and-file-processing-testing.schema.json`.

**Skill-specific evidence fields**

- `filename`
- `declared_content_type`
- `magic_bytes`
- `size_bytes`
- `processing_stage`
- `storage_location`
- `access_result`
- `execution_or_render_signal`

**Required validation controls**

- `harmless_small_files`
- `stage_by_stage_mapping`
- `controlled_viewers_only`
- `cleanup_recorded`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Server acceptance is not equivalent to public delivery or execution.
- A browser rendering local preview content is not a server vulnerability.
- MIME mismatch alone may be harmless when files are forced-download from an isolated origin.
- A signed URL remaining valid may be intended until expiry; compare documented policy.

## Stop conditions

- A file executes, escapes storage, reaches an unsafe parser, or crosses authorization—the proof is complete.
- Processing latency, memory, queue depth, or errors rise.
- A file could reach real users, public search, external recipients, or production devices.
- Cleanup or revocation cannot be guaranteed.

## Common remediation patterns

- Allowlist types and validate extension, MIME, magic/content, parser result, and business purpose.
- Generate server-side object names and isolate upload storage from the application origin and execution paths.
- Use safe download headers, `nosniff`, sandboxing, and content transformation.
- Authorize originals, variants, signed URLs, shares, and deletion independently; use short-lived narrow signatures.
- Run scanners/converters in isolated least-privilege workers with no unnecessary network and strict size/time/decompression limits.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/file-upload-and-file-processing-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.file-upload-and-file-processing-testing
supporting_skills: []
selected_techniques: [extension-MIME-magic-consistency]
hypothesis_id: HYP-example-001
risk: high
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/file-upload-and-file-processing-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 19 for traversal, archive extraction, and XXE.
- Skill 18 for URL-fetching processors.
- Skills 15–16 for execution or active-content rendering.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
upload_endpoint: https://app.example.test/api/files
identity: user_a
fixtures: [tiny_png, text_canary, benign_svg, tiny_zip]
max_file_size: 256KB
```

## Authoritative references

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PortSwigger — File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- [OWASP WSTG — File Upload Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_File_Upload)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `artifact.inspect`, `file.generate_canary`, `file.upload`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `browser.navigate`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
