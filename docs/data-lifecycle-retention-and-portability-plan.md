# ShakerScan Data Lifecycle, Retention, Deletion, Export, and Import Plan

**Status:** Proposed implementation plan  
**Last updated:** 2026-08-29  
**Scope:** DAST, Hunt, AI Red Team (AI Gate), Model Intake, shared findings, evidence, and later full-system portability  
**Implementation state:** Planning only; this document does not describe completed functionality unless explicitly marked as current behavior

## 1. Purpose

ShakerScan needs a coherent data-lifecycle model for four security product planes:

1. deterministic DAST and Continuous ASM;
2. agent-driven Hunt;
3. AI Red Team / AI Gate;
4. Model Intake.

These workflows share parts of the persistence model, especially `scans`, `findings`, evidence objects,
and audit records, but they do not share the same subject, execution, evidence, or compliance semantics.
A generic age-based deletion query cannot safely govern all four.

This plan defines:

- clear Archive, Restore, Close, Expire, Content Purge, Record Purge, and Forget semantics;
- a single reusable lifecycle engine with product-specific adapters;
- safe retention policies for findings and related evidence;
- product-aware operational exports;
- a phased DAST-first implementation sequence;
- a later full-system **Export All / Import All** capability for migration and disaster recovery;
- test, audit, observability, concurrency, and failure-recovery requirements.

The first implementation slice should be DAST because its ownership graph is the simplest. The shared
contract must nevertheless be designed for all product planes before DAST deletion behavior is expanded.

## 2. Executive summary

The recommended product contract is:

- **Archive is the default subject-removal action.** It is reversible and preserves security history.
- **Purging is a separate advanced operation.** It is previewed, approval-gated, bounded, resumable,
  storage-aware, and auditable.
- **Active findings are not age-deleted.** Old active findings become stale or retest candidates.
- **Finding retention begins from lifecycle closure**, not merely from the last observation.
- **Evidence, transcripts, and large artifacts have separate retention clocks** from findings.
- **Legal hold and active-use protection override every automated policy.**
- **Automatic retention is opt-in** and is introduced only after the equivalent manual flow is safe.
- **Operational exports arrive before destructive cleanup.** Full Export All / Import All arrives later.
- **One lifecycle engine is reused across products.** Product adapters resolve ownership and protection;
  they do not create parallel cleanup engines or new scan identities.

## 3. Architectural constraints

This work must preserve the AI-native architecture rules in `AGENTS.md` and
`docs/ai-native-architecture-rfc.md`.

In particular:

- do not add a new DAST scan type for retention, deletion, backup, or migration;
- do not add target-specific Hunt engines;
- do not let an AI planner directly select database rows or filesystem paths for deletion;
- bind every destructive operation to a server-computed scope and immutable preview;
- use one canonical lifecycle capability definition per destructive action;
- reserve and bound multidimensional work before execution;
- preserve trustworthy partial results and resumable deletion intent after failure;
- keep cancellation distinct from purge;
- reuse the existing evidence-retention, approval, evidence, audit, and capability concepts;
- do not introduce parallel scope receipts, approval ledgers, evidence registries, or orchestration engines.

## 4. Current-state audit

### 4.1 Shared scans and findings

The `scans` table stores DAST, AI Gate, and Model Intake executions through `run_kind`. The shared
`findings` table can associate a finding with a web target, AI target, connected device, and scan.
Finding source and tool metadata distinguish DAST, Hunt, AI Gate, Model Intake, ASM, manual, and other
producers.

This shared table is useful for unified triage, but it creates risk: a global `DELETE FROM findings`
operation can cross product boundaries unless the lifecycle layer classifies every row first.

### 4.2 DAST target deletion

Current `DELETE /targets/{id}` behavior is a soft deactivation:

- it sets `targets.is_active=false`;
- it does not delete the target row;
- it does not delete scans;
- it does not delete findings;
- it returns `status: deleted`, even though the result is an archive-like state.

Current gaps:

- the direct target-scan route does not consistently reject inactive targets;
- the ordinary schedule runner can select a due schedule without checking target activity;
- ASM correctly filters inactive targets, but the behavior is not uniform across execution paths;
- adding the same canonical target again returns an existing record without restoring it;
- the API supports reactivation through target update, but the main Targets UI has no explicit
  Archive/Restore lifecycle;
- deactivation does not produce a durable, user-facing lifecycle receipt.

### 4.3 Physical target deletion blast radius

There is no normal public hard-delete flow for a web target. If a target row were physically deleted
under the current foreign keys:

- scans would generally survive with `target_id=NULL`;
- target-linked findings would be deleted by cascade;
- finding verification records would then be deleted by cascade;
- finding-linked evidence-object rows would then be deleted by cascade;
- many target-owned rows such as schedules, graph objects, campaigns, endpoint inventories, Hunt runs,
  request collections, credentials, and principals would be deleted or detached according to their
  individual constraints;
- target URLs and other target-controlled content could still remain inside scan snapshots, HTTP
  archives, results, reports, object storage, and audit records.

Database cascade therefore cannot serve as a complete privacy erasure or storage cleanup mechanism.

### 4.4 Current finding cleanup

`POST /findings/cleanup` currently:

- selects findings whose `last_seen_at` is older than `older_than_days`;
- optionally filters by status and root domain;
- returns a count for dry run;
- reruns the criteria during execution;
- permanently deletes every matching finding in one request.

The Findings UI exposes this as **Advanced cleanup** with 30, 60, 90, and 180-day options. The API can
accept other positive ages, but 365 days is not currently an explicit UI preset.

Important risks:

- the default UI permits Any status and All domains;
- cleanup can therefore include active, critical, verified, accepted-risk, AI Gate, Model Intake,
  device, manual, Hunt-produced, ASM, and ordinary DAST findings;
- `last_seen_at` is not a safe universal deletion clock;
- the preview contains only a count and is not bound to exact finding IDs;
- rows matching at execution time may differ from those represented by the preview count;
- execution is unbounded and loads all selected IDs;
- dependent verification and evidence-index rows can disappear through cascade;
- physical local or object-store evidence is not coordinated through the evidence-retention deletion
  workflow and may become orphaned;
- legal-hold evidence and evidence-retention floors can be bypassed by deleting the parent finding;
- textual or weakly linked policy exceptions may become semantically orphaned;
- no durable resumable cleanup intent exists for this route.

### 4.5 Evidence retention

ShakerScan already has a stronger evidence-retention design:

- retention classes including short, sensitive, standard, audit, and legal hold;
- immutable, expiring, target-scoped previews;
- content-free preview hashes;
- approval-bound execution;
- legal-hold exclusion;
- protection for evidence attached to active findings;
- shared-blob reference analysis;
- coordinated local and remote deletion;
- recovery and idempotent replay behavior;
- durable unfinished execution visibility.

This should be extended or reused by the lifecycle engine. Finding cleanup must not bypass it.

### 4.6 Hunt lifecycle

Hunt stores a separate mission graph around a target:

- `hunt_runs`;
- actions and capability receipts;
- notes and final debrief;
- candidates and verification state;
- spawned scans and campaign provenance;
- archived HTTP transactions;
- promoted findings in the shared findings table.

Hunt supports finish, cancel, and resume. HTTP transactions can be exported and purged separately.
There is no general need for deleting a Hunt merely because a finding is deleted, and deleting a Hunt
must not delete a promoted finding that has become part of the authoritative security record.

### 4.7 AI Red Team / AI Gate lifecycle

AI Gate has its own subject inventory (`ai_targets`) and `ai_*` scan kinds. AI targets are currently
soft-deactivated rather than physically deleted, and AI scan admission checks target activity more
consistently than the DAST direct target-scan path.

AI Red Team data includes several classes with different sensitivity and retention needs:

- target metadata and templates;
- reusable credential and principal bindings;
- prompts and model responses;
- raw or redacted transcripts;
- deterministic and semantic judge evidence;
- campaign history;
- AI Gate findings and retests;
- HTTP transaction archives;
- export and action receipts.

A transcript can expire while a content-free proof summary and finding remain. Conversely, deleting a
finding must not silently delete the campaign history needed to explain how the result was produced.

### 4.8 Model Intake lifecycle

Model Intake has the most compliance-sensitive ownership graph:

- immutable artifact subjects and digests;
- submissions and submission events;
- acquired quarantine content;
- static, runtime, and evaluation evidence records;
- evidence manifests;
- approval receipts;
- policy decisions;
- deployment bindings;
- admissions and admission events;
- automatic review records;
- runner jobs and scratch data;
- JSON, HTML, SARIF, SBOM, AIBOM, license, and notices outputs;
- Model Intake findings in the shared findings table.

Model Intake already has a dedicated quarantine cleanup with dry-run planning, protected digests, plan
hash validation, operator identity, reason, approval, and retention bounds. Active and
reassessment-required admissions protect referenced artifacts.

Generic finding cleanup must exclude Model Intake by default. A Model Intake finding is one projection
of a larger admission and evidence record; deleting the projection must not invalidate, conceal, or
misrepresent an admission decision.

### 4.9 Export capabilities

Current exports are product-specific and incomplete as a system backup:

- scan reports and selected product reports can be exported;
- evidence manifests and metadata bundles are content-free and bounded;
- Hunt records and HTTP transaction archives can be exported;
- AI Gate campaign history and transcript-related surfaces have product-specific behavior;
- Model Intake has extensive report and BOM exports;
- the findings list API can be paginated and can include detail fields, but it is not a complete,
  streaming, one-operation findings export;
- no complete Export All / Import All archive exists.

## 5. Lifecycle terminology

The UI and API should use these terms consistently.

### 5.1 Archive

Reversible deactivation of a subject or completed run. Archive hides the item from normal active views,
blocks new work, and preserves history.

Examples:

- archive a DAST target;
- archive an AI target;
- archive a completed Hunt from the default mission list.

### 5.2 Restore

Return an archived subject or run to an inactive-but-visible or active state according to product rules.
Restore must not silently restart schedules, ASM, scans, Hunts, or production AI testing.

### 5.3 Close

Move a finding or other record into a terminal business state without deleting it. Finding closure
states include resolved and false positive. Accepted risk remains a governed exception, not equivalent
to deletion.

### 5.4 Expire

Apply a policy-driven terminal state to ephemeral content or records after their retention clock elapses.
Expiration may make content eligible for purge, but it does not itself need to delete the row.

### 5.5 Content purge

Delete heavy or sensitive content while preserving content-free metadata and provenance.

Examples:

- purge HTTP request or response bodies while preserving method, URL hash, status, and timestamps;
- purge AI transcripts while preserving campaign and proof summaries;
- purge Model Intake quarantine bytes while preserving verified digests and admission history.

### 5.6 Record purge

Permanently remove records and dependent storage. This is an advanced destructive operation and must
use immutable preview, approval, bounded execution, and a durable receipt.

### 5.7 Forget / regulatory erasure

Remove or pseudonymize subject-identifying content across live tables, embedded snapshots, object
storage, logs, and documented backup boundaries. Forget is not the same as deleting a target row.

## 6. Canonical lifecycle model

### 6.1 Product plane

Every lifecycle candidate must resolve to exactly one primary product plane:

- `dast`;
- `hunt`;
- `ai_red_team`;
- `model_intake`.

Connected-device records should be supported by the same framework later, especially because Hunt can
operate on devices, but device lifecycle is not the first implementation target of this plan.

The resolver should derive product plane from existing canonical fields such as `run_kind`, finding
source, tool, owner IDs, campaign provenance, and subject tables. It should not add a new scan type.

Ambiguous rows must fail closed and remain ineligible for automatic deletion.

### 6.2 Record class

Each candidate must also resolve to a record class:

| Record class | Examples |
|---|---|
| subject | web target, AI target, model artifact subject |
| execution | scan, Hunt run, campaign, Model Intake submission |
| finding | authoritative vulnerability or safety finding |
| candidate | unverified Hunt investigation candidate |
| evidence | evidence object, evidence instance, proof artifact |
| transaction | HTTP archive request/response metadata and bodies |
| transcript | AI prompts, responses, agent traces |
| report | scan report, Model Intake report, BOM |
| decision | policy decision, admission, approval, accepted risk |
| credential metadata | non-secret binding and rotation history |
| audit receipt | command result, export event, deletion receipt |
| scratch/cache | runner scratch, temporary conversion, transient job metadata |

### 6.3 Protection flags

The lifecycle resolver must compute protection independently of requested retention criteria.

Protection flags include:

- subject is active;
- execution is pending, queued, running, cancelling, or awaiting a planner;
- finding is active;
- finding is deterministically verified;
- finding is accepted risk with a live exception;
- retest or verification is pending;
- evidence is legal hold;
- evidence is within its retention floor;
- evidence or blob is shared by an ineligible record;
- Model Intake admission is active or reassessment-required;
- policy decision, approval, or audit receipt is required by a protected record;
- export or retention execution is in progress;
- record ownership is ambiguous;
- storage deletion support is unavailable;
- record is referenced by an unfinished job.

Legal hold and active-use protection always win over age criteria.

### 6.4 Retention clock

The lifecycle engine must name the clock used for every candidate.

| Record type/state | Recommended clock |
|---|---|
| resolved finding | `closed_at` or `resolved_at` |
| false-positive finding | normalized `closed_at` |
| active finding | never auto-delete; `last_seen_at` only drives stale/retest status |
| accepted-risk finding | exception expiry/review date; not automatic purge eligibility |
| Hunt candidate | candidate `last_seen_at` or terminal verification time |
| completed scan or Hunt | `completed_at` |
| AI transcript | transcript creation/completion time |
| evidence | evidence `created_at` plus retention-class floor |
| Model Intake quarantine object | acquisition/materialization time plus digest protection |
| admission and policy decisions | explicit expiry/reassessment plus organizational audit policy |
| scratch/cache | job completion or last access |

A normalized `closed_at` is preferable to inferring closure from `updated_at`. Existing rows require a
deterministic backfill rule with a recorded migration version.

### 6.5 Lifecycle policy

Policies should be durable, versioned, and queryable. A policy is keyed by existing product plane and
record class rather than by a new scan identity.

Minimum policy fields:

- policy ID and version;
- product plane;
- record class;
- eligible lifecycle states;
- retention days;
- clock field;
- minimum retention floor;
- automatic/manual mode;
- batch limit;
- grace period;
- legal-hold behavior;
- verified/accepted-risk protection;
- export-before-purge requirement;
- local and remote content behavior;
- notification behavior;
- active date range and actor.

Unknown or incomplete policy must fail closed.

## 7. Common preview and execution contract

### 7.1 Preview

Every destructive operation starts with a server-computed immutable preview.

The preview must include:

- preview ID, schema version, creation time, expiry, and hash;
- policy ID, version, and policy hash;
- product plane and subject scope;
- normalized criteria;
- exact candidate IDs or a content-bound candidate manifest;
- counts by record class, status, severity, source, proof state, and target;
- estimated database rows and storage bytes;
- local, remote, inline, shared, missing, and unknown storage counts;
- protected and excluded counts with reasons;
- required dependent actions;
- whether an export is available or required;
- whether execution is currently allowed;
- conflicts such as active scans, active Hunts, legal hold, active admissions, or unsupported storage.

A count-only preview is insufficient.

### 7.2 Approval

Execution approval must be bound to:

- the exact preview ID and hash;
- the target or subject scope;
- action name;
- actor and reason;
- short expiry;
- policy version;
- optional export manifest hash when export-before-purge is required.

Criteria must not be resubmitted during execution. The preview is the execution input.

### 7.3 Execution

Execution must:

- reacquire protection and shared-reference locks;
- fail closed if the protected effect has changed;
- reserve bounded database and storage work;
- operate in bounded batches;
- mark durable intent before external deletion;
- coordinate local and remote object deletion;
- preserve rows when blob deletion fails unless the policy explicitly allows metadata-only completion;
- be idempotent and resumable;
- record selected, deleted, preserved, missing, failed, and retryable counts;
- refresh cached owner counts;
- emit a content-free receipt;
- support cancellation without claiming successful deletion.

### 7.4 Grace period and tombstones

For ordinary finding cleanup, consider a configurable tombstone period before physical purge:

1. exact preview and approval;
2. mark findings `pending_purge` with a purge-after time;
3. hide them from active views but allow restore during the grace period;
4. purge content and rows after the grace period through the same durable execution engine.

Legal-hold, audit, or compliance decisions should not use reversible tombstones as a substitute for
their required immutable records.

## 8. Product-specific lifecycle rules

### 8.1 DAST and Continuous ASM

#### Subject behavior

Default action: **Archive target**.

Archive should:

- set the target inactive;
- disable ASM dispatch;
- disable or pause schedules;
- reject new direct scans, batch scans resolved through the target, Hunt starts, and ASM actions;
- preserve scans, findings, endpoints, application graph, campaigns, and evidence;
- preserve encrypted credentials but make them unavailable to execution while the target is archived;
- record who archived the target and why;
- show whether work is currently running.

Archive should not silently cancel running work. The confirmation UI can offer a separate explicit
**Archive and cancel active work** action.

Restore should:

- reactivate the subject only;
- leave schedules and ASM disabled until explicitly re-enabled;
- leave credentials inactive if they expired while archived;
- surface configuration that requires operator review.

#### Finding behavior

- active findings are never automatically deleted;
- stale active findings become retest recommendations;
- resolved and false-positive findings may become retention candidates;
- accepted-risk findings remain governed by exception expiry and review;
- verified high/critical findings require an explicit override even after closure;
- evidence floors and legal hold remain authoritative;
- a deleted scan must not accidentally delete the current canonical finding merely because it was the
  original observation; scan/finding ownership requires explicit handling.

#### Hard purge

DAST target purge must show and govern:

- target row and metadata;
- scans and scan artifacts;
- findings and verification history;
- evidence objects and storage;
- HTTP transaction archives;
- credentials and principals;
- schedules and ASM campaigns;
- endpoint inventory and graph data;
- Hunt runs and candidates on the target;
- export and command receipts;
- embedded target URL copies that would remain after relational deletion.

### 8.2 Hunt

#### Run behavior

- finish and cancel remain operational terminal states;
- archive removes completed/cancelled Hunts from the default view without deleting them;
- restore returns the run to history visibility but does not resume execution;
- resume remains a separate, policy-controlled operation;
- a running or awaiting-planner Hunt cannot be purged;
- spawned scans must be terminal before run purge.

#### Candidates and findings

- unverified candidates are ephemeral and may use a shorter retention policy;
- candidates queued for verification are protected;
- promoted findings become authoritative shared findings;
- deleting or purging a Hunt must not delete promoted findings;
- finding provenance should retain a content-free Hunt/run reference even if detailed Hunt content is
  later purged;
- DAST findings produced by Hunt-spawned scans retain both DAST execution and Hunt campaign provenance.

#### Content classes

Hunt notes, context, decision trace, action results, HTTP archive, and final debrief should have separate
retention classes. HTTP bodies may expire before the content-free capability receipt and mission summary.

### 8.3 AI Red Team / AI Gate

#### Subject behavior

- archive the AI target rather than physically deleting it;
- reject new AI scans and finding replays for archived targets;
- make associated credentials and principals unavailable to execution;
- preserve campaign and finding history;
- restore the subject without automatically restoring production-mode execution or expired credentials.

#### Findings versus transcripts

AI findings and raw conversations must not share one retention clock.

Recommended separation:

- finding and verification summary: governed like other authoritative findings;
- redacted transcript: shorter policy;
- raw transcript and headers: shortest policy and strongest access control;
- deterministic/semantic judge receipt: content-free audit policy;
- campaign history: retained after detailed transcript content expires;
- request template: subject configuration policy;
- secrets: encrypted credential-store policy, never ordinary transcript retention.

Purging a transcript must not delete the finding. Purging a finding must not erase the fact that a
campaign ran or the content-free result used in a security decision.

### 8.4 Model Intake

Model Intake does not participate in generic finding purge by default.

#### Protected records

Protect records and bytes referenced by:

- active admission;
- reassessment-required admission;
- frozen evidence manifest;
- active approval receipt;
- current policy decision;
- deployment binding;
- active or resumable controller/runner job;
- legal hold or audit policy.

#### Separate lifecycle operations

- quarantine cleanup removes unprotected acquired or converted bytes;
- runner cleanup removes scratch and job metadata according to its own limits;
- report retention governs generated reports and BOM artifacts;
- revoke/decommission changes admission state;
- evidence expiration marks stale evidence and triggers reassessment;
- regulatory erasure is a dedicated, exceptional workflow.

Deleting a Model Intake finding projection must never silently change a technical outcome, admission,
policy decision, manifest, or report. If the projection is hidden, the report must still disclose the
underlying control result.

## 9. Recommended retention templates

These are product defaults for discussion, not legal advice or universal compliance requirements.
Operators must be able to configure stricter retention.

| Plane / record class | Suggested starting template | Automatic behavior |
|---|---:|---|
| DAST active finding | indefinite | retest/stale recommendation only |
| DAST resolved finding | 180 or 365 days after closure | opt-in purge |
| DAST false positive | 30 or 180 days after closure | opt-in purge |
| accepted-risk finding | through exception expiry and review | never auto-purge by age alone |
| verified critical/high finding | 365 days or organization policy | explicit override required |
| Hunt open candidate | 30 days since last activity | expire if not queued/running |
| Hunt completed run metadata | 365 days | archive first; purge opt-in |
| Hunt HTTP bodies | 30 to 90 days | content purge only |
| AI raw transcript | 30 days or less | content purge, protected if incident-linked |
| AI redacted transcript | 90 days | content purge |
| AI finding | 180 or 365 days after closure | shared finding policy |
| Model Intake unprotected quarantine | 30 days | existing dedicated cleanup |
| Model Intake scratch | hours or days | existing runner cleanup |
| Model Intake admission evidence | admission/audit policy | no generic automatic purge |
| standard evidence | existing 365-day floor | evidence-retention engine |
| audit evidence | existing long audit floor | evidence-retention engine |
| legal-hold evidence | indefinite | never automatic |

The UI should prominently distinguish **not seen recently** from **closed long enough to purge**.

## 10. Operational export plan

Operational exports support triage, reporting, integration, and pre-purge review. They are distinct from
full system backup.

### 10.1 Findings export

Add a server-side findings export whose filters match the Findings list:

- product plane;
- source type;
- subject/target;
- status;
- severity;
- proof state;
- verification state;
- age and lifecycle clock;
- scan, Hunt, campaign, and Model Intake context where applicable;
- search and selected IDs.

Formats:

- CSV summary for analysts;
- versioned JSON for lossless structured export;
- SARIF 2.1 for compatible security integrations;
- optional ZIP bundle with manifests and redacted evidence metadata.

Requirements:

- stream or cursor through all selected rows;
- do not inherit list-page limits;
- redact secrets by default;
- treat raw requests, responses, transcripts, and model evidence as separately authorized content;
- include export schema version, filters, counts, generated time, and hashes;
- record a content-free export event;
- disclose omissions and expired content;
- support **Export current view**, **Export selected**, and **Export all findings**.

### 10.2 Product-native exports

- DAST: finding export, scan reports, evidence manifest, optional HTTP archive;
- Hunt: Hunt record, decision trace, notes, findings references, optional HTTP archive;
- AI Red Team: campaign history, findings, redacted transcript, optional authorized raw transcript;
- Model Intake: JSON/HTML/SARIF report, manifests, CycloneDX, SPDX, AIBOM, license BOM, notices,
  and admission/policy receipts.

Destructive previews should link to the relevant export without requiring export as a universal blocker.
Organizations can enable an export-before-purge policy when required.

## 11. Later phase: Export All / Import All

Full-system portability is intentionally a later phase. It should be designed after lifecycle ownership,
retention, and product-native export schemas are stable.

### 11.1 Goals

- migration between ShakerScan installations;
- disaster recovery;
- offline organizational archive;
- reproducible incident handoff;
- development/test environment seeding with redacted data;
- versioned backup validation.

### 11.2 Export All contents

The archive may include:

- web targets and target metadata;
- AI targets;
- scans, campaigns, and run summaries;
- Hunt runs, actions, candidates, notes, and provenance;
- findings, exceptions, and verification history;
- evidence objects, evidence instances, and manifests;
- HTTP transaction archives according to content policy;
- Model Intake submissions, subjects, evidence, reports, admissions, and events;
- schedules and automation policy;
- lifecycle policies and legal holds;
- non-secret credential metadata;
- command, approval, export, retention, and deletion receipts;
- object-storage inventory and content hashes;
- schema and build metadata.

### 11.3 Archive modes

#### Portable redacted archive

- excludes reusable secrets;
- excludes or redacts sensitive raw content by default;
- includes content hashes and omission reasons;
- suitable for migration, sharing, and testing.

#### Encrypted recovery archive

- may include encrypted credential material and protected evidence;
- requires an explicit operator action and a separate archive encryption key or passphrase;
- never exports plaintext reusable secrets;
- records encryption scheme and key-derivation parameters without recording the passphrase;
- should support key rotation through re-export rather than in-place mutation.

### 11.4 Export manifest

The top-level manifest should include:

- archive schema version;
- source ShakerScan version and build fingerprint;
- export time and actor;
- archive mode;
- included product planes and record classes;
- table/entity counts;
- object counts and total bytes;
- content hashes and Merkle or deterministic bundle root;
- encryption metadata;
- redaction profile;
- omitted classes and reasons;
- minimum compatible importer version;
- required migrations;
- product-native sub-manifest hashes.

### 11.5 Import All safety

Import begins with a non-mutating preview.

The preview must report:

- schema compatibility;
- archive-integrity result;
- creates, merges, conflicts, and skips;
- ID collisions;
- canonical target collisions;
- missing blobs;
- unsupported product records;
- credential material availability;
- policy and legal-hold conflicts;
- storage required;
- records that will remain disabled;
- migration steps.

Safe defaults:

- never start or resume scans, Hunts, AI campaigns, or Model Intake jobs;
- import targets archived or preserve archived state, but do not infer activation;
- import schedules and ASM policies disabled;
- do not reuse expired or source-install approval receipts;
- do not silently overwrite local records;
- preserve stable IDs when conflict-free and use an explicit remapping manifest otherwise;
- preserve foreign-reference integrity across product planes;
- validate every content hash before binding evidence;
- quarantine unknown or incompatible records;
- make import resumable and idempotent;
- emit a signed or content-hashed import receipt.

### 11.6 Conflict policy

Supported conflict modes should be explicit:

- **create only**: reject all collisions;
- **merge safely**: merge only canonical identities with defined product-specific rules;
- **restore missing content**: fill verified missing blobs/rows without changing newer local state;
- **replace**: reserved for controlled disaster recovery and requires a separate destructive preview.

Replace must never be the default.

### 11.7 Portability package structure

Illustrative structure:

```text
shakerscan-export/
  manifest.json
  lifecycle-policies.json
  subjects/
    dast-targets.jsonl
    ai-targets.jsonl
    model-intake-subjects.jsonl
  executions/
    scans.jsonl
    hunts.jsonl
    campaigns.jsonl
    model-intake-submissions.jsonl
  findings/
    findings.jsonl
    verifications.jsonl
    exceptions.jsonl
    findings.sarif
  evidence/
    manifest.jsonl
    objects/...
  transactions/
    manifest.jsonl
    objects/...
  model-intake/
    manifests.jsonl
    admissions.jsonl
    reports/...
  configuration/
    schedules.jsonl
    policies.jsonl
    credential-metadata.jsonl
  audit/
    approvals.jsonl
    commands.jsonl
    exports.jsonl
    retention.jsonl
```

The actual format should prefer streaming JSON Lines and content-addressed objects so large installations
do not require the API process to hold the archive in memory.

## 12. Proposed API surfaces

Exact routes are subject to implementation review. The important requirement is one lifecycle contract,
not a route proliferation.

### 12.1 Subject archive and restore

```text
POST /targets/{id}/archive
POST /targets/{id}/restore
POST /ai/targets/{id}/archive
POST /ai/targets/{id}/restore
POST /hunts/{id}/archive
POST /hunts/{id}/restore
```

Existing DELETE compatibility routes may delegate to Archive during a deprecation window.

### 12.2 Lifecycle preview and execution

```text
POST /data-lifecycle/previews
GET  /data-lifecycle/previews/{id}
POST /data-lifecycle/previews/{id}/approve
POST /data-lifecycle/previews/{id}/execute
GET  /data-lifecycle/executions
GET  /data-lifecycle/executions/{id}
POST /data-lifecycle/executions/{id}/resume
POST /data-lifecycle/executions/{id}/cancel
```

Product-specific APIs such as Model Intake quarantine cleanup can remain public compatibility adapters
while dispatching through or sharing the canonical lifecycle primitives where practical.

### 12.3 Policies and holds

```text
GET  /settings/data-lifecycle
PUT  /settings/data-lifecycle
GET  /data-lifecycle/holds
POST /data-lifecycle/holds
POST /data-lifecycle/holds/{id}/release
```

### 12.4 Operational exports

```text
POST /findings/export
GET  /exports/{id}
GET  /exports/{id}/download
```

### 12.5 Later portability APIs

```text
POST /portability/exports/preview
POST /portability/exports
GET  /portability/exports/{id}
POST /portability/imports/preview
POST /portability/imports
GET  /portability/imports/{id}
POST /portability/imports/{id}/resume
```

Large archives should use asynchronous jobs and content-addressed storage, not synchronous in-memory
responses.

## 13. UI plan

### 13.1 Targets

- change Delete wording to Archive;
- show impact summary: schedules, ASM state, active work, findings, and scans preserved;
- offer separate cancellation of active work;
- add Archived filter;
- add Restore;
- explain that archive does not delete findings;
- reserve Hard purge for an advanced lifecycle screen.

### 13.2 Findings

Replace the current count-only Advanced cleanup panel with:

- product plane selector;
- target/subject selector;
- eligible status selector;
- 30, 180, and 365-day presets plus custom policy;
- explicit clock label such as “closed for” rather than “not seen in”;
- severity, proof, source, and evidence-size breakdown;
- protected/excluded counts and reasons;
- exact preview expiry;
- export action;
- approval and typed confirmation for risky overrides;
- execution progress and resumable failure state.

The first release should allow execution only for DAST resolved/false-positive findings even if the
preview UI can classify other products.

### 13.3 Hunt

- add Archived Hunts filter;
- add Archive after finish/cancel;
- retain separate HTTP archive export/purge controls;
- show candidate-retention status;
- show promoted findings that will be preserved during Hunt content purge.

### 13.4 AI Red Team

- add Archived AI targets filter and Restore;
- display finding, transcript, campaign, and credential retention separately;
- show redacted versus raw export choices;
- warn that transcript purge preserves findings and campaign summaries.

### 13.5 Model Intake

- keep quarantine and runner cleanup in Model Intake Status;
- display protected digests and active admission reasons;
- link to lifecycle policy without exposing Model Intake to generic finding deletion;
- expose decommission/revoke/expire language instead of generic Delete.

### 13.6 Data Lifecycle settings

Create `/settings/data-lifecycle` with:

- policies by product and record class;
- manual or automatic mode;
- retention and grace periods;
- batch limits and maintenance windows;
- export-before-purge policy;
- legal holds;
- storage estimates;
- last and next run;
- execution history and incomplete operations.

### 13.7 Later portability UI

Create a Backup & Migration area with:

- Export All preview;
- redacted versus encrypted-recovery mode;
- storage estimate and included classes;
- archive progress and integrity verification;
- Import All preview;
- conflicts and ID mappings;
- disabled-on-import summary;
- resumable import history.

## 14. Phased implementation plan

### Phase 0 — Safety stabilization

**Objective:** Stop inactive subjects and broad cleanup from causing surprising execution or deletion.

Deliverables:

- reject direct DAST target scans for inactive targets;
- exclude inactive targets from scheduled execution;
- verify every target-resolved Hunt and ASM entry point rejects inactive targets;
- validate IDs and return controlled 400/404 responses;
- change user-facing target action wording from Delete to Archive where possible;
- temporarily restrict bulk finding cleanup execution to explicitly selected safe statuses, or disable
  destructive execution until Phase 3 while retaining dry run;
- exclude Model Intake, AI Gate, and Hunt findings from generic cleanup execution unless explicitly and
  safely supported;
- add focused regression tests for current deletion routes.

Exit criteria:

- no new work can start through an inactive web target;
- count-only cleanup cannot delete active or cross-product findings by default;
- existing read and report behavior remains compatible.

### Phase 1 — Shared lifecycle classification and read-only impact preview

**Objective:** Build the cross-product ownership model without enabling new deletion.

Deliverables:

- canonical product-plane resolver;
- record-class resolver;
- retention-clock resolver;
- protection evaluation;
- dependency and storage-impact resolver;
- read-only preview model and schema;
- durable preview storage, expiry, and hash;
- product adapters for DAST, Hunt, AI Red Team, and Model Intake classification;
- unknown/ambiguous ownership reporting;
- preview UI for internal/operator validation.

Exit criteria:

- representative records from all four planes classify deterministically;
- ambiguous records fail closed;
- previews enumerate exact effects and protected exclusions;
- previews do not mutate application state.

### Phase 2 — DAST Archive and Restore

**Objective:** Establish correct reversible subject lifecycle for web targets.

Deliverables:

- Archive and Restore API operations;
- compatibility behavior for the existing DELETE route;
- transactional disabling of schedules and ASM;
- execution gates across direct scans, batch scans, Hunt, schedules, and ASM;
- Archived targets UI and restore flow;
- explicit handling of already-existing archived targets during creation;
- archive/restore command receipts;
- active-work warning and optional separate cancellation.

Exit criteria:

- archived targets preserve scans and findings;
- archived targets cannot produce new work;
- restore does not silently restart automation;
- UI and API use consistent lifecycle language.

### Phase 3 — DAST finding retention and operational export

**Objective:** Replace unsafe age-based DAST deletion with the canonical preview/execution workflow.

Deliverables:

- DAST findings CSV, JSON, SARIF, and manifest export;
- exact finding-retention preview;
- normalized closure clock/backfill;
- safe status eligibility;
- 30, 180, and 365-day presets;
- evidence protection and blob coordination;
- bounded batches;
- optional grace-period tombstones;
- approval-bound execution;
- resumable failure handling;
- durable deletion receipts;
- count and summary reconciliation.

Exit criteria:

- active, accepted-risk, verified protected, legal-hold, and in-use records are not accidentally deleted;
- executed set matches the approved preview;
- no local or remote evidence blob becomes silently orphaned;
- large retention operations remain bounded and resumable;
- exported counts match preview counts for eligible records.

### Phase 4 — Hunt lifecycle adapter

**Objective:** Add Hunt-specific archive, candidate expiration, and content retention without deleting
authoritative findings.

Deliverables:

- Hunt Archive/Restore;
- run-protection rules;
- candidate-retention policy;
- promoted-finding preservation;
- Hunt content-class preview;
- coordinated HTTP archive and note/trace content purge;
- Hunt export manifest referencing preserved findings;
- provenance tombstone after detailed Hunt purge.

Exit criteria:

- purging Hunt content never deletes promoted findings;
- active or resumable Hunt work blocks purge;
- content-free mission and capability history remains trustworthy.

### Phase 5 — AI Red Team lifecycle adapter

**Objective:** Separate AI subject, finding, transcript, campaign, and credential lifecycles.

Deliverables:

- AI target Archive/Restore;
- execution and replay gates;
- transcript retention classes;
- raw/redacted/content-free separation;
- AI finding retention through the shared finding contract;
- campaign-summary preservation;
- credential availability rules for archived targets;
- AI export manifest and redaction disclosure.

Exit criteria:

- transcript purge preserves authoritative findings and campaign summaries;
- finding purge does not erase campaign audit facts;
- archived targets cannot spend credentials or queue work;
- raw content requires explicit authorization.

### Phase 6 — Model Intake lifecycle adapter

**Objective:** Integrate Model Intake protections without weakening its dedicated retention controls.

Deliverables:

- Model Intake product-plane and record-class adapter;
- protected-digest resolver;
- admission, manifest, approval, policy, and deployment protection rules;
- shared visibility for quarantine and runner cleanup;
- exclusion from generic finding purge;
- decommission/revoke/expire lifecycle mapping;
- Model Intake export manifest integration;
- regulatory-erasure preview design.

Exit criteria:

- active or reassessment-required admission evidence cannot be purged;
- Model Intake cleanup remains plan-hash and approval protected;
- deleting or hiding a finding projection cannot change or conceal admission state.

### Phase 7 — Unified policies, legal hold, and opt-in automation

**Objective:** Make safe lifecycle behavior configurable and operationally observable.

Deliverables:

- durable lifecycle policy settings;
- `/settings/data-lifecycle` UI;
- legal-hold creation and release;
- maintenance windows and bounded batches;
- manual versus automatic modes;
- before/after notifications;
- unfinished-operation recovery;
- storage forecasting;
- policy version and audit history;
- default automation disabled.

Exit criteria:

- automatic runs execute the same preview/execution engine as manual runs;
- legal hold overrides every automatic policy;
- policy changes do not mutate already approved previews;
- operators can explain every retained, excluded, and deleted record.

### Phase 8 — Advanced hard purge and regulatory erasure

**Objective:** Support explicit permanent removal without relying on blind database cascade.

Deliverables:

- DAST and AI subject hard-purge previews;
- product-aware dependency traversal;
- embedded target-content inventory;
- storage cleanup and orphan verification;
- active-work and legal-hold blocks;
- privacy-oriented Forget mode;
- documented backup and audit boundaries;
- content-free erasure receipt;
- separate controlled handling for Model Intake subjects.

Exit criteria:

- hard purge has a complete and reviewed blast-radius preview;
- object storage and database state reconcile;
- retained audit receipts do not contain removed sensitive content;
- Forget behavior is explicitly documented for backups and external systems.

### Phase 9 — Export All / Import All

**Objective:** Provide portable, versioned, verified migration and disaster recovery.

Dependencies:

- stable lifecycle ownership model;
- stable product-native export schemas;
- stable evidence and storage manifests;
- import-safe canonical merge behavior;
- policy and legal-hold serialization.

Deliverables:

- archive manifest and package format;
- redacted portable mode;
- encrypted recovery mode;
- streaming, chunked Export All;
- export integrity verifier;
- non-mutating Import All preview;
- conflict and ID-remapping engine;
- disabled-on-import execution policy;
- bounded, resumable, idempotent import;
- post-import consistency verifier;
- export/import receipts;
- Backup & Migration UI.

Exit criteria:

- a representative installation can round-trip through export/import without losing supported
  relationships;
- secrets never appear in plaintext archives;
- imported automation remains disabled;
- integrity failures block binding and activation;
- repeated import is idempotent or reports explicit conflicts;
- source and restored record counts and hashes reconcile.

### Phase 10 — Operational hardening

**Objective:** Validate lifecycle behavior at production scale and across failures.

Deliverables:

- scale tests with millions of findings/evidence references;
- object-store fault injection;
- database failover and cancellation tests;
- upgrade/rollback coverage during unfinished lifecycle work;
- retention and portability metrics;
- operator runbooks;
- release-readiness checklist;
- generated functionality-reference updates.

Exit criteria:

- no unbounded API memory behavior;
- every partial failure is visible and resumable or safely terminal;
- upgrade and rollback preserve durable intent;
- operational receipts reconcile with storage and database state.

## 15. Testing strategy

### 15.1 Classification tests

- every supported `run_kind` resolves to the expected plane;
- every finding source/tool/owner combination resolves deterministically;
- Hunt-spawned DAST findings retain dual provenance without ambiguous ownership;
- Model Intake findings always receive Model Intake protection;
- malformed and legacy records fail closed.

### 15.2 Archive tests

- archive preserves scans, findings, evidence, and reports;
- archived DAST targets cannot be scanned through any route;
- archived targets cannot run schedules or ASM;
- archived AI targets cannot run scans or finding replays;
- restore does not enable automation;
- archive is idempotent;
- invalid identifiers return controlled errors.

### 15.3 Preview tests

- exact candidate set and hash are stable;
- preview expires;
- policy change invalidates execution;
- newly eligible rows are not added at execution;
- newly protected rows block or are preserved according to policy;
- shared blobs are counted correctly;
- storage byte estimates reconcile with manifests;
- legal hold is always excluded.

### 15.4 Execution tests

- approval target/action/hash mismatch is rejected;
- active finding and active admission changes block deletion;
- local deletion failure preserves retry state;
- remote deletion failure preserves retry state;
- cancellation does not claim completion;
- database failure after blob deletion resumes safely;
- database success before external deletion cannot orphan storage silently;
- replay is idempotent;
- owner counts and dashboards reconcile.

### 15.5 Product boundary tests

- DAST cleanup cannot select AI Gate, Hunt, or Model Intake findings by accident;
- Hunt purge does not delete promoted findings;
- AI transcript purge does not delete findings;
- AI finding purge does not delete campaign history;
- Model Intake finding operations do not alter admission or policy decisions;
- protected Model Intake digests never enter a generic cleanup candidate set.

### 15.6 Export tests

- filters match Findings UI semantics;
- CSV escaping prevents formula injection;
- JSON schema is versioned and stable;
- SARIF validates against the supported schema;
- secret-shaped values are redacted;
- raw export requires explicit authorization;
- manifest counts and hashes reconcile;
- large exports stream without unbounded memory;
- exports disclose omitted/expired content.

### 15.7 Export All / Import All tests

- archive integrity failure blocks import;
- version incompatibility is explained before mutation;
- canonical target collisions follow selected conflict policy;
- IDs and foreign references round-trip;
- missing content is quarantined or rejected;
- schedules and automation import disabled;
- approvals are not reusable across installations;
- encrypted archives reject incorrect keys without partial import;
- repeated imports are idempotent;
- post-import counts, hashes, and product reports reconcile.

## 16. Observability and audit

Metrics should include:

- previews created, expired, approved, and invalidated;
- candidates and protected exclusions by product/record class/reason;
- database rows and bytes selected/deleted/preserved;
- local and remote deletion successes, misses, and failures;
- resumable operations;
- policy version used;
- archive/restore counts;
- stale active findings and recommended retests;
- automated retention runs and blocked runs;
- export/import bytes, records, duration, conflicts, and integrity failures;
- orphan-detection results.

Audit records should be content-free by default and retain:

- actor;
- reason;
- action;
- scope;
- preview and policy hashes;
- approval receipt;
- result counts;
- manifest hashes;
- timestamps;
- failure/retry state.

They should not retain deleted request bodies, transcripts, credentials, model files, or other sensitive
content merely to prove that deletion occurred.

## 17. Concurrency and failure handling

Lifecycle actions intersect with scanners, Hunts, exports, and external storage. Required controls:

- advisory or equivalent locks over exact subject and blob identities;
- row locks when validating mutable protection state;
- durable deletion intent before non-transactional filesystem/S3 work;
- bounded worker pools for blocking storage I/O;
- cancellation shielding until deletion threads return;
- deterministic retry keys;
- storage delete verification;
- shared-reference re-evaluation;
- retention preview invalidation on ownership or policy drift;
- startup recovery for unfinished operations;
- upgrade checks that block unsafe schema migration while destructive work is executing.

## 18. Migration and compatibility

- retain existing DELETE target endpoints as archive compatibility adapters for a documented period;
- change response status from ambiguous `deleted` to `archived`, with a compatibility field if needed;
- retain dry-run compatibility for finding cleanup while moving execution to preview IDs;
- do not silently reinterpret existing scheduled cleanup records;
- backfill finding `closed_at` deterministically and record the source of the inferred timestamp;
- version every lifecycle preview, receipt, export, and portability archive;
- keep old exports readable through explicit import migrations where feasible;
- update generated OpenAPI and functionality documentation in the same release as route changes.

## 19. Security and privacy considerations

- retention configuration is security-sensitive state;
- preview and execution endpoints require operator authorization appropriate to deployment mode;
- export can be more sensitive than deletion and needs separate authorization;
- raw AI transcripts and HTTP archives can contain secrets even after structured redaction;
- CSV output must prevent spreadsheet formula execution;
- archive downloads need short-lived access and no secret-bearing URLs;
- full recovery archives need strong authenticated encryption;
- import treats every archive field as untrusted input;
- imports must never execute embedded scripts, Postman scripts, OpenAPI external references, model code,
  shell commands, or planner-supplied actions;
- imported targets and schedules remain inactive until explicitly reviewed;
- privacy erasure must document database backup, object-store versioning, external export, and audit
  retention boundaries.

## 20. Decisions to make before implementation

1. Should ordinary finding deletion use a grace-period tombstone, and what is the default duration?
2. Which status transitions populate normalized `closed_at`?
3. Should verified high/critical findings ever be automatically purgeable?
4. Should accepted-risk findings remain indefinitely or follow exception expiry plus a separate retention
   period?
5. Which content-free Hunt and AI campaign facts must remain after detailed content purge?
6. Which audit classes require an organizationally configurable minimum floor?
7. Should export-before-purge be optional, policy-required, or required only above an impact threshold?
8. How should source-install approvals be represented after Import All without making them executable?
9. Which Model Intake records can ever participate in regulatory erasure after an artifact was admitted?
10. What backup and object-store versioning boundaries can ShakerScan verify versus only document?
11. Should Restore preserve previous schedules as disabled drafts or create new schedule versions?
12. What is the maximum synchronous preview size before the operation becomes an asynchronous job?

## 21. Recommended immediate backlog

The first actionable backlog should be limited to planning and Phase 0/1 design:

1. write the lifecycle classification contract and representative fixtures;
2. enumerate every product-owned table, blob type, and weak/textual reference;
3. define Archive and Restore semantics for web and AI targets;
4. define finding closure and protection semantics;
5. define the immutable preview schema by extending existing retention concepts;
6. produce DAST read-only impact previews against test fixtures;
7. add regression tests for inactive-target execution leaks and cross-product finding cleanup;
8. specify operational findings export schemas;
9. review the plan against Model Intake admission and evidence guarantees;
10. approve the DAST Phase 2/3 implementation boundary before enabling new destructive execution.

## 22. Completion definition

This initiative is complete when:

- users can explain what Archive, Restore, Close, Expire, Content Purge, Record Purge, and Forget do;
- inactive subjects cannot generate new work;
- no generic cleanup can cross product boundaries accidentally;
- every destructive execution matches an immutable reviewed preview;
- findings, evidence, transcripts, model artifacts, approvals, and audit records use appropriate clocks;
- legal hold and active-use protections fail closed;
- storage and database deletion reconcile;
- operational exports are complete and redacted by default;
- automatic retention is opt-in, bounded, and observable;
- Export All / Import All can safely round-trip supported cross-product state in a later phase;
- no workflow introduces a new scan type, Hunt engine, scope ledger, or untrusted execution path.

## 23. References

Internal:

- `AGENTS.md`
- `docs/ai-native-architecture-rfc.md`
- `docs/product-model.md`
- `docs/functionality-reference.md`
- `docs/model-intake-security-review-roadmap.md`
- `docs/multi-node-architecture.md`
- `api/targets/router.py`
- `api/finding_routes/router.py`
- `api/evidence_routes/router.py`
- `api/hunt/`
- `api/ai_targets/router.py`
- `api/model_intake/router.py`
- `api/runtime/http_archive_router.py`
- `api/target_dedupe.py`
- `db/init.sql`

External standards and interoperability references:

- NIST SP 800-92, *Guide to Computer Security Log Management*:
  <https://csrc.nist.gov/pubs/sp/800/92/final>
- OASIS SARIF 2.1.0:
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- GitHub documentation on third-party SARIF files:
  <https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files>
