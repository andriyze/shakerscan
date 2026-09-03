# Release process

**Status:** current immutable-candidate publication process; revised 2026-09-03.

ShakerScan releases use one immutable source commit and one set of image digests. Protecting
`main`, building, accepting, publishing, and moving the stable channel are separate gates, and each
gate runs *before* the change it guards becomes visible to anyone.

## 0. Repository controls

`.github/rulesets/main.json` is the source of truth for how `main` is protected. It requires a pull
request, resolved review threads, linear history, no bypass actors, and three required checks that
report on every pull request:

| Check | Workflow | What it proves |
| --- | --- | --- |
| `commit-policy` | `commit-policy.yml` | A `release:` commit carries only metadata (`VERSION`, notes, ledger, `install/STABLE_VERSION`). |
| `python-suite` | `python-suite.yml` | The complete partitioned Python suite plus every static gate (generated inventories and contracts, installer manifest, import closure, module size, documentation policy, surface dispositions, target transport) from the locked dependency set. |
| `smoke` | `e2e-pr.yml` | The fast deterministic E2E areas (platform, AI Gate, Hunt) and the real-stack browser acceptance on the built stack. |

Each check runs once per change. The candidate reuses the `python-suite` report for its exact SHA
instead of rerunning the suite inside the image, and the slow E2E areas (DAST against Juice Shop,
Model Intake), the recall benchmark, the fault receipts, and the upgrade rehearsal run only in
candidate certification, on the final images. `v2-contracts.yml` is a manual stack acceptance and
runs nothing on pull requests.

A committed ruleset is a promise until it is imported. Apply and verify it with:

```bash
python3 scripts/apply_main_ruleset.py --apply    # create or update the live ruleset from the file
python3 scripts/apply_main_ruleset.py --check    # exit 1 when main is under-protected
```

The **Release candidate** workflow runs the same `--check` and refuses to build from an
unprotected `main`. The ruleset does not require an approving reviewer; CODEOWNERS routes review
requests only. Store Docker Hub credentials as repository secrets.

## 1. Freeze and build a candidate

Merge the intended commit through protected `main`, obtain successful exact-SHA CodeQL, then run
**Release candidate** with `version`, the exact 40-character SHA, and the CodeQL run ID. Optional
real-fleet Scan parity, Model Intake physical acceptance, and Connected Device physical acceptance
run IDs may be supplied when those support boundaries are being qualified.

The workflow verifies every supplied workflow identity, conclusion, and head SHA; checks that
`install/MANIFEST.sha256` is current and that `main` is protected; reuses the `python-suite` report
for the exact SHA (running the suite in the image only when a metadata-only merge skipped it); runs
the installer smoke, the external wire ceilings, and the native builds; bakes version plus source revision into `/opt/shakerscan/release-manifest.json`;
pushes only `candidate-<sha>-<run-id>` multi-architecture manifests; and uploads
`release-candidate-receipt.json`. The receipt binds the four final image digests, the signed
provenance verification, and the digest of the installer manifest. Each platform build publishes
BuildKit provenance and an SBOM; the final multi-architecture digests receive GitHub/Sigstore build
attestations that are verified immediately. Vulnerability scans of the four final manifests run in
parallel with certification; both must succeed for the run to be promotable.

Certification runs the exact-manifest installed-stack E2E, the stateful previous-stable upgrade and
rollback (baseline digests read from `RELEASES.md`), the preservation matrix, the DAST recall
benchmark, and the fault receipts, then seals the promotion-ready receipt.

Never deploy by a mutable version or `latest` during acceptance. Use the candidate tag or, for the
strongest binding, the digests in the receipt. Any application-code change creates a new candidate
SHA and requires a new candidate build.

## 2. Optional physical support-boundary acceptance

Operators may qualify Model Intake KVM, an authorized physical Connected Device, or a clean
hosted-installer control plane with multiple broker VPS nodes on the exact candidate digest. These
receipts exercise host-specific support boundaries; they are optional operational evidence, not a
release-promotion requirement. An omitted receipt is recorded as not run, never passed.

## 3. Publish the immutable version

Run **Promote release** with the version, candidate SHA, and candidate workflow run ID. The workflow
verifies that the candidate run succeeded for the exact SHA, downloads its receipt, checks the
installer manifest digest against the checked-out tree, compares every registry digest, re-verifies
every signed provenance attestation, creates version tags from those digests, and creates an
**annotated** `v<version>` git tag on the candidate commit. It performs no build. The GitHub Release
attaches `release-image-lock.env` (four image digests plus `RUNTIME_MANIFEST_SHA256`) and the
certified `release-candidate-receipt.json`, so the evidence outlives workflow-artifact retention.
`latest` and the installer remain unchanged.

Promotion must happen within the candidate artifact's 30-day retention; afterwards, cut a new
candidate. Expired `candidate-*` tags are removed by the **Candidate tag cleanup** workflow, which
is a dry run unless dispatched with `delete: true`.

## 4. Public smoke and stable promotion

Test the published version as a new user would. At minimum run
`scripts/public_install_smoke.sh <version>`, which uses the public curl installer in an empty
temporary home and verifies the installed version plus UI, API, and worker identity. The installer
verifies every downloaded runtime file against `install/MANIFEST.sha256` and the manifest against
the published lock, so a moved tag or a mismatched tree fails the install instead of activating.
Model Intake is explicitly excluded from this release's public smoke receipt. Continue with the
stateful upgrade, rollback, doctor/status, agent/MCP launch, and a bounded scan. Preserve the
generated content-free receipt and hash.

Then run **Promote stable channel** with the version and smoke receipt. In this order, the workflow:

1. validates the receipt schema, hash, source SHA, and image digests against the release lock;
2. moves each `latest` alias to the already-published version digest without rebuilding;
3. pushes a `release/stable-<version>` branch that bumps `install/STABLE_VERSION` and prints the
   `gh pr create` command in the run summary.

Open and merge that pull request last. The hosted installer resolves `install/STABLE_VERSION`
from `main` at request time, so the merge is the public promotion; every gate above has already
run by then. The Cloudflare worker serves the bootstrap script from the resolved release tag, so
`main` no longer carries live installer code.

## Stop conditions

Stop and cut a new candidate for any identity mismatch, stale fleet, failed or missing coverage,
heartbeat authority loss, migration failure, digest drift, build-receipt mismatch, manifest
mismatch, unaccepted high/critical dependency finding, or public smoke regression. Roll back by
pinning the previous immutable version/digest; do not overwrite an existing version tag.
