# Clean-install findings — 2026-09-20

Source: 2.3.9 installed from the public installer on clean Ubuntu 24.04 EC2 hosts
(t3.xlarge control plane `3.92.68.103`, t3.large worker node `18.206.55.61`,
c5.metal KVM host `54.211.166.112`), driven through the CLI, the API and the browser UI,
plus the local dev stack. Priority: **standalone server > fleet > Model Intake.**
Status column: `open`, `fixed` (on this branch, verified), `fixed-unverified`, `deferred`.

## Standalone server (highest)

| # | Finding | Where | Status |
|---|---|---|---|
| S1 | New Scan form loses input entered before the async contract preview arrives: the typed target and the first "Allow active testing" click were dropped and submit answered "Enter at least one target URL." | `ui/src/app/scan/new/page.tsx` | not a product defect: retested on the branch build, a value set through the input's own change event stays and submits; the original loss came from the browser-automation tool not delivering keystrokes to the tab (it failed the same way in the Targets search box). A hydration gate added for it was reverted. |
| S2 | Every Linux scan reports DNS posture `partial`: systemd-resolved answers DS/DNSKEY with SERVFAIL (`NoNameservers`), and the DoH fallback only covered timeouts. | `api/capabilities/dns.py` | fixed, verified on the branch build (Baseline DNS `success` on the KVM host where 2.3.9 reports `partial / adapter_failed`) |
| S3 | `SHAKERSCAN_START=0` installs the runtime but not Docker; the next `shakerscan start` says *"Run './scanner.sh install-deps'"* — the installed command is `shakerscan`. | `scanner.sh` | fixed, verified on the host (installed wrapper prints `shakerscan install-deps`, a checkout prints `./scanner.sh install-deps`) |
| S4 | Live scan activity strips the `[Discovery]` / `[Shard N]` child label, so on a parallel scan an operator cannot tell which child produced a line. | `ui/src/lib/scanDetailPresentation.mjs` (`scanLogEntry`) | fixed, verified in the UI (parallel scan log lines carry the `Shard 1` label) |
| S5 | A scan that lost its worker lease (infrastructure restart) is told "Review target and retry"; the target had nothing to do with it. | `ui/src/app/scans/[id]/page.tsx` (`scanFailureRecommendation`) | fixed, verified (a scan killed by a stack restart shows 'Retry scan' with the worker-queue wording) |
| S6 | Targets page truncates the primary label to "sha…" for `https://shakerscan.com` at a normal desktop width. | `ui/src/app/targets/page.tsx` | fixed, verified (Targets page shows `shakerscan.com` in full at desktop width) |
| S7 | Dashboard on a fresh install: "What changed is hidden in scoped mode. Historical change events do not all carry a cohort binding yet…" is internal vocabulary shown to a first-time user. | `ui/src/app/page.tsx` | fixed, verified (dashboard reads 'Recent changes are shown per cohort…') |
| S8 | Worker Pools shows "Connected devices: not ready — no fresh device worker" for an opt-in pool that was never started; it reads like a fault. | `ui/src/app/workers/page.tsx` | fixed, verified (Worker Pools shows 'not started' and the server remedy naming `shakerscan devices start`) |
| S9 | The resolved-families preview lags the preset radio by a second or two, so the line an operator reads to confirm what will run is briefly wrong. | `ui/src/app/scan/new/page.tsx` | fixed-unverified (preview state is cleared before each reload; unit-tested, not timed in a browser) |
| S12 | A target with a certificate the client will not trust (www.shakerscan.com presented a self-signed certificate during this test) fails the whole HTTP baseline as `adapter_failed / unclassified_adapter_error`, blocks the redirect and security.txt actions, and the report says only "adapter failed" while every Go-based probe carries on. The cause is in the HTTP archive (`request_error:ConnectError`) but not in the action reason. | `api/capabilities/http.py`, `api/scan/activity.py` | fixed-unverified (classified as `tls_certificate_untrusted`; the question of whether the bound baseline should verify TLS at all is open) |
| S13 | Every navigation prefetched all fourteen sidebar routes (each answered 307 then 200 by the Next server). Not the cause of the slow Targets/Scans skeletons seen through the automation browser: that tab was hidden, and React hydrates a `Suspense` boundary (`useSearchParams`) at idle priority, which a hidden tab starves; a visible tab hydrates on first paint. Same on 2.3.9. | `ui/src/components/Sidebar.tsx` | fixed (`prefetch={false}`, verified: no route prefetches after navigation); the skeleton delay is a harness artifact, not a defect |
| S10 | Raw `docker compose up -d worker` resets the launcher's worker scale (20 → 1). The docs say not to use raw compose, but a product error message (M2) sends the operator there. | `scanner.sh` / docs | deferred (covered by M2 fix + doc note) |

## Fleet (medium)

| # | Finding | Where | Status |
|---|---|---|---|
| F1 | `fleet init` restarts the whole stack (backup, convert, rollback) while scans are running; a running scan died with `execution_lease_lost`, correctly not replayed. Init must refuse or warn while work is queued or running. | `scripts/fleet_cli.py` | fixed, verified read-only (`fleet preflight` on the branch prints the 'Queued or running scans' check; init refusal covered by unit tests) |
| F2 | Preflight `[PASS] HTTP port 80 / HTTPS port 443: available` only checks that the ports are free locally; with the cloud security group closed init still spends 120 s on ACME then rolls back. The `[WARN] Public API reachability … the managed HTTPS gateway will be provisioned` wording implies the gateway will fix reachability. Needs an external reachability probe and an explicit "open 80/443 in the cloud firewall" message. | `scripts/fleet_cli.py` | fixed, verified read-only (preflight prints the firewall wording and the 'Inbound firewall' line; the gateway-log diagnosis is unit-tested) |
| F3 | Rollback leaves `.shakerscan-fleet/control/` (generated control identity/CA) and `backups/` behind while `/health.fleet` reports "not initialized". | `scripts/fleet_cli.py` | fixed-unverified (unit-tested rollback removes generated dirs and names the kept backup; a live init still needs ports 80/443 open) |
| F4 | The rollback restart changed the worker count (9 before init, 8 after). Unconfirmed cause. | `scanner.sh` capacity derivation | fixed-unverified (cause found: host RAM rounded up, Docker MemTotal down; both round down now; unit-tested) |
| F5 | Init output ordering: the normal "Services started… UI: http://localhost:3000" banner prints after the failure, then `fleet error:`, then the preflight table again. | `scripts/fleet_cli.py` | fixed-unverified (line-buffered output, flushed before child processes; unit-tested) |
| F7 | Audit of PR #176: the running-work guard failed open (an unreachable API, an error on the second request, or a body without a total all counted as "nothing to interrupt", and a positive count already seen was discarded) and censused only the presentation scan list, which hides shards, internal, Model Intake and device rows. | `scripts/fleet_cli.py` | fixed (fail closed unless `--allow-running-work`; a stopped stack is recognised by the absence of the api container; census includes the hidden rows; new submissions are still not paused, which the hint says) |
| F6 | Broker worker join not yet tested: blocked on inbound 80/443 for `m2.shakerscan.com`. | — | blocked |

## Already merged before this branch (from the PR #176 audit, confirmed in source, not fixed here)

| # | Finding | Where | Status |
|---|---|---|---|
| A2 | Hint ingestion keeps declared query values (`_same_origin_path` appends `parsed.query`) and the receipt redactor is pattern-based, so ordinary or percent-encoded parameter values survive into receipts. | `api/capabilities/hint_files.py`, `api/runtime/receipts.py` | open (PR #170) |
| A3 | The scan page's carried-over summary is computed from the first 100 active target findings and can declare "Nothing unresolved from earlier scans" on a target with more. | `ui/src/app/scans/[id]/page.tsx`, `carriedOverSummary` | open (PR #173) |
| A4 | `scanFindingIdentity` is title+URL+tool lowercased, so distinct fingerprints/templates with the same display strings collapse and a still-unresolved finding drops out of the carried-over set. | `ui/src/lib/scanDetailPresentation.mjs` | open (PR #173) |
| A5 | Finding drill-down links from a scan carry no `freshness`, so the Findings page applies its 14-day default and an older scan's count does not match the linked list. | `ui/src/app/scans/[id]/page.tsx`, `ui/src/app/findings/page.tsx` | open (PR #170) |

## Model Intake (least)

| # | Finding | Where | Status |
|---|---|---|---|
| M1 | Quarantine unreadable on a non-root Linux install: acquisition (which ran on a general DAST worker, not the model-intake worker) chowns quarantine to the image's gid 10001 while api/sandbox run as the host account → dynamic sandbox CRASHED, Firecracker review stopped at `prepare_isolated_runtime` with EACCES. | `scanner/scanner_tools/model_intake_acquisition.py`, both Compose files | fixed-unverified (gid now comes from the scanner account; unit-tested; a live rerun needs the runner rootfs rebuilt, see M8/M9) |
| M2 | Runner installer recreates the API with a bare `docker compose up -d api`; on an installed runtime (release Compose only) that fails, exits 1, and skips trust-anchor registration — while `status` still says "api wired: yes". | `scripts/model_intake_runner_cli.py` | fixed-unverified (compose file + status now reports what the API says) |
| M3 | Runner installer prints "installed but not enabled … run `systemctl enable --now`" and then enables the unit itself. | `scripts/model_intake_runner_cli.py` | fixed-unverified |
| M4 | A failed conversion surfaces as *"conversion completed without an equivalent, strictly rescanned runtime subject"*; the real cause (safetensors refusing BERT's tied tensors) is only in the runner receipt. A runner job whose payload is `FAIL` is shown as job `state: completed`. | `api/api.py` review step, `api/model_intake/router.py` | fixed-unverified (review names the receipt verdict and failing phase; job refresh carries `receipt_status`) |
| M5 | First calibration returns payload `FAIL: known-answer embedding digest is absent or does not match` although the review records the digest and proceeds. | runner / review | fixed-unverified (guest message says no digest is configured; review treats a calibration FAIL as expected, only TIMEOUT/CRASHED/UNSUPPORTED/INCOMPLETE fail it) |
| M6 | `journalctl -u shakerscan-model-intake-runner` shows only startup; per-job execution is not logged and `work/<job>/jailer.log` is auto-cleaned, so runs cannot be reconstructed afterwards. | runner service | fixed-unverified (runner logs job start/finish/verdict/failing phase to the journal) |
| M8 | Building the Model Intake image from source on a 96-vCPU host fails its own self-test: modelscan dies with `OpenBLAS error: Memory allocation still failed after 10 retries` (per-thread buffers sized from the CPU count inside the build container). Found while building the branch on the c5.metal host. | `scanner/Dockerfile.model-intake` | fixed-unverified (BLAS threads pinned to 1 in the image) |
| M9 | Reviewing a model after the guest source changed is correctly refused: 'The installed microVM rootfs was built from a different ShakerScan guest source. Reinstall the Model Intake runner'. Expected fail-closed behaviour, recorded because it is why the branch's runtime path was not re-run: the guest fix (M5) changes the rootfs inputs digest, so verifying it needs `model_intake_runner_cli.py install` again on the host. | runner install | open (rebuild the rootfs to re-verify M1, M4, M5) |
| M7 | Model Intake artifact acquisition ran on a general DAST worker (`worker-16`) although docs say Model Intake jobs are consumed only by the model-intake worker. Routing/doc mismatch. | `api/model_intake/router.py`, docs | not reproduced on the branch build: acquisition ran on `shakerscan-model-intake-worker-1`; the queue policy routes both Model Intake job kinds to that worker only |

## Verified working on the clean install

Installer (installs Docker itself), 2.3.9 image pull, fleet of 9 workers uniform, API/UI/health,
CLI scan, UI scan submission with standing authorization recorded, not-examined verdict with
"scan www instead" next step, Targets/Worker Pools/Exposure pages, Firecracker tier end to end
(runner install, jailed microVM boot, calibration + runtime jobs with signed receipts, evidence frozen).
