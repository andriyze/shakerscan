# Clean-install findings — 2026-09-20

Source: 2.3.9 installed from the public installer on clean Ubuntu 24.04 EC2 hosts
(t3.xlarge control plane `3.92.68.103`, t3.large worker node `18.206.55.61`,
c5.metal KVM host `54.211.166.112`), driven through the CLI, the API and the browser UI,
plus the local dev stack. Priority: **standalone server > fleet > Model Intake.**
Status column: `open`, `fixed` (on this branch, verified), `fixed-unverified`, `deferred`.

## Standalone server (highest)

| # | Finding | Where | Status |
|---|---|---|---|
| S1 | New Scan form loses input entered before the async contract preview arrives: the typed target and the first "Allow active testing" click were dropped and submit answered "Enter at least one target URL." | `ui/src/app/scan/new/page.tsx` | open (nothing in the page resets state; needs a browser retest on the branch build) |
| S2 | Every Linux scan reports DNS posture `partial`: systemd-resolved answers DS/DNSKEY with SERVFAIL (`NoNameservers`), and the DoH fallback only covered timeouts. | `api/capabilities/dns.py` | fixed-unverified |
| S3 | `SHAKERSCAN_START=0` installs the runtime but not Docker; the next `shakerscan start` says *"Run './scanner.sh install-deps'"* — the installed command is `shakerscan`. | `scanner.sh` | fixed-unverified |
| S4 | Live scan activity strips the `[Discovery]` / `[Shard N]` child label, so on a parallel scan an operator cannot tell which child produced a line. | `ui/src/lib/scanDetailPresentation.mjs` (`scanLogEntry`) | fixed-unverified |
| S5 | A scan that lost its worker lease (infrastructure restart) is told "Review target and retry"; the target had nothing to do with it. | `ui/src/app/scans/[id]/page.tsx` (`scanFailureRecommendation`) | fixed-unverified |
| S6 | Targets page truncates the primary label to "sha…" for `https://shakerscan.com` at a normal desktop width. | `ui/src/app/targets/page.tsx` | fixed-unverified |
| S7 | Dashboard on a fresh install: "What changed is hidden in scoped mode. Historical change events do not all carry a cohort binding yet…" is internal vocabulary shown to a first-time user. | `ui/src/app/page.tsx` | fixed-unverified |
| S8 | Worker Pools shows "Connected devices: not ready — no fresh device worker" for an opt-in pool that was never started; it reads like a fault. | `ui/src/app/workers/page.tsx` | fixed-unverified |
| S9 | The resolved-families preview lags the preset radio by a second or two, so the line an operator reads to confirm what will run is briefly wrong. | `ui/src/app/scan/new/page.tsx` | fixed-unverified |
| S10 | Raw `docker compose up -d worker` resets the launcher's worker scale (20 → 1). The docs say not to use raw compose, but a product error message (M2) sends the operator there. | `scanner.sh` / docs | deferred (covered by M2 fix + doc note) |

## Fleet (medium)

| # | Finding | Where | Status |
|---|---|---|---|
| F1 | `fleet init` restarts the whole stack (backup, convert, rollback) while scans are running; a running scan died with `execution_lease_lost`, correctly not replayed. Init must refuse or warn while work is queued or running. | `scripts/fleet_cli.py` | fixed-unverified |
| F2 | Preflight `[PASS] HTTP port 80 / HTTPS port 443: available` only checks that the ports are free locally; with the cloud security group closed init still spends 120 s on ACME then rolls back. The `[WARN] Public API reachability … the managed HTTPS gateway will be provisioned` wording implies the gateway will fix reachability. Needs an external reachability probe and an explicit "open 80/443 in the cloud firewall" message. | `scripts/fleet_cli.py` | fixed-unverified (wording + gateway-log diagnosis; no external probe) |
| F3 | Rollback leaves `.shakerscan-fleet/control/` (generated control identity/CA) and `backups/` behind while `/health.fleet` reports "not initialized". | `scripts/fleet_cli.py` | fixed-unverified |
| F4 | The rollback restart changed the worker count (9 before init, 8 after). Unconfirmed cause. | `scanner.sh` capacity derivation | fixed-unverified (host RAM rounded up while Docker's MemTotal rounded down; both round down now) |
| F5 | Init output ordering: the normal "Services started… UI: http://localhost:3000" banner prints after the failure, then `fleet error:`, then the preflight table again. | `scripts/fleet_cli.py` | fixed-unverified |
| F6 | Broker worker join not yet tested: blocked on inbound 80/443 for `m2.shakerscan.com`. | — | blocked |

## Model Intake (least)

| # | Finding | Where | Status |
|---|---|---|---|
| M1 | Quarantine unreadable on a non-root Linux install: acquisition (which ran on a general DAST worker, not the model-intake worker) chowns quarantine to the image's gid 10001 while api/sandbox run as the host account → dynamic sandbox CRASHED, Firecracker review stopped at `prepare_isolated_runtime` with EACCES. | `scanner/scanner_tools/model_intake_acquisition.py`, both Compose files | fixed-unverified (runtime path validated on the KVM host with a group workaround) |
| M2 | Runner installer recreates the API with a bare `docker compose up -d api`; on an installed runtime (release Compose only) that fails, exits 1, and skips trust-anchor registration — while `status` still says "api wired: yes". | `scripts/model_intake_runner_cli.py` | fixed-unverified (compose file); `status` check open |
| M3 | Runner installer prints "installed but not enabled … run `systemctl enable --now`" and then enables the unit itself. | `scripts/model_intake_runner_cli.py` | open |
| M4 | A failed conversion surfaces as *"conversion completed without an equivalent, strictly rescanned runtime subject"*; the real cause (safetensors refusing BERT's tied tensors) is only in the runner receipt. A runner job whose payload is `FAIL` is shown as job `state: completed`. | `api/api.py` review step, `api/model_intake/router.py` | open |
| M5 | First calibration returns payload `FAIL: known-answer embedding digest is absent or does not match` although the review records the digest and proceeds. | runner / review | open |
| M6 | `journalctl -u shakerscan-model-intake-runner` shows only startup; per-job execution is not logged and `work/<job>/jailer.log` is auto-cleaned, so runs cannot be reconstructed afterwards. | runner service | open |
| M7 | Model Intake artifact acquisition ran on a general DAST worker (`worker-16`) although docs say Model Intake jobs are consumed only by the model-intake worker. Routing/doc mismatch. | `api/model_intake/router.py`, docs | open |

## Verified working on the clean install

Installer (installs Docker itself), 2.3.9 image pull, fleet of 9 workers uniform, API/UI/health,
CLI scan, UI scan submission with standing authorization recorded, not-examined verdict with
"scan www instead" next step, Targets/Worker Pools/Exposure pages, Firecracker tier end to end
(runner install, jailed microVM boot, calibration + runtime jobs with signed receipts, evidence frozen).
