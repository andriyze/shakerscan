#!/usr/bin/env python3
"""End-to-end test runner — drives the real running stack against real targets.

Usage:
    python -m tests.e2e.run_e2e --area all
    python -m tests.e2e.run_e2e --area model_intake
    python -m tests.e2e.run_e2e --area ai_gate
    python -m tests.e2e.run_e2e --area dast
    python -m tests.e2e.run_e2e --area hunt
    python -m tests.e2e.run_e2e --area platform

Exit code is non-zero if any area's gate fails (hard CI gate). See
docs/E2E_TEST_PLAN.md.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import urllib.parse

try:
    from . import harness as H
    from .fixtures import fixtures_server as FX
except ImportError:  # run as a plain script: python tests/e2e/run_e2e.py
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import harness as H
    from fixtures import fixtures_server as FX


# Full-artifact LFS digest of nex-agi/Nex-N2-mini shard 1 (the artifact that
# produced the false mismatch). The shard is multi-GB, so intake caps the
# download at 10MB and must report truncated — never compare a 10MB prefix
# against this full digest as a "mismatch".
NEX_N2_SHARD = ("https://huggingface.co/nex-agi/Nex-N2-mini/resolve/"
                "ca218dcb1fbe05f84d1807d180cb5d9bcb1c5c93/model-00001-of-00016.safetensors")
NEX_N2_FULL_SHA = "d6b15ebf2a6b81f62c9a913bc340486a7a1a97cbbf97a50abf9be53ddcd4f5dc"


def run_model_intake() -> H.Scorecard:
    sc = H.Scorecard("model_intake")
    print("\n== Model Intake e2e ==", flush=True)

    fx_good = f"{FIXTURES_BASE}/models/good.safetensors"
    fx_pickle = f"{FIXTURES_BASE}/models/dangerous.pkl"
    fx_large = f"{FIXTURES_BASE}/models/large.safetensors"

    def _mi_scan(opts: dict, label: str, timeout: int = 180) -> dict:
        opts = {"intake_mode": "preflight", **opts}
        artifact_url = str(opts.get("artifact_url") or "")
        if artifact_url.startswith(FIXTURES_BASE) and not opts.get("approval_receipt_id"):
            host = artifact_url.split("/", 3)[2].split(":", 1)[0]
            _, preview = H.post("/arsenal/scope/preview", {
                "url": artifact_url,
                "allowed_hosts": [host],
                "environment": "lab",
            })
            scope = preview.get("scope_receipt") or {}
            _, approval = H.post("/arsenal/approvals", {
                "scope_receipt_id": scope.get("receipt_id"),
                "risk_tier": "active",
                "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
                "action_name": "model_intake.scan",
                "approved_by": "model-intake-e2e",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            })
            opts = {
                **opts,
                "allow_insecure_http": True,
                "allow_private_networks": True,
                "allowed_acquisition_hosts": [host],
                "allowed_acquisition_ports": [FIXTURES_PORT],
                "approval_receipt_id": (approval.get("approval_receipt") or {}).get("id"),
            }
        _, r = H.post("/model-intake/scan", opts)
        sid = r.get("scan_id")
        if not sid:
            raise RuntimeError(f"submit rejected: {r}")
        H.wait_for_scan(sid, timeout=timeout, label=label)
        result = H.scan_result(sid)
        result["_scan_id"] = sid
        result["_e2e_activity_logs"] = H.get(f"/scans/{sid}/logs?limit=200").get("lines") or []
        return result

    # MI-1 (deterministic hard gate): a 206 partial download capped below the full
    # artifact must report known_unverified_truncated, NOT a false sha256_mismatch
    # against the full-artifact digest. Local fixture — no network flakiness.
    try:
        res = _mi_scan({"artifact_url": fx_large, "expected_sha256": FX.LARGE_SHA,
                        "max_download_bytes": 4096}, "MI-1")
        s = (res.get("model_intake") or {}).get("summary") or {}
        fids = {str(f.get("id")) for f in (res.get("findings") or [])}
        sc.check("MI-1 206 partial download flagged truncated (not mismatch)",
                 s.get("checksum_status") == "known_unverified_truncated",
                 f"checksum_status={s.get('checksum_status')}")
        sc.check("MI-1 sha256 scope is inspected_bytes",
                 s.get("sha256_scope") == "inspected_bytes", f"sha256_scope={s.get('sha256_scope')}")
        sc.check("MI-1 no false sha256_mismatch finding",
                 "model_intake:sha256_mismatch" not in fids, f"findings={sorted(fids)[:6]}")
        activity_logs = [str(line) for line in (res.get("_e2e_activity_logs") or [])]
        sc.check("MI-1 live and durable activity logs are visible",
                 any("phase=artifact_acquisition" in line for line in activity_logs)
                 and any("phase=decision" in line for line in activity_logs),
                 f"lines={activity_logs[:8]}")
    except Exception as e:
        sc.error("MI-1 local 206 truncation", e)

    # MI-1-HF (opt-in / nightly): the real multi-GB HuggingFace shard — useful
    # coverage for the original 206 bug, but an external dependency, so NOT a hard
    # PR gate. Runs only when SHAKERSCAN_E2E_HF=1.
    if os.environ.get("SHAKERSCAN_E2E_HF") == "1":
        try:
            res = _mi_scan({"artifact_url": NEX_N2_SHARD, "expected_sha256": NEX_N2_FULL_SHA,
                            "metadata_json": {"license": "apache-2.0"}}, "MI-1-HF", timeout=300)
            intake = res.get("model_intake") or {}
            s = intake.get("summary") or {}
            fids = {str(f.get("id")) for f in (res.get("findings") or [])}
            header = (((intake.get("supply_chain") or {}).get("format_inspection") or {})
                      .get("safetensors_header") or {})
            sc.check("MI-1-HF real HF shard not false-mismatched",
                     s.get("checksum_status") == "known_unverified_truncated",
                     f"checksum_status={s.get('checksum_status')}")
            sc.check("MI-1-HF truncated shard uses full size for structural validation",
                     header.get("valid") is True
                     and header.get("validation_complete") is True
                     and header.get("payload_bounds_checked") is True
                     and "model_intake:safetensors_header_invalid" not in fids,
                     f"valid={header.get('valid')} payload_size={header.get('payload_size')} "
                     f"findings={sorted(fids)[:6]}")
        except Exception as e:
            sc.error("MI-1-HF real HF intake", e)
    else:
        sc.skip("MI-1-HF real HuggingFace shard",
                "external dependency; set SHAKERSCAN_E2E_HF=1 (nightly/manual)")

    # MI-2: correct digest on a fully-downloadable artifact -> verified.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA}, "MI-2")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-2 correct digest verifies",
                 s.get("checksum_status") == "verified" and s.get("sha256_scope") == "full_artifact",
                 f"checksum_status={s.get('checksum_status')} scope={s.get('sha256_scope')}")
    except Exception as e:
        sc.error("MI-2 verified checksum", e)

    # MI-3: a tampered artifact (wrong expected hash, full download) -> critical
    # sha256_mismatch (the real tamper path, which the 206 false-mismatch masked).
    try:
        res = _mi_scan({"artifact_url": fx_good, "expected_sha256": FX.WRONG_SHA}, "MI-3")
        fids = {str(f.get("id")) for f in (res.get("findings") or [])}
        sc.check("MI-3 tampered artifact -> critical sha256_mismatch",
                 "model_intake:sha256_mismatch" in fids, f"findings={sorted(fids)[:6]}")
    except Exception as e:
        sc.error("MI-3 tamper detection", e)

    # MI-4/T2: a dangerous pickle goes through complete acquisition plus the
    # generated scanner chain. The report must distinguish a proven os.system
    # callable from ordinary framework-pickle capability, reject it, and ignore
    # an attacker-supplied inline "approved" exception.
    try:
        res = _mi_scan({
            "artifact_url": fx_pickle,
            "require_hash": False,
            "complete_artifact_download": True,
            "run_generated_scanners": True,
            "policy_exceptions": [{
                "finding_id": "model_intake:unsafe_serialization",
                "status": "approved",
                "approved_by": "attacker-controlled-input",
                "expires_at": "2999-01-01T00:00:00Z",
            }],
        }, "MI-4")
        ids = [(str(f.get("id")) + " " + str(f.get("title"))).lower() for f in (res.get("findings") or [])]
        flagged = any(any(k in x for k in ("pickle", "serial", "unsafe", "risky", "deserial")) for x in ids)
        sc.check("MI-4 dangerous pickle flagged", flagged,
                 f"findings={[str(f.get('id')) for f in (res.get('findings') or [])][:6]}")
        intake = res.get("model_intake") or {}
        pickle_result = next((item for item in (intake.get("generated_evidence") or {}).get("results", [])
                              if (item.get("scanner") or {}).get("name") == "python-pickletools"), {})
        sc.check("MI-4 semantic scanner proves dangerous callable",
                 (pickle_result.get("summary") or {}).get("semantic_classification") == "dangerous_callable_detected"
                 and pickle_result.get("execution", {}).get("status") == "FAIL",
                 f"summary={pickle_result.get('summary')} status={pickle_result.get('execution', {}).get('status')}")
        corporate = intake.get("corporate_use") or {}
        sc.check("MI-4 corporate verdict rejects proven malicious artifact",
                 corporate.get("verdict") == "REJECT" and corporate.get("malicious_primitive_proven") is True,
                 f"verdict={corporate.get('verdict')} proven={corporate.get('malicious_primitive_proven')}")
        deployment = H.get(f"/scans/{res.get('_scan_id')}/deployment-decision")
        sc.check("MI-4 caller-supplied exception cannot weaken deployment gate",
                 deployment.get("decision") == "block" and not deployment.get("applied_exceptions"),
                 f"decision={deployment.get('decision')} exceptions={deployment.get('applied_exceptions')}")
    except Exception as e:
        sc.error("MI-4 unsafe serialization", e)

    # MI-5: a VALID self-signed signature with no configured trust anchor must read
    # as untrusted_root, never "verified" (the trust-root bug). Signature material
    # rides in metadata_json (the verifier's metadata fallback); trust anchors are
    # durable operator-owned state and cannot be supplied by this request.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA,
                       "metadata_json": {"signature_public_key": FX.SIGNING_PUB_PEM,
                                         "signature_value": FX.SIGNATURE_B64}}, "MI-5")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-5 valid self-signed -> untrusted_root (not verified)",
                 s.get("signature_verification_status") == "untrusted_root"
                 and s.get("signature_verified") is False,
                 f"status={s.get('signature_verification_status')} valid={s.get('signature_valid')}")
    except Exception as e:
        sc.error("MI-5 trust-root (untrusted)", e)
    # MI-6: a valid signature whose key is supplied in the SAME untrusted scan
    # request must remain untrusted. Trust anchors are durable, operator-owned
    # control-plane state; a scan submitter cannot mint one inline.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA,
                       "signature_public_key": FX.SIGNING_PUB_PEM,
                       "signature_value": FX.SIGNATURE_B64,
                       "signature_trusted_keys": [FX.SIGNING_PUB_PEM]}, "MI-6")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-6 caller cannot supply its own trust anchor",
                 s.get("signature_verification_status") == "untrusted_root"
                 and s.get("signature_verified") is False
                 and s.get("signature_trusted_root") is not True,
                 f"status={s.get('signature_verification_status')} trusted_root={s.get('signature_trusted_root')}")
    except Exception as e:
        sc.error("MI-6 caller trust-anchor rejection", e)

    # MI-6A/B/C: exercise the positive durable trust path through the real API,
    # DB, queue, worker, crypto verifier, and result. Expired and wrong anchors
    # must not verify; an active correct anchor must; deactivation must take
    # effect on the next scan. Public scan callers never select these anchors.
    created_anchor_ids: list[str] = []
    try:
        operator_headers = H.model_intake_operator_headers()

        def _create_anchor(label: str, public_key: str, *, valid_from: str | None = None,
                           valid_until: str | None = None) -> str:
            status, body = H.post("/model-intake/trust-anchors", {
                "name": f"e2e-{label}-{_RUN_NONCE}",
                "description": "Disposable real-stack trust verification fixture",
                "public_key_pem": public_key,
                "policy_profile": "production",
                "purpose": "publisher_signature",
                "environment": "production",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "source": "model-intake-e2e",
                "owner": "model-intake-e2e",
            }, headers=operator_headers)
            anchor_id = str(body.get("id") or "")
            if status != 200 or not anchor_id:
                raise RuntimeError(f"could not create {label} trust anchor: status={status} body={body}")
            created_anchor_ids.append(anchor_id)
            return anchor_id

        now = datetime.now(timezone.utc)
        _create_anchor(
            "expired-correct",
            FX.SIGNING_PUB_PEM,
            valid_from=(now - timedelta(days=2)).isoformat(),
            valid_until=(now - timedelta(days=1)).isoformat(),
        )
        _create_anchor("active-wrong", FX.WRONG_SIGNING_PUB_PEM)
        negative = (_mi_scan({
            "artifact_url": fx_good,
            "expected_sha256": FX.GOOD_SHA,
            "signature_public_key": FX.SIGNING_PUB_PEM,
            "signature_value": FX.SIGNATURE_B64,
        }, "MI-6A").get("model_intake") or {}).get("summary") or {}
        sc.check(
            "MI-6A expired and wrong durable anchors do not verify",
            negative.get("signature_verification_status") == "untrusted_key"
            and negative.get("signature_verified") is False
            and negative.get("signature_trusted_root") is False,
            f"status={negative.get('signature_verification_status')} trusted={negative.get('signature_trusted_root')}",
        )

        correct_anchor_id = _create_anchor("active-correct", FX.SIGNING_PUB_PEM)
        positive = (_mi_scan({
            "artifact_url": fx_good,
            "expected_sha256": FX.GOOD_SHA,
            "signature_public_key": FX.SIGNING_PUB_PEM,
            "signature_value": FX.SIGNATURE_B64,
        }, "MI-6B").get("model_intake") or {}).get("summary") or {}
        sc.check(
            "MI-6B operator-created durable anchor verifies exact signature",
            positive.get("signature_verification_status") == "verified"
            and positive.get("signature_verified") is True
            and positive.get("signature_trusted_root") is True,
            f"status={positive.get('signature_verification_status')} trusted={positive.get('signature_trusted_root')}",
        )

        status, deactivated = H.delete(
            f"/model-intake/trust-anchors/{correct_anchor_id}",
            headers=operator_headers,
        )
        if status != 200 or deactivated.get("deactivated") is not True:
            raise RuntimeError(f"could not deactivate positive trust anchor: status={status} body={deactivated}")
        after_revoke = (_mi_scan({
            "artifact_url": fx_good,
            "expected_sha256": FX.GOOD_SHA,
            "signature_public_key": FX.SIGNING_PUB_PEM,
            "signature_value": FX.SIGNATURE_B64,
        }, "MI-6C").get("model_intake") or {}).get("summary") or {}
        sc.check(
            "MI-6C deactivated durable anchor stops verification",
            after_revoke.get("signature_verification_status") == "untrusted_key"
            and after_revoke.get("signature_verified") is False
            and after_revoke.get("signature_trusted_root") is False,
            f"status={after_revoke.get('signature_verification_status')} trusted={after_revoke.get('signature_trusted_root')}",
        )
    except Exception as e:
        sc.error("MI-6 durable trust-anchor lifecycle", e)
    finally:
        try:
            cleanup_headers = H.model_intake_operator_headers()
            for anchor_id in reversed(created_anchor_ids):
                H.delete(f"/model-intake/trust-anchors/{anchor_id}", headers=cleanup_headers)
        except Exception:
            pass

    # MI-7: the compatibility endpoint must not expose a second authority path.
    # Admission requests are rejected before acquisition, including requests
    # carrying forged repository completeness and custom-code declarations.
    try:
        status, body = H.post("/model-intake/scan", {
            "artifact_url": fx_good,
            "intake_mode": "admission",
            "expected_sha256": FX.GOOD_SHA,
            "metadata_json": {
                "repository_manifest": {
                    "complete": True,
                    "files": [{"path": "good.safetensors", "size": len(FX.GOOD)}],
                    "custom_code_required": False,
                },
                "python_files": [],
                "custom_code_required": False,
            },
        })
        detail = body.get("detail") or {}
        sc.check("MI-7 legacy admission endpoint is removed",
                 status == 409
                 and detail.get("code") == "legacy_model_intake_admission_mode_removed"
                 and detail.get("authoritative_workflow") == "/model-intake/submissions"
                 and not body.get("scan_id"),
                 f"status={status} body={body}")
    except Exception as e:
        sc.error("MI-7 legacy admission endpoint rejection", e)

    return sc


# Targets must be reachable from the WORKER container, not the host: inside the
# compose network the honey apps are at host.docker.internal, not localhost (a
# localhost:3001 target resolves to the worker itself and fails pre-scan
# validation). Override SHAKERSCAN_E2E_HONEY_HOST on Linux CI (e.g. the compose
# service name / bridge IP).
HONEY_HOST = os.environ.get("SHAKERSCAN_E2E_HONEY_HOST", "host.docker.internal")
# The local fixtures server (started in main) — worker-reachable, deterministic,
# and deliberately leaky, so the AI detection/redaction and Model-Intake artifact
# assertions run without external honey apps. Override SHAKERSCAN_E2E_AI_ENDPOINT
# to point at a real honey AI app instead.
FIXTURES_PORT = int(os.environ.get("SHAKERSCAN_E2E_FIXTURES_PORT", "18099"))
FIXTURES_BASE = f"http://{HONEY_HOST}:{FIXTURES_PORT}"
AI_ENDPOINT = os.environ.get("SHAKERSCAN_E2E_AI_ENDPOINT", f"{FIXTURES_BASE}/ai/chat")


import time as _time

# Unique per run so the endpoint_url uniqueness constraint never collides with a
# prior run's (possibly soft-deleted) target. The extra query param is ignored by
# the target endpoint.
_RUN_NONCE = f"{os.getpid()}-{int(_time.time())}"


def _ai_endpoint(tag: str) -> str:
    sep = "&" if "?" in AI_ENDPOINT else "?"
    return f"{AI_ENDPOINT}{sep}e2e={tag}-{_RUN_NONCE}"


def run_platform() -> H.Scorecard:
    """Exercise adjacent product contracts against the assembled live stack.

    This lane is intentionally non-scanning. It proves that V2 Scan changes did
    not break shared persistence, routers, or public read models, while its only
    writes are disposable records that are disabled/deleted before return.
    """
    sc = H.Scorecard("platform")
    print("\n== Platform regression e2e ==", flush=True)

    health: dict = {}
    try:
        health = H.get("/health")
        reconciliation = health.get("scan_action_budget_reconciliation") or {}
        sc.check(
            "P-1 health, persistence, and queue are ready",
            health.get("status") == "healthy"
            and health.get("database") == "ok"
            and health.get("redis") == "ok"
            and reconciliation.get("status") == "ok",
            (
                f"status={health.get('status')} db={health.get('database')} "
                f"redis={health.get('redis')} reconciliation={reconciliation.get('status')}"
            ),
        )
        contract = H.get("/scan/contracts")
        sc.check(
            "P-1 canonical Scan contract remains mounted",
            contract.get("schema_version") == "scan-public-contract/v1"
            and contract.get("generation") == "v2"
            and contract.get("engine") == "scan",
            f"schema={contract.get('schema_version')} generation={contract.get('generation')}",
        )
        metrics = H.get("/metrics/v2")
        sc.check(
            "P-1 operational metrics remain content-free and queryable",
            metrics.get("schema_version") == "scan-operational-metrics/v1"
            and isinstance(metrics.get("counters"), dict)
            and isinstance(metrics.get("alerts"), list),
            f"schema={metrics.get('schema_version')}",
        )
    except Exception as exc:
        sc.error("P-1 platform health and contracts", exc)

    try:
        catalog = H.get("/asm/check-families")
        family_names = {
            str(item.get("name"))
            for item in (catalog.get("families") or [])
            if isinstance(item, dict)
        }
        sc.check(
            "P-2 ASM registry remains available",
            {"recon", "sqli", "xss", "bola"} <= family_names,
            f"families={sorted(family_names)}",
        )
    except Exception as exc:
        sc.error("P-2 ASM registry", exc)

    try:
        devices = H.get("/devices?limit=1")
        readiness = H.get("/devices/readiness")
        sc.check(
            "P-3 Connected Devices inventory and readiness remain explicit",
            isinstance(devices.get("devices"), list)
            and readiness.get("status") in {"ready", "not_ready", "disabled"}
            and isinstance(readiness.get("required_worker_tools"), list),
            f"status={readiness.get('status')} total={devices.get('total')}",
        )
    except Exception as exc:
        sc.error("P-3 Connected Devices surfaces", exc)

    try:
        workers = H.get("/workers")
        fleet = health.get("fleet") or H.get("/health").get("fleet") or {}
        sc.check(
            "P-4 worker and Fleet state remain explicit",
            isinstance(workers.get("workers"), list)
            and isinstance(workers.get("stale_count"), int)
            and fleet.get("status") in {
                "enabled", "ready", "configured", "disabled", "unsupported", "not_ready",
            },
            f"workers={workers.get('count')} fleet_status={fleet.get('status')}",
        )
    except Exception as exc:
        sc.error("P-4 Fleet and workers surfaces", exc)

    try:
        read_contracts = (
            ("schedules", "/schedules?limit=1", "schedules", list),
            ("findings", "/findings?limit=1", "findings", list),
            ("evidence", "/evidence/instances?limit=1", "evidence_instances", list),
            ("timeline", "/timeline?limit=1", "events", list),
            ("campaigns", "/arsenal/campaigns?limit=1", "campaigns", list),
        )
        failures = []
        for label, path, field, field_type in read_contracts:
            body = H.get(path)
            if not isinstance(body.get(field), field_type):
                failures.append(f"{label}:{field}={type(body.get(field)).__name__}")
        arsenal = H.get("/arsenal/contracts")
        if arsenal.get("execution_enabled") is not False:
            failures.append("arsenal:execution_enabled")
        sc.check(
            "P-5 schedules, findings, evidence, timeline, and mission ledger read models work",
            not failures,
            f"failures={failures}",
        )
    except Exception as exc:
        sc.error("P-5 adjacent read models", exc)

    target_id = ""
    schedule_id = ""
    finding_id = ""
    credential_id = ""
    target_url = f"https://platform-{_RUN_NONCE}.invalid"
    try:
        target_status, target = H.post("/targets", {
            "url": target_url,
            "name": f"Disposable platform E2E {_RUN_NONCE}",
        })
        target_id = str(target.get("id") or "")
        if target_status not in {200, 201} or not target_id:
            raise RuntimeError(f"target creation failed: status={target_status} body={target}")

        policy_status, policy = H.put(
            f"/targets/{target_id}/asm/policy",
            {"enabled": False, "config": {}},
        )
        coverage = H.get(f"/targets/{target_id}/asm/coverage")
        gaps = H.get(f"/targets/{target_id}/asm/gaps")
        sc.check(
            "P-6 disposable target and ASM read models round-trip",
            policy_status == 200
            and policy.get("enabled") is False
            and isinstance(coverage, dict)
            and isinstance(gaps.get("recommended_campaigns"), list),
            (
                f"policy_status={policy_status} enabled={policy.get('enabled')} "
                f"coverage_total={coverage.get('total')}"
            ),
        )

        enable_status, enabled_policy = H.put(
            f"/targets/{target_id}/asm/policy",
            {"enabled": True, "config": {"recon_interval_hours": 24}},
        )
        disable_status, disabled_policy = H.put(
            f"/targets/{target_id}/asm/policy",
            {"enabled": False, "config": {}},
        )
        sc.check(
            "P-12 ASM policy enable and disable round-trip",
            enable_status == 200
            and enabled_policy.get("enabled") is True
            and disable_status == 200
            and disabled_policy.get("enabled") is False,
            (
                f"enable_status={enable_status} enabled={enabled_policy.get('enabled')} "
                f"disable_status={disable_status} disabled={disabled_policy.get('enabled')}"
            ),
        )

        future = datetime.now(timezone.utc) + timedelta(hours=6)
        schedule_status, schedule = H.post("/schedules", {
            "target_id": target_id,
            "name": f"Disposable platform E2E {_RUN_NONCE}",
            "frequency": "daily",
            "time_of_day": future.strftime("%H:%M"),
            "timezone": "UTC",
            "schedule_kind": "normal_scan",
            "scan_options": {"budget_profile": "fast"},
            "jitter_minutes": 0,
        })
        schedule_id = str(schedule.get("id") or "")
        if schedule_status not in {200, 201} or not schedule_id:
            raise RuntimeError(f"schedule creation failed: status={schedule_status} body={schedule}")
        update_status, updated = H.patch(
            f"/schedules/{schedule_id}", {"is_active": False},
        )
        stored_schedule = H.get(f"/schedules/{schedule_id}")
        sc.check(
            "P-7 schedule create, disable, and read lifecycle works",
            update_status == 200
            and updated.get("status") == "updated"
            and stored_schedule.get("is_active") is False,
            f"update_status={update_status} active={stored_schedule.get('is_active')}",
        )

        finding_status, finding = H.post("/findings/manual", {
            "target": target_url,
            "title": f"Disposable platform regression record {_RUN_NONCE}",
            "severity": "info",
            "description": "Lifecycle-only E2E record; not a vulnerability claim.",
            "category": "E2E",
            "evidence": "No security finding; public persistence contract check only.",
            "notes": "Disposable and deleted by the platform E2E lane.",
        })
        finding_id = str(finding.get("id") or "")
        if finding_status not in {200, 201} or not finding_id:
            raise RuntimeError(f"finding creation failed: status={finding_status} body={finding}")
        evidence = H.get(f"/findings/{finding_id}/evidence")
        listed = H.get(f"/findings?target_id={target_id}&source_type=manual&limit=10")
        listed_ids = {str(item.get("id")) for item in (listed.get("findings") or [])}
        sc.check(
            "P-8 manual finding and evidence projection round-trip",
            finding_id in listed_ids
            and evidence.get("finding_id") == finding_id
            and isinstance(evidence.get("evidence_objects"), list),
            f"listed={finding_id in listed_ids} evidence_count={len(evidence.get('evidence_objects') or [])}",
        )

        credential_status, credential = H.post("/credential-profiles", {
            "target_kind": "web",
            "target_id": target_id,
            "name": f"Disposable platform credential {_RUN_NONCE}",
            "auth_kind": "authorization_header",
            "principal_slot": "primary",
            "principal_label": "e2e-primary",
            "secret": f"Bearer disposable-{_RUN_NONCE}",
            "allowed_capabilities": ["http.request"],
            "created_by": "platform-e2e",
        })
        credential_profile = credential.get("profile") or {}
        credential_id = str(credential_profile.get("id") or "")
        if credential_status != 201 or not credential_id:
            raise RuntimeError(
                f"credential creation failed: status={credential_status} body={credential}"
            )
        public_before = json.dumps(credential_profile, sort_keys=True)
        rotate_status, rotated = H.post(
            f"/credential-profiles/{credential_id}/rotate",
            {
                "expected_record_version": credential_profile.get("record_version"),
                "secret": f"Bearer rotated-{_RUN_NONCE}",
                "created_by": "platform-e2e",
            },
        )
        rotated_profile = rotated.get("profile") or {}
        public_after = json.dumps(rotated_profile, sort_keys=True)
        sc.check(
            "P-9 encrypted credential create and rotation stay metadata-only",
            rotate_status == 200
            and rotated_profile.get("record_version") == 2
            and rotated_profile.get("storage_encrypted") is True
            and rotated_profile.get("execution_compatible") is True
            and "disposable-" not in public_before
            and "rotated-" not in public_after
            and rotated_profile.get("secret_values_visible") is False,
            (
                f"create_status={credential_status} rotate_status={rotate_status} "
                f"version={rotated_profile.get('record_version')}"
            ),
        )

        collection_status, collection = H.post("/request-collections", {
            "target_id": target_id,
            "name": f"Disposable platform collection {_RUN_NONCE}",
            "format": "postman_collection",
            "document": {
                "info": {
                    "name": "Platform E2E",
                    "schema": (
                        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                    ),
                },
                "item": [{
                    "name": "Safe health request",
                    "request": {"method": "GET", "url": f"{target_url}/health"},
                }],
            },
        })
        collection_id = str(collection.get("id") or "")
        binding_id = str((collection.get("binding") or {}).get("id") or "")
        if collection_status != 200 or not collection_id or not binding_id:
            raise RuntimeError(
                f"collection creation failed: status={collection_status} body={collection}"
            )
        select_status, selected = H.post(
            f"/request-collections/{collection_id}/select",
            {"methods": ["GET"], "safe_methods_only": True, "limit": 10},
        )
        selected_blob = json.dumps(selected, sort_keys=True)
        sc.check(
            "P-10 request collection import, binding, and redacted selection work",
            select_status == 200
            and selected.get("count") == 1
            and selected.get("secret_values_visible") is False
            and "Bearer disposable-" not in selected_blob,
            (
                f"collection_status={collection_status} select_status={select_status} "
                f"count={selected.get('count')}"
            ),
        )

        manifest = H.get(
            f"/evidence/export-manifest?finding_id={finding_id}&limit=10"
        )
        bundle = H.get(
            f"/evidence/export-bundle?finding_id={finding_id}&limit=10&format=json"
        )
        sc.check(
            "P-11 evidence manifest and bundle exports remain content-free",
            manifest.get("content_included") is False
            and bundle.get("content_included") is False
            and isinstance(manifest.get("manifest_hash"), str)
            and isinstance(bundle.get("bundle_hash"), str),
            (
                f"manifest_schema={manifest.get('schema_version')} "
                f"bundle_schema={bundle.get('schema_version')}"
            ),
        )
    except Exception as exc:
        sc.error("P-6 through P-12 disposable persistence lifecycle", exc)
    finally:
        if credential_id:
            H.delete(f"/credential-profiles/{credential_id}")
        if finding_id:
            H.delete(f"/findings/{finding_id}")
        if schedule_id:
            H.delete(f"/schedules/{schedule_id}")
        if target_id:
            H.delete(f"/targets/{target_id}")

    return sc


def _create_ai_target(name: str, production: bool) -> str | None:
    _, resp = H.post("/ai/targets", {
        "name": f"{name}-{_RUN_NONCE}", "target_type": "api_chat", "endpoint_url": _ai_endpoint(name),
        "method": "POST", "headers_template": {"Content-Type": "application/json"},
        "request_template": {"action": "query", "query": "{{prompt}}"},
        "response_path": "$.answer", "production_mode": production,
        "rate_limit_rps": 8, "request_budget": 8,
    })
    return (resp.get("target") or {}).get("id")


def run_ai_gate() -> H.Scorecard:
    sc = H.Scorecard("ai_gate")
    print("\n== AI Gate e2e ==", flush=True)

    # AI-4: a production scan is refused without explicit confirmation.
    prod_id = None
    try:
        prod_id = _create_ai_target("e2e-ai-prod-gate", production=True)
        sc.check("AI-4 prod target created", bool(prod_id))
        if prod_id:
            code_no, _ = H.post(f"/ai/targets/{prod_id}/scan",
                                {"probe_pack": "shaker-ai-smoke", "scan_profile": "smoke", "environment": "production"})
            sc.check("AI-4 prod scan refused without confirm", code_no == 409, f"http={code_no}")
    except Exception as e:
        sc.error("AI-4 confirm_production gate", e)
    finally:
        if prod_id:
            H._req("DELETE", f"/ai/targets/{prod_id}")

    # AI-1/AI-2: a real smoke scan completes and its transcript is redaction-gated.
    tid = None
    try:
        tid = _create_ai_target("e2e-ai-smoke", production=False)
        sc.check("AI-1 target created", bool(tid))
        if tid:
            code, resp = H.post(f"/ai/targets/{tid}/scan",
                                {"probe_pack": "shaker-ai-smoke", "scan_profile": "smoke", "environment": "staging"})
            scan_id = resp.get("scan_id") or resp.get("id")
            sc.check("AI-1 smoke scan accepted", bool(scan_id) and code in (200, 202), f"http={code}")
            if scan_id:
                scan = H.wait_for_scan(scan_id, timeout=420, label="AI-1")
                status = str(scan.get("status"))
                using_fixture = AI_ENDPOINT.startswith(FIXTURES_BASE)
                if status != "completed" and not using_fixture:
                    # Only an OVERRIDDEN external endpoint may legitimately skip.
                    sc.skip("AI-1/AI-2 live scan + transcript redaction",
                            f"AI scan status={status}; external endpoint {AI_ENDPOINT} not completed")
                elif status != "completed":
                    # The local fixture is deterministic and always responsive — a
                    # non-completed scan is a REAL failure, never a passing skip.
                    sc.check("AI-1 smoke scan completed (deterministic fixture)", False,
                             f"status={status} endpoint={AI_ENDPOINT}")
                else:
                    sc.check("AI-1 smoke scan completed", True, f"status={status}")
                    tr = H.get(f"/ai/scans/{scan_id}/transcript")
                    blob = json.dumps(tr)
                    # AI-2: the leaky fixture leaks password=/api_key=sk_live_/client_secret:
                    # in EVERY response. The transcript must have CAPTURED that response
                    # (non-vacuous) and yet contain NONE of the planted secrets — the
                    # real judge-redactor-leak regression.
                    captured = "Internal config dump" in blob  # proves the leaky response was stored
                    survived = [t for t in FX.PLANTED_TOKENS if t in blob]
                    sc.check("AI-2 transcript redaction applied", tr.get("redaction_applied") is True,
                             f"redaction_applied={tr.get('redaction_applied')}")
                    sc.check("AI-2 leaky response was captured (test not vacuous)", captured, f"captured={captured}")
                    sc.check("AI-2 no planted secret survives transcript", not survived,
                             f"survived={survived} redaction_markers={blob.count('***')}")
    except Exception as e:
        sc.error("AI-1/AI-2 smoke scan + redaction", e)
    finally:
        if tid:
            H._req("DELETE", f"/ai/targets/{tid}")

    # AI-3: production principal-probe filter. A generated cross-principal
    # admin-impersonation probe (family=tool_abuse, non_production_only) must be
    # BLOCKED in production and never executed — the bypass bug. Non-vacuous: the
    # SAME probe is generated in a staging control.
    rag_id = None
    try:
        _, resp = H.post("/ai/targets", {
            "name": f"e2e-ai-principal-{_RUN_NONCE}", "target_type": "rag",
            "endpoint_url": _ai_endpoint("principal"),
            "method": "POST", "headers_template": {"Content-Type": "application/json"},
            "request_template": {"message": "{{prompt}}"}, "response_path": "$.answer",
            "production_mode": False, "rate_limit_rps": 8, "request_budget": 12,
        })
        rag_id = (resp.get("target") or {}).get("id")
        sc.check("AI-3 rag target created", bool(rag_id))
        if rag_id:
            for role in ("attacker", "admin", "victim"):
                H.post(f"/ai/targets/{rag_id}/principals",
                       {"label": f"{role}-a", "role": role, "tenant_id": f"tenant-{role}"})

            def _principal_manifest(environment, confirm):
                body = {"probe_pack": "shaker-agent-abuse", "scan_profile": "standard", "environment": environment}
                if confirm:
                    body["confirm_production"] = True
                _, r = H.post(f"/ai/targets/{rag_id}/scan", body)
                sid = r.get("scan_id") or r.get("id")
                if not sid:
                    raise RuntimeError(f"principal scan rejected: {r}")
                H.wait_for_scan(sid, timeout=420, label=f"AI-3:{environment}")
                ep = (((H.scan_result(sid).get("ai_gate") or {}).get("execution_plan")) or {})
                man = ep.get("probe_manifest") or {}
                return {
                    "blocked": man.get("blocked_for_production_probe_ids") or [],
                    "pair": man.get("principal_pair_probe_ids") or [],
                    "executed": ep.get("executed") or [],
                }

            ADMIN = "agent-admin-action"
            prod = _principal_manifest("production", True)
            sc.check("AI-3 admin-impersonation probe blocked in production",
                     any(ADMIN in p for p in prod["blocked"]), f"blocked={prod['blocked'][:4]}")
            sc.check("AI-3 admin-impersonation probe NOT executed in production",
                     not any(ADMIN in p for p in prod["executed"]), f"executed={prod['executed'][:4]}")
            stg = _principal_manifest("staging", False)
            sc.check("AI-3 control: same probe IS generated in staging (non-vacuous)",
                     any(ADMIN in p for p in stg["pair"]), f"staging_pair={stg['pair'][:4]}")
    except Exception as e:
        sc.error("AI-3 production principal-probe filter", e)
    finally:
        if rag_id:
            H._req("DELETE", f"/ai/targets/{rag_id}")

    return sc


JUICE_SHOP = os.environ.get("SHAKERSCAN_E2E_DAST_TARGET", f"http://{HONEY_HOST}:3001")
HUNT_WEB_TARGET = os.environ.get(
    "SHAKERSCAN_E2E_HUNT_TARGET",
    os.environ.get("SHAKERSCAN_E2E_DAST_TARGET", FIXTURES_BASE),
)


def _dast_fixture_authority(
    fixture_target: str = FIXTURES_BASE,
    *,
    allowed_host: str = HONEY_HOST,
) -> tuple[str, str, dict[str, dict[str, str]]]:
    """Create target-bound approval plus exact saved-request selections."""
    _, target = H.post("/targets", {
        "url": fixture_target,
        "name": f"E2E request mutation fixture {_RUN_NONCE}",
    })
    target_id = str(target.get("id") or "")
    if not target_id:
        raise RuntimeError(f"DAST fixture target rejected: {target}")
    _, scope_response = H.post("/arsenal/scope/preview", {
        "url": fixture_target,
        "target_id": target_id,
        "allowed_hosts": [allowed_host],
        "environment": "lab",
    })
    scope = scope_response.get("scope_receipt") or {}
    _, approval_response = H.post("/arsenal/approvals", {
        "scope_receipt_id": scope.get("receipt_id"),
        "risk_tier": "active",
        "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
        "action_name": "scan.submit",
        "approved_by": "dast-e2e",
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(minutes=30)
        ).isoformat(),
    })
    approval_id = str(
        (approval_response.get("approval_receipt") or {}).get("id") or ""
    )
    if not approval_id:
        raise RuntimeError(f"DAST fixture approval rejected: {approval_response}")

    postman = {
        "info": {
            "name": "ShakerScan V2 request verifier E2E",
            "schema": (
                "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            ),
        },
        "item": [
            {
                "name": "SQLi JSON body",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"id":"1"}'},
                    "url": f"{fixture_target}/dast/sqli",
                },
            },
            {
                "name": "XSS JSON body",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"message":"control"}'},
                    "url": f"{fixture_target}/dast/xss",
                },
            },
            {
                "name": "Exact JSON body",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"name":"exact-json"}'},
                    "url": f"{fixture_target}/dast/json",
                },
            },
            {
                "name": "Owner reads owner order",
                "request": {
                    "method": "GET",
                    "header": [{"key": "Authorization", "value": "Bearer parity-owner"}],
                    "url": f"{fixture_target}/authz/orders/owner-order",
                },
            },
            {
                "name": "Attacker reads owner order",
                "request": {
                    "method": "GET",
                    "header": [{"key": "Authorization", "value": "Bearer parity-attacker"}],
                    "url": f"{fixture_target}/authz/orders/owner-order",
                },
            },
        ],
    }
    _, collection = H.post("/request-collections", {
        "target_id": target_id,
        "name": "ShakerScan V2 request verifier E2E",
        "format": "postman_collection",
        "document": postman,
    })
    collection_id = str(collection.get("id") or "")
    if not collection_id:
        raise RuntimeError(f"DAST fixture collection rejected: {collection}")
    # Web targets deduplicate by host, while this fixture intentionally runs on
    # a dedicated port. Replace the collection's default origin with the exact
    # origin exercised by the replay transport.
    _, bound = H.post(f"/request-collections/{collection_id}/bindings", {
        "target_kind": "web",
        "target_id": target_id,
        "allowed_origins": [fixture_target],
    })
    binding_id = str((bound.get("binding") or {}).get("id") or "")
    if not binding_id:
        raise RuntimeError(f"DAST fixture binding rejected: {bound}")

    selections: dict[str, dict[str, str]] = {}
    selection_specs = {
        "sqli": (r"/dast/sqli$", 1),
        "xss": (r"/dast/xss$", 1),
        "parity": (
            r"(/dast/(sqli|xss|json)|/authz/orders/owner-order)$",
            5,
        ),
    }
    for family, (path_regex, max_requests) in selection_specs.items():
        _, selected = H.post(
            f"/request-collections/{collection_id}/selections",
            {
                "name": f"e2e-{family}",
                "binding_id": binding_id,
                "replay_policy": "confirmed_active",
                "path_regex": path_regex,
                "safe_methods_only": False,
                "max_requests": max_requests,
            },
        )
        selection_id = str((selected.get("selection") or {}).get("id") or "")
        if not selection_id:
            raise RuntimeError(f"DAST {family} selection rejected: {selected}")
        selections[family] = {
            "collection_id": collection_id,
            "binding_id": binding_id,
            "selection_id": selection_id,
            "replay_policy": "confirmed_active",
        }
    return fixture_target, approval_id, selections


def _hunt_fixture_authority(
    fixture_target: str = FIXTURES_BASE,
    *,
    allowed_host: str = HONEY_HOST,
    risk_tier: str = "active",
) -> tuple[str, str, str]:
    """Create one reusable, target-bound, bounded Hunt approval."""
    _, target = H.post("/targets", {
        "url": fixture_target,
        "name": f"E2E canonical Hunt fixture {_RUN_NONCE}",
    })
    target_id = str(target.get("id") or "")
    if not target_id:
        raise RuntimeError(f"Hunt fixture target rejected: {target}")
    _, scope_response = H.post("/arsenal/scope/preview", {
        "url": fixture_target,
        "target_id": target_id,
        "allowed_hosts": [allowed_host],
        "environment": "lab",
    })
    scope_id = str((scope_response.get("scope_receipt") or {}).get("receipt_id") or "")
    if not scope_id:
        raise RuntimeError(f"Hunt fixture scope rejected: {scope_response}")
    _, approval_response = H.post("/arsenal/approvals", {
        "scope_receipt_id": scope_id,
        "risk_tier": risk_tier,
        "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
        # No action_name: this receipt authorizes the admitted Hunt and its
        # individually revalidated capability calls until expiry or revocation.
        "approved_by": "hunt-e2e",
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(minutes=30)
        ).isoformat(),
    })
    approval_id = str(
        (approval_response.get("approval_receipt") or {}).get("id") or ""
    )
    if not approval_id:
        raise RuntimeError(f"Hunt fixture approval rejected: {approval_response}")
    return target_id, scope_id, approval_id


def _hunt_start_payload(
    target_id: str,
    *,
    active: bool = False,
    approval_id: str | None = None,
    scope_id: str | None = None,
    goal: str,
    target_kind: str = "web",
    network_discovery: bool = False,
    credential_refs: dict[str, str] | None = None,
    request_collection_ids: list[str] | None = None,
    capabilities: list[str] | None = None,
) -> dict:
    credentials_requested = bool(credential_refs)
    privileged = active or network_discovery or credentials_requested
    return {
        "schema_version": "hunt-start/v2",
        "target_id": target_id,
        "target_kind": target_kind,
        "goal": goal,
        "budget_profile": "fast",
        "budgets": {
            "max_active_actions": 4 if privileged else 0,
            "max_state_changing_requests": 0,
            "max_hosts": 1 if network_discovery else 0,
            "max_tcp_ports": 100 if network_discovery else 0,
            "max_udp_ports": 0,
            "max_oob_interactions": 0,
            "max_device_fragility_points": 5 if target_kind == "device" else 0,
        },
        "policy": {
            "active_testing": active or network_discovery,
            "allow_state_changing_http": False,
            "network_discovery": network_discovery,
            "allow_oob_interactions": False,
            "authorization_confirmed": privileged,
            "approval_receipt_id": approval_id,
            "scope_receipt_id": scope_id,
        },
        "credential_refs": credential_refs or {},
        "capabilities": capabilities or [],
        "request_collection_ids": request_collection_ids or [],
    }


def _hunt_api_collection_fixture(
    target_id: str,
) -> tuple[str, str, str]:
    """Create two exact principals and one API-bound safe request collection."""
    profile_ids: list[str] = []
    for slot, token in (("primary", "parity-owner"), ("secondary", "parity-attacker")):
        status, created = H.post("/credential-profiles", {
            "target_kind": "api",
            "target_id": target_id,
            "name": f"Hunt E2E {slot} {_RUN_NONCE}",
            "auth_kind": "authorization_header",
            "principal_slot": slot,
            "principal_label": f"e2e-{slot}",
            "secret": f"Bearer {token}",
            "allowed_capabilities": ["http.request", "request.replay"],
            "created_by": "hunt-e2e",
        })
        profile_id = str((created.get("profile") or {}).get("id") or "")
        if status != 201 or not profile_id:
            raise RuntimeError(f"Hunt {slot} credential rejected: {created}")
        profile_ids.append(profile_id)

    status, collection = H.post("/request-collections", {
        "target_id": target_id,
        "name": f"Hunt API replay E2E {_RUN_NONCE}",
        "format": "postman_collection",
        "document": {
            "info": {
                "name": "Hunt API replay E2E",
                "schema": (
                    "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                ),
            },
            "item": [{
                "name": "Exact principal-safe order read",
                "request": {
                    "method": "GET",
                    "header": [{"key": "X-E2E-Collection", "value": "hunt-v2"}],
                    "url": f"{FIXTURES_BASE}/authz/orders/owner-order?shape=hunt",
                },
            }],
        },
    })
    collection_id = str(collection.get("id") or "")
    if status != 200 or not collection_id:
        raise RuntimeError(f"Hunt API collection rejected: {collection}")
    _, bound = H.post(f"/request-collections/{collection_id}/bindings", {
        "target_kind": "api",
        "target_id": target_id,
        "allowed_origins": [FIXTURES_BASE],
    })
    if not (bound.get("binding") or {}).get("id"):
        raise RuntimeError(f"Hunt API collection binding rejected: {bound}")
    return collection_id, profile_ids[0], profile_ids[1]


def _load_real_mcp_adapter():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "shakerscan_mcp.py"
    module_name = f"_shakerscan_mcp_e2e_{os.getpid()}"
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load installed MCP adapter")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def run_hunt() -> H.Scorecard:
    """Exercise canonical Hunt authority through REST, CLI, and MCP clients."""
    sc = H.Scorecard("hunt")
    print("\n== Hunt V2 e2e ==", flush=True)
    target_id = scope_id = approval_id = ""
    try:
        hunt_host = urllib.parse.urlsplit(HUNT_WEB_TARGET).hostname or HONEY_HOST
        target_id, scope_id, approval_id = _hunt_fixture_authority(
            HUNT_WEB_TARGET,
            allowed_host=hunt_host,
        )
    except Exception as exc:
        sc.error("H-0 target-bound fixture authority", exc)
        return sc

    # Direct REST: explicit passive zeros, one durable inline action, duplicate
    # redelivery, receipt query, and a clean finish.
    try:
        status, passive = H.post("/hunts", _hunt_start_payload(
            target_id,
            goal="Passive real-stack Hunt acceptance.",
        ))
        hunt_id = str(passive.get("hunt_id") or "")
        budget = passive.get("budget") or {}
        policy = passive.get("policy") or {}
        sc.check(
            "H-1 passive REST Hunt preserves zero authority",
            status == 200
            and bool(hunt_id)
            and policy.get("active_testing") is False
            and all(int(budget.get(key) or 0) == 0 for key in (
                "max_active_actions", "max_state_changing_requests", "max_hosts",
                "max_tcp_ports", "max_udp_ports", "max_oob_interactions",
                "max_device_fragility_points",
            )),
            f"status={status} hunt={hunt_id} budget={budget}",
        )
        key = f"e2e-rest-inline-{_RUN_NONCE}"
        call_status, first = H.post(
            f"/hunts/{hunt_id}/capabilities/collections.inspect",
            {"idempotency_key": key, "input": {}},
            timeout=90,
        )
        replay_status, replay = H.post(
            f"/hunts/{hunt_id}/capabilities/collections.inspect",
            {"idempotency_key": key, "input": {}},
            timeout=90,
        )
        sc.check(
            "H-2 passive action persists receipt and duplicate delivery is idempotent",
            call_status == replay_status == 200
            and bool(first.get("action_id"))
            and bool(first.get("receipt_id"))
            and replay.get("action_id") == first.get("action_id")
            and replay.get("idempotent_replay") is True,
            f"first={first} replay={replay}",
        )
        invalid_status, _invalid = H.post(
            f"/hunts/{hunt_id}/capabilities/http.request",
            {
                "idempotency_key": f"e2e-target-smuggle-{_RUN_NONCE}",
                "input": {
                    "method": "GET", "path": "/", "url": "https://other.invalid",
                },
            },
        )
        sc.check(
            "H-3 planner cannot supply a capability target",
            invalid_status == 422,
            f"status={invalid_status}",
        )
        _, receipts = H.post(f"/hunts/{hunt_id}/query", {
            "kind": "receipts", "limit": 20,
        })
        serialized_receipts = json.dumps(receipts).lower()
        sc.check(
            "H-4 REST Hunt receipt query remains content-free",
            int(receipts.get("count") or 0) >= 1
            and "authorization: bearer" not in serialized_receipts
            and "password=" not in serialized_receipts,
            f"count={receipts.get('count')}",
        )
        _, finished = H.post(f"/hunts/{hunt_id}/finish", {
            "summary": "Passive acceptance completed.", "next_actions": [],
        })
        sc.check(
            "H-5 passive REST Hunt completes",
            finished.get("status") == "completed",
            f"status={finished.get('status')}",
        )
    except Exception as exc:
        sc.error("H-1 through H-5 passive REST lifecycle", exc)

    # Privileged REST: use one active server-returned verifier, revoke the exact
    # reusable approval, and prove a second active action fails before dispatch.
    try:
        status, active = H.post("/hunts", _hunt_start_payload(
            target_id,
            active=True,
            approval_id=approval_id,
            scope_id=scope_id,
            goal="Privileged verifier and revocation acceptance.",
        ))
        active_hunt_id = str(active.get("hunt_id") or "")
        allowed = {
            str(item.get("name"))
            for item in active.get("capabilities") or []
            if isinstance(item, dict)
        }
        sc.check(
            "H-6 active REST Hunt receives bounded verifier authority",
            status == 200 and bool(active_hunt_id) and "xss.verify" in allowed,
            f"status={status} capabilities={sorted(allowed)}",
        )
        call_status, action = H.post(
            f"/hunts/{active_hunt_id}/capabilities/xss.verify",
            {
                "idempotency_key": f"e2e-active-xss-{_RUN_NONCE}",
                "input": {"severity": "low"},
            },
            timeout=180,
        )
        sc.check(
            "H-7 privileged verifier settles a durable action and receipt",
            call_status == 200
            and bool(action.get("action_id"))
            and bool(action.get("receipt_id"))
            and action.get("status") in {"completed", "partial"},
            f"status={call_status} action={action}",
        )
        revoke_status, revoked = H.post(
            f"/arsenal/approvals/{approval_id}/revoke",
            {"revoked_by": "hunt-e2e", "reason": "prove fail-closed redelivery"},
        )
        second_status, second = H.post(
            f"/hunts/{active_hunt_id}/capabilities/xss.verify",
            {
                "idempotency_key": f"e2e-active-after-revoke-{_RUN_NONCE}",
                "input": {"severity": "low"},
            },
        )
        sc.check(
            "H-8 revoked approval blocks the next privileged action",
            revoke_status == 200
            and revoked.get("revoked") is True
            and second_status == 400
            and "revoked" in json.dumps(second).lower(),
            f"revoke={revoke_status} second={second_status} body={second}",
        )
        _, finished = H.post(f"/hunts/{active_hunt_id}/finish", {
            "summary": "Active verifier and revocation acceptance completed.",
            "next_actions": [],
        })
        sc.check(
            "H-9 privileged REST Hunt completes after authority revocation",
            finished.get("status") == "completed",
            f"status={finished.get('status')}",
        )
    except Exception as exc:
        sc.error("H-6 through H-9 privileged REST lifecycle", exc)

    # Installed wrapper: start and call through scanner.sh, parsing only stable
    # JSON. This covers runtime API discovery rather than calling v2_cli directly.
    try:
        root = Path(__file__).resolve().parents[2]
        cli_path = Path(
            os.environ.get("SHAKERSCAN_E2E_CLI") or (root / "scanner.sh")
        )
        cli_env = dict(os.environ)
        if os.environ.get("SHAKERSCAN_E2E_CLI_HOME"):
            cli_env["HOME"] = str(os.environ["SHAKERSCAN_E2E_CLI_HOME"])
        cli_start = subprocess.run(
            [
                str(cli_path), "hunt", "start",
                "--target-id", target_id,
                "--target-kind", "web",
                "--budget-profile", "fast",
                "--budget", "max_active_actions=0",
                "--budget", "max_state_changing_requests=0",
                "--budget", "max-hosts=0",
            ],
            cwd=root,
            env=cli_env,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        # A misspelled server dimension must fail locally and preserve a stable
        # non-zero exit before the valid wrapper acceptance below.
        sc.check(
            "H-10 installed CLI rejects contract drift with stable exit code",
            cli_start.returncode == 2
            and "budget dimension" in cli_start.stderr.lower(),
            f"exit={cli_start.returncode}",
        )
        valid_cli_start = subprocess.run(
            [
                str(cli_path), "hunt", "start",
                "--target-id", target_id,
                "--target-kind", "web",
                "--budget-profile", "fast",
                "--budget", "max_active_actions=0",
                "--budget", "max_state_changing_requests=0",
                "--budget", "max_hosts=0",
            ],
            cwd=root,
            env=cli_env,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        cli_hunt = json.loads(valid_cli_start.stdout or "{}")
        cli_hunt_id = str(cli_hunt.get("hunt_id") or "")
        cli_call = subprocess.run(
            [
                str(cli_path), "hunt", "call", cli_hunt_id,
                "collections.inspect", "--idempotency-key",
                f"e2e-cli-inline-{_RUN_NONCE}",
            ],
            cwd=root,
            env=cli_env,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        cli_action = json.loads(cli_call.stdout or "{}")
        sc.check(
            "H-11 installed CLI start and call produce valid V2 authority",
            valid_cli_start.returncode == cli_call.returncode == 0
            and bool(cli_hunt_id)
            and cli_action.get("response", {}).get("status") == "completed",
            f"start_exit={valid_cli_start.returncode} call_exit={cli_call.returncode}",
        )
        H.post(f"/hunts/{cli_hunt_id}/finish", {
            "summary": "Installed CLI acceptance completed.", "next_actions": [],
        })
    except Exception as exc:
        sc.error("H-10 through H-11 installed CLI acceptance", exc)

    # MCP adapter: invoke its real client implementation against this API, then
    # compare the same canonical policy/manifest/action lifecycle.
    try:
        mcp = _load_real_mcp_adapter()
        client = mcp.ArsenalClient(H.API)
        started = client.call_tool("shakerscan_hunt_start", {
            "schema_version": "hunt-start/v2",
            "target_id": target_id,
            "target_kind": "web",
            "goal": "MCP real-stack Hunt acceptance.",
            "budget_profile": "fast",
            "budgets": {
                "max_active_actions": 0,
                "max_state_changing_requests": 0,
                "max_hosts": 0,
            },
            "policy": {},
        })["structuredContent"]
        mcp_hunt_id = str(started.get("hunt_id") or "")
        action = client.call_tool("shakerscan_hunt_capability", {
            "hunt_id": mcp_hunt_id,
            "capability_name": "collections.inspect",
            "idempotency_key": f"e2e-mcp-inline-{_RUN_NONCE}",
            "input": {},
        })["structuredContent"]
        queried = client.call_tool("shakerscan_hunt_query", {
            "hunt_id": mcp_hunt_id, "kind": "receipts", "limit": 20,
        })["structuredContent"]
        finished = client.call_tool("shakerscan_hunt_finish", {
            "hunt_id": mcp_hunt_id,
            "summary": "MCP acceptance completed.",
            "next_actions": [],
        })["structuredContent"]
        sc.check(
            "H-12 MCP start, query, capability, and finish use the real V2 API",
            bool(mcp_hunt_id)
            and action.get("status") == "completed"
            and int(queried.get("count") or 0) >= 1
            and finished.get("status") == "completed",
            f"hunt={mcp_hunt_id} action={action.get('status')}",
        )
    except Exception as exc:
        sc.error("H-12 MCP real-stack acceptance", exc)

    # API/collection Hunt: bind an exact safe request to the API origin, use
    # two worker-only principals, and prove method/query/header/body/principal
    # preservation from the fixture's independent traffic ledger.
    try:
        api_target_id, api_scope_id, api_approval_id = _hunt_fixture_authority(
            risk_tier="credential",
        )
        collection_id, primary_id, secondary_id = _hunt_api_collection_fixture(
            api_target_id,
        )
        FX.reset_parity_traffic()
        status, api_hunt = H.post("/hunts", _hunt_start_payload(
            api_target_id,
            goal="Exact API collection and principal replay acceptance.",
            target_kind="api",
            approval_id=api_approval_id,
            scope_id=api_scope_id,
            credential_refs={
                "primary_credential_profile_id": primary_id,
                "secondary_credential_profile_id": secondary_id,
            },
            request_collection_ids=[collection_id],
            capabilities=["collections.inspect", "collections.replay_safe"],
        ))
        api_hunt_id = str(api_hunt.get("hunt_id") or "")
        actions: list[dict] = []
        for principal in ("primary", "secondary"):
            action_status, action = H.post(
                f"/hunts/{api_hunt_id}/capabilities/collections.replay_safe",
                {
                    "idempotency_key": f"e2e-api-{principal}-{_RUN_NONCE}",
                    "input": {
                        "collection_id": collection_id,
                        "methods": ["GET"],
                        "path_regex": r"/authz/orders/owner-order$",
                        "limit": 1,
                        "as_principal": principal,
                    },
                },
                timeout=120,
            )
            actions.append({"http_status": action_status, **action})
        traffic = FX.parity_traffic()
        relevant = [
            item for item in traffic
            if item.get("path") == "/authz/orders/owner-order"
        ]
        sc.check(
            "H-13 API collection replay preserves exact request and two principals",
            status == 200
            and bool(api_hunt_id)
            and all(
                item.get("http_status") == 200
                and item.get("status") in {"completed", "partial"}
                and item.get("receipt_id")
                for item in actions
            )
            and {item.get("principal") for item in relevant} >= {"owner", "attacker"}
            and all(
                item.get("method") == "GET"
                and item.get("query_keys") == ["shape"]
                and item.get("collection_marker") == "hunt-v2"
                and int(item.get("content_length") or 0) == 0
                for item in relevant
            ),
            f"actions={actions} traffic={relevant}",
        )
        H.post(f"/hunts/{api_hunt_id}/finish", {
            "summary": "API collection acceptance completed.", "next_actions": [],
        })
    except Exception as exc:
        sc.error("H-13 API collection and principal acceptance", exc)

    # Network Hunt: the only target input is the registered target; the planner
    # supplies a bounded port list. Cancelling the Hunt prevents all later work.
    try:
        network_target_id, network_scope_id, network_approval_id = (
            _hunt_fixture_authority(risk_tier="active")
        )
        status, network_hunt = H.post("/hunts", _hunt_start_payload(
            network_target_id,
            goal="Registered-address network service acceptance.",
            target_kind="network",
            network_discovery=True,
            approval_id=network_approval_id,
            scope_id=network_scope_id,
            capabilities=["service.fingerprint"],
        ))
        network_hunt_id = str(network_hunt.get("hunt_id") or "")
        action_status, action = H.post(
            f"/hunts/{network_hunt_id}/capabilities/service.fingerprint",
            {
                "idempotency_key": f"e2e-network-service-{_RUN_NONCE}",
                "input": {"ports": [FIXTURES_PORT], "profile": "version_light"},
            },
            timeout=180,
        )
        _, cancelled = H.post(f"/hunts/{network_hunt_id}/cancel", {})
        after_status, _after = H.post(
            f"/hunts/{network_hunt_id}/capabilities/service.fingerprint",
            {
                "idempotency_key": f"e2e-network-after-cancel-{_RUN_NONCE}",
                "input": {"ports": [FIXTURES_PORT], "profile": "version_light"},
            },
        )
        sc.check(
            "H-14 network Hunt binds registered addresses and cancellation stops new work",
            status == 200
            and action_status == 200
            and action.get("status") in {"completed", "partial"}
            and bool(action.get("receipt_id"))
            and cancelled.get("status") == "cancelled"
            and after_status == 409,
            (
                f"start={status} action={action_status}/{action.get('status')} "
                f"cancel={cancelled.get('status')} after={after_status}"
            ),
        )
    except Exception as exc:
        sc.error("H-14 network and cancellation acceptance", exc)

    # Device Hunt: no separate device-agent engine. New work persists typed
    # canonical policy/runtime state and removes the legacy device_state view.
    device_id = ""
    try:
        pid = os.getpid()
        stamp = int(_time.time())
        locator = (
            f"127.{1 + pid % 250}.{1 + stamp % 250}."
            f"{1 + (pid + stamp) % 250}"
        )
        device_status, created = H.post("/devices", {
            "name": f"LG TV Hunt E2E {_RUN_NONCE}",
            "primary_locator": locator,
            "device_class": "tv",
            "manufacturer": "LG",
            "model": "release-fixture",
            "identity_confidence": "high",
            "environment": "lab",
        })
        device_id = str((created.get("device") or {}).get("id") or "")
        status, device_hunt = H.post("/hunts", _hunt_start_payload(
            device_id,
            goal="Canonical typed device Hunt acceptance.",
            target_kind="device",
            capabilities=["device.inspect", "device.capabilities.inspect"],
        ))
        device_hunt_id = str(device_hunt.get("hunt_id") or "")
        action_status, action = H.post(
            f"/hunts/{device_hunt_id}/capabilities/device.inspect",
            {
                "idempotency_key": f"e2e-device-inspect-{_RUN_NONCE}",
                "input": {},
            },
        )
        current = H.get(f"/hunts/{device_hunt_id}")
        context = current.get("context_pack") or {}
        sc.check(
            "H-15 device Hunt uses canonical typed state and one action receipt",
            device_status == 200
            and status == 200
            and action_status == 200
            and action.get("status") == "completed"
            and bool(action.get("receipt_id"))
            and isinstance(context.get("device_policy_state"), dict)
            and context.get("device_policy_state", {}).get("schema_version")
                == "hunt-device-policy/v2"
            and isinstance(context.get("device_runtime"), dict)
            and context.get("device_runtime", {}).get("schema_version")
                == "hunt-device-runtime/v2"
            and "device_state" not in context,
            f"create={device_status} start={status} action={action_status} context={context}",
        )
        H.post(f"/hunts/{device_hunt_id}/finish", {
            "summary": "Device Hunt acceptance completed.", "next_actions": [],
        })
    except Exception as exc:
        sc.error("H-15 canonical device Hunt acceptance", exc)
    finally:
        if device_id:
            H.delete(f"/devices/{device_id}")

    return sc


def run_dast() -> H.Scorecard:
    sc = H.Scorecard("dast")
    print("\n== DAST e2e ==", flush=True)

    # D-1: a passive canonical V2 Scan of Juice Shop must complete, retain
    # deterministic baseline posture findings, and expose its action receipts.
    try:
        _, resp = H.post("/scans", {
            "target": JUICE_SHOP,
            "budget_profile": "fast",
            "policy": {"active_testing": False},
            "advanced": {"max_endpoints": 40, "force_single_worker": True},
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-1 scan accepted", bool(scan_id), str(resp)[:120])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=1200, poll=10, label="D-1")
            status = str(scan.get("status"))
            sc.check("D-1 scan completes (no hang/crash/reap)", status == "completed", f"status={status}")
            res = H.scan_result(scan_id)
            log_lines = (H.get(f"/scans/{scan_id}/logs?limit=1000").get("lines") or [])
            connectivity_failures = [
                str(line) for line in log_lines
                if "pre_scan_failed" in str(line).lower() or "target unreachable" in str(line).lower()
            ]
            sc.check(
                "D-1 target was reachable from the worker",
                not connectivity_failures,
                f"connectivity_failures={connectivity_failures[:2]}",
            )
            findings = res.get("findings") or []
            grade = res.get("grade") or (res.get("result") or {}).get("grade")
            sc.check("D-1 graded report produced", bool(grade), f"grade={grade}")
            sc.check("D-1 findings persisted (no save crash)", len(findings) > 0, f"findings={len(findings)}")
            canonical = res.get("canonical_action_execution") or {}
            baseline_receipt = next((
                action for action in canonical.get("actions") or []
                if action.get("action_id") == "baseline.http"
            ), {})
            passive_template_receipt = next((
                action for action in canonical.get("actions") or []
                if action.get("action_id") == "passive.templates"
            ), {})
            sc.check(
                "D-1 canonical action receipt persisted",
                res.get("schema_version") == "canonical-scan-report/v2"
                and baseline_receipt.get("status") == "success"
                and bool(baseline_receipt.get("receipt")),
                f"schema={res.get('schema_version')} baseline={baseline_receipt.get('status')}",
            )
            sc.check(
                "D-1 reviewed passive template pack completes",
                passive_template_receipt.get("status") == "success"
                and bool(passive_template_receipt.get("receipt"))
                and passive_template_receipt.get("budget_reserved") == {
                    "http_requests": 7,
                    "tool_wall_seconds": 30,
                },
                (
                    "status="
                    f"{passive_template_receipt.get('status')} "
                    "reserved="
                    f"{passive_template_receipt.get('budget_reserved')}"
                ),
            )
            # D-4: the 3 removed phantom attack chains must never be reported.
            chains = json.dumps((res.get("attack_chains") or {}))
            phantom = [c for c in ("auth_bypass_to_admin_access", "open_redirect_to_phishing",
                                   "info_disclosure_to_exploitation") if c in chains]
            sc.check("D-4 no phantom attack chains reported", not phantom, f"phantom={phantom}")
    except Exception as e:
        sc.error("D-1 standard scan", e)

    fixture_target = ""
    approval_id = ""
    selections: dict[str, dict[str, str]] = {}
    setup_error: Exception | None = None
    try:
        fixture_target, approval_id, selections = _dast_fixture_authority()
    except Exception as exc:
        setup_error = exc

    # D-2: a true canonical active Scan must replay an exact encrypted POST body,
    # run the SQLi mutation differential, and retain its suspected finding.
    try:
        if setup_error:
            raise setup_error
        _, resp = H.post("/scans", {
            "target": fixture_target,
            "budget_profile": "balanced",
            "policy": {
                "active_testing": True,
                "allow_state_changing_http": True,
                "exclude_families": ["xss", "nuclei", "bola"],
            },
            "advanced": {
                "max_duration_seconds": 600,
                "max_http_requests": 2000,
                "max_state_changing_requests": 10,
                "max_endpoints": 40,
                "force_single_worker": True,
            },
            "approval_receipt_id": approval_id,
            "request_collections": [selections["sqli"]],
            "options": {"require_current_workers": True},
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-2 bounded active scan accepted", bool(scan_id), str(resp)[:100])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=600, poll=8, label="D-2")
            sc.check("D-2 bounded active scan completes", str(scan.get("status")) == "completed",
                     f"status={scan.get('status')}")
            findings = (H.scan_result(scan_id).get("findings") or [])
            sqli = [
                f for f in findings
                if f.get("tool") == "request_sqli_differential"
            ]
            sc.check("D-2 retains request-based SQLi result", bool(sqli),
                     f"sqli={[str(f.get('title'))[:45] for f in sqli][:3]}")
    except Exception as e:
        sc.error("D-2 bounded active SQLi detection", e)

    # D-3: the same public V2 path must retain a reflected request-body XSS
    # differential as a suspected finding, never silently omit it.
    try:
        if setup_error:
            raise setup_error
        _, resp = H.post("/scans", {
            "target": fixture_target,
            "budget_profile": "balanced",
            "policy": {
                "active_testing": True,
                "allow_state_changing_http": True,
                "exclude_families": ["sqli", "nuclei", "bola"],
            },
            "advanced": {
                "max_duration_seconds": 600,
                "max_http_requests": 2000,
                "max_state_changing_requests": 10,
                "max_endpoints": 40,
                "force_single_worker": True,
            },
            "approval_receipt_id": approval_id,
            "request_collections": [selections["xss"]],
            "options": {"require_current_workers": True},
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-3 bounded XSS scan accepted", bool(scan_id), str(resp)[:100])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=600, poll=8, label="D-3")
            sc.check("D-3 bounded XSS scan completes", str(scan.get("status")) == "completed",
                     f"status={scan.get('status')}")
            findings = (H.scan_result(scan_id).get("findings") or [])
            xss = [
                f for f in findings
                if f.get("tool") == "request_xss_differential"
            ]
            sc.check("D-3 retains request-based XSS result", bool(xss),
                     f"xss={[str(f.get('title'))[:40] for f in xss][:3]}")
    except Exception as e:
        sc.error("D-3 bounded XSS detection", e)

    return sc


AREAS = {
    "platform": run_platform,
    "model_intake": run_model_intake,
    "ai_gate": run_ai_gate,
    "dast": run_dast,
    "hunt": run_hunt,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--area", default="all", choices=["all", *AREAS.keys()])
    ap.add_argument(
        "--scorecard",
        default=os.environ.get("SHAKERSCAN_E2E_SCORECARD"),
        help="write the complete machine-readable scorecard to this path",
    )
    args = ap.parse_args()

    H.preflight()
    # Start the local fixtures server (leaky AI endpoint + model artifacts); the
    # worker reaches it at host.docker.internal:FIXTURES_PORT.
    FX.start(FIXTURES_PORT)
    print(f"fixtures server on :{FIXTURES_PORT} (worker URL {FIXTURES_BASE})", flush=True)
    areas = list(AREAS.values()) if args.area == "all" else [AREAS[args.area]]
    cards = [fn() for fn in areas]

    print("\n== Scorecard ==", flush=True)
    failed = False
    for c in cards:
        s = c.summary()
        print(f"  {s['area']}: {s['passed']}/{s['total']} — gate {s['gate'].upper()}", flush=True)
        failed = failed or not c.passed
    if args.scorecard:
        scorecard = {
            "schema_version": "shakerscan-e2e-scorecard/v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gate": "fail" if failed else "pass",
            "areas": [card.summary() for card in cards],
        }
        scorecard_path = os.path.abspath(args.scorecard)
        os.makedirs(os.path.dirname(scorecard_path), exist_ok=True)
        with open(scorecard_path, "w", encoding="utf-8") as handle:
            json.dump(scorecard, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        print(f"scorecard written to {scorecard_path}", flush=True)
    print(("\nE2E GATE: FAIL" if failed else "\nE2E GATE: PASS"), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
