"""Assisted authorization proof through the real API, queue, worker and database.

Known vulnerable/protected/shared fixture routes test proof completion, not AI
route discovery, a Juice Shop answer key, or a claim about recall improvement.
"""
from __future__ import annotations


def run(harness, scorecard, *, authority, start_payload, fixture_base: str, nonce: str) -> None:
    hunt_id = ""
    try:
        target_id, scope_id, approval_id = authority(risk_tier="credential")
        profiles = {}
        for slot, token in (("primary", "authz-token-a"), ("secondary", "authz-token-b")):
            status, created = harness.post("/credential-profiles", {
                "target_kind": "web", "target_id": target_id,
                "name": f"Hunt proof {slot} {nonce}",
                "auth_kind": "authorization_header", "principal_slot": slot,
                "principal_label": f"proof-{slot}", "secret": f"Bearer {token}",
                "allowed_capabilities": ["auth.session.establish", "authz.verify"],
                # authz.verify is an active credential consumer. Reuse the same
                # target-bound credential-tier approval that authorizes this Hunt
                # instead of weakening the profile contract for an E2E fixture.
                "allow_active_capabilities": True,
                "approval_receipt_id": approval_id,
                "created_by": "hunt-e2e",
            })
            profile_id = str((created.get("profile") or {}).get("id") or "")
            if status != 201 or not profile_id:
                raise RuntimeError(f"proof profile setup failed: status={status}")
            profiles[f"{slot}_credential_profile_id"] = profile_id
        payload = start_payload(target_id, active=True, goal="Assisted authorization proof completion",
            scope_id=scope_id, approval_id=approval_id, credential_refs=profiles,
            capabilities=["auth.session.establish", "authz.verify"], budget_profile="balanced")
        # Five actual actions: two sessions, one positive, and two negative controls.
        # Reserve headroom so exhaustion does not replace the subject of this test.
        payload["budgets"]["max_active_actions"] = 8
        status, started = harness.post("/hunts", payload)
        hunt_id = str(started.get("hunt_id") or "")
        if status != 200 or not hunt_id:
            raise RuntimeError(f"proof Hunt setup failed: status={status}")

        def call(name, body):
            status, response = harness.post(f"/hunts/{hunt_id}/capabilities/{name}", body, timeout=180)
            result = response.get("result") or {}
            if status != 200 or result.get("status") not in {"success", "partial"} or not result.get("receipt_id"):
                raise RuntimeError(f"proof action failed: {name} status={status} result={result}")
            return response, result

        sessions = {}
        for slot in ("primary", "secondary"):
            _, result = call("auth.session.establish", {
                "idempotency_key": f"proof-session-{slot}-{nonce}", "input": {"as_principal": slot},
            })
            ref = str((result.get("session") or {}).get("session_ref") or "")
            if not ref:
                raise RuntimeError(f"proof session missing: {slot}")
            sessions[f"{slot}_session_ref"] = ref

        def request(key, routes):
            return {"idempotency_key": f"proof-{key}-{nonce}",
                    "input": {**sessions, "routes": [fixture_base + path for path in routes]}}

        body = request("positive", ["/authz/vuln/orders", "/authz/vuln/orders/1001"])
        response, result = call("authz.verify", body)
        ids = result.get("verified_finding_ids") or []
        finding = harness.get(f"/findings/{ids[0]}") if len(ids) == 1 else {}
        row = finding.get("finding", finding)
        per_hunt = harness_findings(harness, hunt_id)
        before = harness.get(f"/hunts/{hunt_id}").get("budget_used")
        replay, repeated = call("authz.verify", body)
        after = harness.get(f"/hunts/{hunt_id}").get("budget_used")
        current = harness.get(f"/findings/{ids[0]}") if len(ids) == 1 else {}
        current_row = current.get("finding", current)
        receipt = result.get("receipt") or {}
        observation = next((item for item in receipt.get("observations", [])
                            if item.get("kind") == "authz_differential"), {})
        scorecard.check(
            "H-19 authorization proof materializes into a Hunt-attributed finding",
            len(ids) == 1 and observation.get("proof_state") == "verified"
            and row.get("last_verification_verdict") == "exploited"
            and row.get("is_verified") is True and row.get("proof_state") == "verified"
            and str(row.get("hunt_run_id")) == hunt_id and row.get("cwe") == "CWE-639"
            and any(str(item.get("id")) == ids[0] for item in per_hunt)
            and repeated.get("verified_finding_ids") == ids
            and repeated.get("receipt_id") == result.get("receipt_id")
            and replay.get("action_id") == response.get("action_id")
            and before == after and before is not None
            and current_row.get("verification_count") == row.get("verification_count")
            and int(row.get("verification_count") or 0) >= 1,
            f"hunt={hunt_id} ids={ids} proof={observation.get('proof_state')} "
            f"attributed={row.get('hunt_run_id')} replay={replay.get('idempotent_replay')}",
        )

        controls = []
        for key, routes in (("protected", ["/authz/safe/orders", "/authz/safe/orders/1001"]),
                            ("shared", ["/authz/public/directory", "/authz/public/directory/7001"])):
            _, control = call("authz.verify", request(key, routes))
            observations = (control.get("receipt") or {}).get("observations") or []
            differentials = [item for item in observations if item.get("kind") == "authz_differential"]
            controls.append(bool(differentials) and not control.get("verified_finding_ids")
                            and all(item.get("proof_state") != "verified" for item in differentials))
        scorecard.check(
            "H-20 protected and shared objects remain unverified",
            all(controls) and len(controls) == 2
            and {str(item.get("id")) for item in harness_findings(harness, hunt_id)} == set(ids),
            f"hunt={hunt_id} protected/shared={controls}",
        )
    except Exception as exc:
        scorecard.error("H-19 through H-20 canonical authorization proof acceptance", exc)
    finally:
        if hunt_id:
            harness.post(f"/hunts/{hunt_id}/finish", {
                "summary": "Assisted authorization proof acceptance completed; not a discovery benchmark.",
                "next_actions": [],
            })


def harness_findings(harness, hunt_id: str) -> list[dict]:
    return harness.get(f"/findings?hunt_id={hunt_id}&verified_only=true&limit=100").get("findings") or []
