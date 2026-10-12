"""``shakerscan knowledge review`` and ``knowledge allow-changes`` through ShakerScan Enterprise.

On an Enterprise connection (a service token) accepting a proposal, confirming agent-written
instructions and letting Hunts edit a target's instructions each take the person's step-up for
that one decision: the gateway's approval protocol, purpose ``knowledge_decision``. The token alone
never does them, and the CLI never sends the engine's accept or confirm route itself there.

Unit fixtures: FakeGateway is a ``send`` double that serves the approval routes and the reads the
review needs (it is not a gateway; the real gateway runs these flows in the Enterprise
repository's tests with this client in a pseudo-terminal). The terminal is a scripted double.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

from tests.test_knowledge_review_cli import PROPOSAL, TARGET, UNCONFIRMED, _proposal  # noqa: E402

ORIGIN = "https://gateway.example"
CODE = "246810"
REAL_TERMINAL = approval.Terminal


def test_enterprise_release_binds_label_and_time_and_never_posts_directly(monkeypatch):
    gateway = FakeGateway()
    assert _run(gateway, Terminal("r"), "release", TARGET, "--label", "v7",
                "--at", "2026-10-12T10:00:00Z", monkeypatch=monkeypatch) == 0
    (begin,) = gateway.begins()
    entry = begin["knowledge"]
    assert entry["decision"] == "release_marker"
    assert entry["release_label"] == "v7"
    assert entry["released_at"] == "2026-10-12T10:00:00Z"
    assert entry["text_sha256"] == hashlib.sha256(
        b'{"label":"v7","released_at":"2026-10-12T10:00:00Z"}').hexdigest()
    assert not any(method == "POST" and path.endswith("/knowledge/releases")
                   for method, path, _ in gateway.seen)


@pytest.mark.parametrize("action,key,extra", [
    ("dismiss", "d", ["--reason", "false_positive"]), ("reopen", "o", []),
])
def test_enterprise_finding_decision_uses_stepup(monkeypatch, action, key, extra):
    gateway = FakeGateway()
    original = gateway.__call__

    def send(method, path, payload=None, headers=None, **kwargs):
        if method == "GET" and path == f"/findings/{PROPOSAL}":
            return 200, {"id": PROPOSAL, "title": "test", "status": "active"}
        return original(method, path, payload, headers, **kwargs)

    monkeypatch.setattr(approval, "Terminal", lambda: Terminal(key))
    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: send)
    assert v2_cli.main(["--api-url", ORIGIN, "knowledge", action, TARGET, PROPOSAL,
                        "--note", "human decision", *extra]) == 0
    (begin,) = gateway.begins()
    assert begin["knowledge"]["decision"] == action
    assert begin["knowledge"]["subject_id"] == PROPOSAL
    assert begin["knowledge"]["note"] == "human decision"
AUTHORITY = {"target_id": TARGET, "revision": 3, "metadata_changes": True, "instruction_changes": False,
             "credential_profile_ids": [], "collection_ids": [],
             "ssh_host_keys": [{"port": 22, "fingerprint": "SHA256:" + "A" * 43, "source": "pinned"}],
             "ssh_trust_first_contact": False, "recorded_by": "x", "updated_at": "2026-10-10T00:00:00Z"}


def contract_digest(account: str, part: dict[str, Any], origin: str = ORIGIN) -> str:
    """The set digest from the contract text (docs/hunt-permission-requests.md), not the client."""
    document = {"schema_version": "shakerscan-approval-set/v1", "purpose": "knowledge_decision",
                "account": account, "origin": origin,
                "knowledge": {key: part[key] for key in ("decision", "target_id", "subject_id", "text_sha256",
                                                          "expected_revision", "reason", "note")}}
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if part["decision"] == "release_marker":
        document["knowledge"].update(release_label=part["release_label"], released_at=part["released_at"])
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


class FakeGateway:
    """UNIT FIXTURE (a ``send`` double): the review's reads, reject/rebase, the token refusal of
    accept/confirm, and the approval protocol's knowledge purpose."""

    def __init__(self, *proposals: dict[str, Any], unconfirmed: list[dict[str, Any]] | None = None,
                 authority: dict[str, Any] | None = None, knows_knowledge: bool = True,
                 has_stepup: bool = True, enterprise: bool = True) -> None:
        self.enterprise = enterprise
        self.proposals = {item["id"]: dict(item) for item in proposals}
        self.unconfirmed = list(unconfirmed or [])
        self.authority = dict(authority or AUTHORITY)
        self.knows_knowledge, self.has_stepup = knows_knowledge, has_stepup
        self.seen: list[tuple[str, str, Any]] = []
        self.begun: dict[str, dict[str, Any]] = {}

    def __call__(self, method: str, path: str, payload: Any = None, headers: Any = None, *,
                 timeout: float | None = None) -> tuple[int, Any]:
        self.seen.append((method, path, payload))
        if path == "/_enterprise/healthz":
            return (200, {"status": "ok", "mode": "enterprise"}) if self.enterprise else (404, {"detail": "Not Found"})
        if path.startswith("/_enterprise/approvals/"):
            if not self.has_stepup:
                return 404, {"detail": "Not Found"}
            return self._approval(path, payload)
        if method == "GET" and "/instruction-proposals" in path:
            pending = [item for item in self.proposals.values() if item["status"] == "pending"]
            return 200, {"proposals": pending, "unconfirmed_instructions": self.unconfirmed}
        if method == "GET" and path == f"/targets/{TARGET}/hunt-authority":
            return 200, dict(self.authority)
        if method == "GET" and path == f"/targets/{TARGET}":
            return 200, {"id": TARGET, "name": "Admin portal"}
        if method == "PUT" and path == f"/targets/{TARGET}/hunt-authority":
            if payload.get("instruction_changes"):
                return 403, "letting Hunts edit instructions cannot be done with a service token alone"
            self.authority.update(payload, revision=self.authority["revision"] + 1)
            return 200, dict(self.authority)
        if method == "POST" and (path.endswith("/accept") or path.endswith("/skill/confirm")):
            return 403, "cannot be done with a service token alone: run `shakerscan knowledge review`"
        if method == "POST" and path.endswith("/reject"):
            self.proposals[path.split("/")[-2]]["status"] = "rejected"
            return 200, {"proposal": {"status": "rejected"}}
        return 404, {"detail": f"fake has no {method} {path}"}

    def _approval(self, path: str, payload: dict[str, Any]) -> tuple[int, Any]:
        error = "shakerscan-approval-error/v1"
        if path.endswith("/begin"):
            if payload.get("purpose") != "knowledge_decision" or not self.knows_knowledge:
                return 422, {"schema_version": error, "error": "request_invalid",
                             "message": "invalid approval request fields"}
            identifier = f"apv_{len(self.begun) + 1:04d}"
            digest = contract_digest(payload["account"], payload["knowledge"], payload["origin"])
            self.begun[identifier] = {"digest": digest, "knowledge": payload["knowledge"]}
            return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": identifier,
                         "set_digest": digest, "methods": ["totp"], "expires_at": "2026-10-10T00:03:00Z"}
        begun = self.begun.pop(payload["approval_id"], None)
        if begun is None or payload["set_digest"] != begun["digest"]:
            return 404, {"schema_version": error, "error": "approval_unknown", "message": "begin again"}
        if payload["proof"] != {"method": "totp", "code": CODE}:
            return 403, {"schema_version": error, "error": "stepup_failed", "message": "the code is not valid"}
        item = begun["knowledge"]
        if item["decision"] == "accept":
            self.proposals[item["subject_id"]]["status"] = "accepted"
            result = {"proposal": {"status": "accepted"}, "instructions": {"revision": 4}}
        elif item["decision"] == "confirm":
            self.unconfirmed = []
            result = {"revision": 5, "trust": "operator"}
        elif item["decision"] == "allow_changes":
            self.authority.update(instruction_changes=True, revision=self.authority["revision"] + 1)
            result = dict(self.authority)
        elif item["decision"] == "release_marker":
            result = {"id": PROPOSAL, "released_at": item["released_at"]}
        else:
            result = {"finding": {"status": "active" if item["decision"] == "reopen" else "false_positive"}}
        return 200, {"schema_version": "shakerscan-approval-result/v1", "approval_id": payload["approval_id"],
                     "decided_by": "carol", "decision_via": "terminal_stepup",
                     "knowledge": {"decision": item["decision"], "target_id": item["target_id"],
                                   "http_status": 200, "result": result}}

    def begins(self) -> list[dict[str, Any]]:
        return [payload for method, path, payload in self.seen if path == approval.BEGIN_PATH]

    def engine_decisions(self) -> list[str]:
        return [path for method, path, _ in self.seen
                if method == "POST" and (path.endswith("/accept") or path.endswith("/skill/confirm"))]


class Terminal(approval.Terminal):
    """A labelled double for the person's terminal: scripted keys and typed answers."""

    def __init__(self, *keys: str, codes: tuple[str, ...] = (CODE,), account: str = "carol") -> None:
        super().__init__(io.StringIO(), io.StringIO())
        self.keys, self.codes, self.account = list(keys), list(codes), account
        self.secrets_asked = 0

    def require(self, what: str) -> None:
        return None

    def key(self, prompt: str, choices: str, **_waiting: Any) -> str:
        self.stdout.write(prompt)
        key = self.keys.pop(0)
        assert key in choices, (key, choices)
        return key

    def line(self, prompt: str) -> str:
        self.stdout.write(prompt)
        return self.account

    def secret(self, prompt: str) -> str:
        self.stdout.write(prompt)
        self.secrets_asked += 1
        return self.codes.pop(0)


def _run(gateway: FakeGateway, terminal: Terminal, *argv: str, monkeypatch: pytest.MonkeyPatch,
         enterprise: bool = True) -> int:
    monkeypatch.setattr(approval, "Terminal", lambda: terminal)
    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: gateway)
    if enterprise:
        monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "sst_fixture_token")
        url = ORIGIN
    else:
        monkeypatch.delenv("SHAKERSCAN_API_TOKEN", raising=False)
        url = "http://127.0.0.1:8080"
    return v2_cli.main(["--api-url", url, "knowledge", *argv])


def test_an_enterprise_accept_takes_the_persons_code_for_that_proposal(monkeypatch):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64))
    terminal = Terminal("y")
    assert _run(gateway, terminal, "review", "--note", "covers 8443", monkeypatch=monkeypatch) == 0
    (begin,) = gateway.begins()
    assert begin["purpose"] == "knowledge_decision" and begin["account"] == "carol"
    assert begin["origin"] == ORIGIN
    assert begin["knowledge"] == {"decision": "accept", "target_id": TARGET, "subject_id": PROPOSAL,
                                  "text_sha256": "f" * 64, "expected_revision": None, "reason": None, "note": "covers 8443"}
    assert gateway.engine_decisions() == [], "an Enterprise connection never sends accept itself"
    text = terminal.stdout.getvalue()
    assert text.index("+Inspect 443 and 8443.") < text.index("[y] accept") < text.index("TOTP code for carol")
    # What the code decides is said again right before it is asked for.
    summary = f"Your step-up will accept proposal {PROPOSAL} on target {TARGET}, text ffffffffffff, and nothing else."
    assert text.index("[y] accept") < text.index(summary) < text.index("TOTP code for carol")
    assert "accepted: the target instructions are now revision 4 (by carol, with your step-up)" in text
    assert CODE not in text


def test_enterprise_confirm_also_takes_the_step_up_and_reject_does_not(monkeypatch):
    item = {**UNCONFIRMED}
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64), unconfirmed=[item])
    terminal = Terminal("r", "c")
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 0
    (begin,) = gateway.begins()
    assert begin["knowledge"] == {"decision": "confirm", "target_id": TARGET, "subject_id": None,
                                  "text_sha256": "e" * 64, "expected_revision": 4, "reason": None, "note": None}
    assert [path for method, path, _ in gateway.seen if method == "POST" and "/_enterprise" not in path] == [
        f"/targets/{TARGET}/instruction-proposals/{PROPOSAL}/reject"]
    assert terminal.secrets_asked == 1
    assert "confirmed: these are now the target's operator instructions (by carol" in terminal.stdout.getvalue()


def test_each_decision_takes_its_own_step_up(monkeypatch):
    second = _proposal(id="33333333-3333-4333-8333-333333333333", methodology_sha256="b" * 64)
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64), second)
    terminal = Terminal("y", "y", codes=(CODE, CODE))
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 0
    assert [item["knowledge"]["subject_id"] for item in gateway.begins()] == [PROPOSAL, second["id"]]
    assert terminal.secrets_asked == 2


def test_a_wrong_code_decides_nothing_and_the_review_goes_on(monkeypatch):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64), unconfirmed=[dict(UNCONFIRMED)])
    terminal = Terminal("y", "n", codes=("000000",))
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 1
    assert gateway.proposals[PROPOSAL]["status"] == "pending" and gateway.unconfirmed
    assert "not applied: the gateway refused (stepup_failed, HTTP 403)" in terminal.stdout.getvalue()
    assert gateway.engine_decisions() == []


def test_a_gateway_that_predates_terminal_knowledge_review_gets_an_exact_message(monkeypatch):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64), knows_knowledge=False)
    terminal = Terminal("y")
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 1
    text = terminal.stdout.getvalue()
    assert "cannot take knowledge-review decisions from the terminal" in text and "Nothing was decided" in text
    assert gateway.engine_decisions() == [] and gateway.proposals[PROPOSAL]["status"] == "pending"


def test_a_gateway_without_step_up_routes_stops_the_review_without_a_fallback(monkeypatch, capsys):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64), has_stepup=False)
    assert _run(gateway, Terminal("y"), "review", monkeypatch=monkeypatch) == 2
    assert "no terminal approval yet" in capsys.readouterr().err
    assert gateway.engine_decisions() == []


def test_a_proposal_without_the_digest_of_its_text_is_not_sent(monkeypatch):
    gateway = FakeGateway(_proposal())  # an engine that did not give methodology_sha256
    terminal = Terminal("y")
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 1
    assert gateway.begins() == [] and gateway.engine_decisions() == []
    assert "did not give the digest" in terminal.stdout.getvalue()


# --- knowledge allow-changes ---------------------------------------------------------------------


def test_allow_changes_on_enterprise_steps_up_for_that_target_and_revision(monkeypatch):
    gateway = FakeGateway()
    terminal = Terminal("y")
    assert _run(gateway, terminal, "allow-changes", TARGET, monkeypatch=monkeypatch) == 0
    (begin,) = gateway.begins()
    assert begin["knowledge"] == {"decision": "allow_changes", "target_id": TARGET, "subject_id": None,
                                  "text_sha256": None, "expected_revision": 3, "reason": None, "note": None}
    assert not [call for call in gateway.seen if call[0] == "PUT"]
    text = terminal.stdout.getvalue()
    assert "Admin portal" in text and "without a proposal you review" in text
    assert text.index("[y] yes") < text.index("TOTP code for carol")
    assert "on: Hunt permissions are now revision 4 (by carol, with your step-up)" in text


def test_allow_changes_on_open_source_writes_only_that_switch_after_a_keypress(monkeypatch):
    gateway = FakeGateway(enterprise=False)
    monkeypatch.setattr(FakeGateway, "__call__", _oss_put(FakeGateway.__call__))
    assert _run(gateway, Terminal("n"), "allow-changes", TARGET, monkeypatch=monkeypatch, enterprise=False) == 1
    assert not [call for call in gateway.seen if call[0] == "PUT"]
    assert _run(gateway, Terminal("y"), "allow-changes", TARGET, monkeypatch=monkeypatch, enterprise=False) == 0
    ((_, path, body),) = [call for call in gateway.seen if call[0] == "PUT"]
    assert path == f"/targets/{TARGET}/hunt-authority"
    assert body == {"expected_revision": 3, "metadata_changes": True, "credential_profile_ids": [],
                    "collection_ids": [], "ssh_trust_first_contact": False,
                    "ssh_host_keys": [{"port": 22, "fingerprint": "SHA256:" + "A" * 43}],
                    "instruction_changes": True}
    assert gateway.begins() == []


def _oss_put(original):
    def call(self, method, path, payload=None, headers=None, *, timeout=None):
        if method == "PUT":
            self.seen.append((method, path, payload))
            self.authority.update(payload, revision=self.authority["revision"] + 1)
            return 200, dict(self.authority)
        return original(self, method, path, payload, headers, timeout=timeout)
    return call


def test_turning_it_off_needs_no_step_up_and_already_set_changes_nothing(monkeypatch):
    gateway = FakeGateway(authority={**AUTHORITY, "instruction_changes": True})
    terminal = Terminal("y")
    assert _run(gateway, terminal, "allow-changes", TARGET, "--off", monkeypatch=monkeypatch) == 0
    assert gateway.begins() == [] and terminal.secrets_asked == 0
    ((_, _, body),) = [call for call in gateway.seen if call[0] == "PUT"]
    assert body["instruction_changes"] is False and body["expected_revision"] == 3
    again = Terminal()
    assert _run(gateway, again, "allow-changes", TARGET, "--off", monkeypatch=monkeypatch) == 0
    assert "nothing to change" in again.stdout.getvalue()


@pytest.mark.parametrize("target", ["not-a-uuid", "../../hunts", TARGET + "x"])
def test_allow_changes_refuses_anything_but_a_target_id(monkeypatch, capsys, target):
    gateway = FakeGateway()
    assert _run(gateway, Terminal(), "allow-changes", target, monkeypatch=monkeypatch) == 2
    assert "is not a target id" in capsys.readouterr().err and gateway.seen == []


def test_allow_changes_refuses_an_engine_without_the_setting(monkeypatch, capsys):
    gateway = FakeGateway(authority={"target_id": TARGET, "revision": 1})
    assert _run(gateway, Terminal(), "allow-changes", TARGET, monkeypatch=monkeypatch) == 2
    assert "arrives with 2.9" in capsys.readouterr().err


def test_allow_changes_and_review_refuse_a_pipe(monkeypatch, capsys):
    """The real terminal check: an agent's tool shell is a pipe, refused before any request."""
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64))
    monkeypatch.setattr(v2_cli, "_approval_send", lambda client: gateway)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", "sst_fixture_token")
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n246810\n"))
    assert v2_cli.main(["--api-url", ORIGIN, "knowledge", "allow-changes", TARGET]) == 2
    assert v2_cli.main(["--api-url", ORIGIN, "knowledge", "review"]) == 2
    assert capsys.readouterr().err.count("interactive terminal") == 2
    assert gateway.seen == []


# --- the decision entry ---------------------------------------------------------------------------


def test_knowledge_entries_are_exact_and_refuse_anything_else():
    entry = approval.knowledge_entry("accept", TARGET.upper(), subject_id=PROPOSAL.upper(), text_sha256="f" * 64)
    assert entry == {"decision": "accept", "target_id": TARGET, "subject_id": PROPOSAL, "text_sha256": "f" * 64,
                     "expected_revision": None, "reason": None, "note": None}
    document = approval.set_document("knowledge_decision", "carol", ORIGIN + "/", {"knowledge": entry})
    assert approval.set_digest(document) == contract_digest("carol", entry)
    bad = [
        ("accept", {"text_sha256": "f" * 64}),
        ("accept", {"subject_id": PROPOSAL}),
        ("accept", {"subject_id": PROPOSAL, "text_sha256": "F" * 64}),
        ("accept", {"subject_id": PROPOSAL, "text_sha256": "f" * 64, "expected_revision": 1}),
        ("accept", {"subject_id": PROPOSAL, "text_sha256": "f" * 64, "note": "n" * 2001}),
        ("confirm", {"text_sha256": "f" * 64}),
        ("confirm", {"text_sha256": "f" * 64, "expected_revision": True}),
        ("confirm", {"text_sha256": "f" * 64, "expected_revision": 1, "note": "x"}),
        ("confirm", {"text_sha256": "f" * 64, "expected_revision": 1, "subject_id": PROPOSAL}),
        ("allow_changes", {"expected_revision": -1}),
        ("allow_changes", {"expected_revision": 1, "text_sha256": "f" * 64}),
        ("delete", {}),
    ]
    for decision, values in bad:
        with pytest.raises(approval.ApprovalError):
            approval.knowledge_entry(decision, TARGET, **values)
    with pytest.raises(approval.ApprovalError):
        approval.knowledge_entry("allow_changes", "../x", expected_revision=1)


def test_a_note_or_a_gateway_message_cannot_carry_terminal_controls():
    for note in ("ok\u202eevil", "ok\x1b[2K", "a\u200bb"):
        with pytest.raises(approval.ApprovalError):
            approval.knowledge_entry("accept", TARGET, subject_id=PROPOSAL, text_sha256="f" * 64, note=note)
    assert approval.knowledge_entry("accept", TARGET, subject_id=PROPOSAL, text_sha256="f" * 64,
                                    note="line one\nline two")["note"] == "line one\nline two"
    shown = approval._detail_text({"message": "refused\x1b]0;x\x07 \u202eok"})
    assert "\x1b" not in shown and "\x07" not in shown and "\u202e" not in shown


FINDING = "44444444-4444-4444-8444-444444444444"


def test_finding_and_interpretation_decisions_are_exact_entries():
    dismiss = approval.knowledge_entry("dismiss", TARGET, subject_id=FINDING, reason="false_positive",
                                       note="lab host")
    assert dismiss == {"decision": "dismiss", "target_id": TARGET, "subject_id": FINDING, "text_sha256": None,
                       "expected_revision": None, "reason": "false_positive", "note": "lab host"}
    document = approval.set_document("knowledge_decision", "olga", ORIGIN, {"knowledge": dismiss})
    assert approval.set_digest(document) == contract_digest("olga", dismiss)
    for decision in ("reopen", "retract", "retract_hunt"):
        assert approval.knowledge_entry(decision, TARGET, subject_id=FINDING, note="why")["note"] == "why"
    bad = [
        ("dismiss", {"subject_id": FINDING, "note": "x"}),
        ("dismiss", {"subject_id": FINDING, "reason": "boring", "note": "x"}),
        ("dismiss", {"subject_id": FINDING, "reason": "duplicate"}),
        ("reopen", {"subject_id": FINDING, "note": "x", "reason": "duplicate"}),
        ("reopen", {"note": "x"}),
        ("retract", {"subject_id": FINDING, "note": " "}),
        ("retract_hunt", {"subject_id": "not-a-uuid", "note": "x"}),
        ("retract", {"subject_id": FINDING, "note": "x", "text_sha256": "f" * 64}),
        ("reopen", {"subject_id": FINDING, "note": "x", "expected_revision": 1}),
    ]
    for decision, values in bad:
        with pytest.raises(approval.ApprovalError):
            approval.knowledge_entry(decision, TARGET, **values)
    assert "dismiss finding 44444444" in approval._knowledge_summary(dismiss)


def test_the_server_not_the_token_says_whether_a_step_up_is_needed(monkeypatch):
    # A token, but the server says it is an open-source engine: no step-up, the plain request.
    local = FakeGateway(enterprise=False)
    monkeypatch.setattr(FakeGateway, "__call__", _oss_put(FakeGateway.__call__))
    assert _run(local, Terminal("y"), "allow-changes", TARGET, monkeypatch=monkeypatch) == 0
    assert local.begins() == [] and [c for c in local.seen if c[0] == "PUT"]
    # No token, but the server is an Enterprise gateway: the step-up is still asked for.
    gateway = FakeGateway()
    assert _run(gateway, Terminal("y"), "allow-changes", TARGET, monkeypatch=monkeypatch, enterprise=False) == 0
    assert gateway.begins() and not [c for c in gateway.seen if c[0] == "PUT"]


def test_a_server_that_cannot_say_what_it_is_decides_nothing(monkeypatch, capsys):
    gateway = FakeGateway()
    original = FakeGateway.__call__

    def broken(self, method, path, payload=None, headers=None, *, timeout=None):
        if path == "/_enterprise/healthz":
            return 503, {"detail": "starting"}
        return original(self, method, path, payload, headers, timeout=timeout)

    monkeypatch.setattr(FakeGateway, "__call__", broken)
    assert _run(gateway, Terminal("y"), "allow-changes", TARGET, monkeypatch=monkeypatch) == 2
    assert "cannot tell what kind of instance" in capsys.readouterr().err
    assert not [c for c in gateway.seen if c[0] != "GET"]


def test_an_unanswered_decision_is_reported_as_unknown_not_as_refused(monkeypatch):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64))
    original = FakeGateway.__call__

    def silent_finish(self, method, path, payload=None, headers=None, *, timeout=None):
        if path == approval.FINISH_PATH:
            self.seen.append((method, path, payload))
            raise approval.ApprovalError("no answer within 60 s")
        return original(self, method, path, payload, headers, timeout=timeout)

    monkeypatch.setattr(FakeGateway, "__call__", silent_finish)
    terminal = Terminal("y")
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 1
    text = terminal.stdout.getvalue()
    assert "outcome unknown" in text and "check with `shakerscan knowledge review`" in text
    assert "not applied" not in text


def test_a_gateway_reported_unknown_outcome_is_said_as_such(monkeypatch):
    gateway = FakeGateway(_proposal(methodology_sha256="f" * 64))
    original = FakeGateway._approval

    def unknown(self, path, payload):
        status, body = original(self, path, payload)
        if path.endswith("/finish") and status == 200:
            body["knowledge"] = {"decision": "accept", "target_id": TARGET, "http_status": 502,
                                 "outcome": "unknown", "error": {"message": "the engine did not answer"}}
        return status, body

    monkeypatch.setattr(FakeGateway, "_approval", unknown)
    terminal = Terminal("y")
    assert _run(gateway, terminal, "review", monkeypatch=monkeypatch) == 1
    assert "outcome unknown: the engine did not answer" in terminal.stdout.getvalue()


def test_the_decision_helper_is_ready_for_dismissal(monkeypatch):
    """After the interpretations work merges, `knowledge dismiss` calls this with its entry."""
    sent = []

    def send(method, path, payload=None, headers=None, *, timeout=None):
        sent.append((method, path, payload))
        return 200, {"finding": {"status": "false_positive"}}

    entry = approval.knowledge_entry("dismiss", TARGET, subject_id=FINDING, reason="false_positive", note="lab")
    path = f"/targets/{TARGET}/findings/{FINDING}/dismiss"
    assert v2_cli.apply_knowledge_decision(send, None, entry, "POST", path,
                                           {"reason": "false_positive", "note": "lab"})[0] == 200
    assert sent == [("POST", path, {"reason": "false_positive", "note": "lab"})]
