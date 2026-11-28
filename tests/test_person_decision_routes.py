"""`shakerscan api` never sends a person's decision from inside an agent: it names the person's command.

An AI agent asks, a person decides, and the agent reads the outcome. The routes are listed once,
in scripts/person_decision_routes.py; these tests read that list.

The test runner has no terminal. Where a test is about a person at their own terminal, the
labelled double ``at_terminal`` stands for it (api_cli.person_terminal answers True); the tests of
the terminal check itself pass the streams or the answer explicitly.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, "scripts")
import api_cli  # noqa: E402
import person_decision_routes as routes  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
API = "https://scanner.example.com"
ID = "11111111-2222-4333-8444-555555555555"


class Recorder:
    """An opener that records every request and answers 200 (or a gateway refusal)."""

    def __init__(self):
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return _Response(b'{"ok": true}')


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def sent(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(api_cli, "_opener", lambda: recorder)
    monkeypatch.setattr(api_cli, "bearer_token", lambda: None)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    monkeypatch.delenv(api_cli.PERSON_SCRIPT_ENV, raising=False)
    at_terminal(monkeypatch)
    return recorder.requests


def at_terminal(monkeypatch, answer=True):
    """Labelled double: a person's terminal (or, with False, a shell tool, a pipe or a script)."""
    monkeypatch.setattr(api_cli, "person_terminal", lambda stdin=None, stdout=None: answer)


def as_agent(monkeypatch, name="pi"):
    monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", name)


# The engine's 38 person-only decision routes, by method and route. A change that drops one from
# the list fails here.
PERSON_ONLY = {
    ("POST", "/arsenal/approvals"), ("POST", "/arsenal/approvals/{approval_receipt_id}/revoke"),
    ("DELETE", "/targets/{target_id}/authorization"), ("POST", "/targets/{target_id}/authorization"),
    ("PUT", "/targets/{target_id}/hunt-authority"), ("POST", "/data-deletion/execute"),
    ("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/grants"),
    ("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/promote"),
    ("POST", "/targets/{target_id}/discovered-secrets/{secret_id}/reveal"),
    ("POST", "/evidence/retention/sweep"), ("POST", "/finding-exceptions"),
    ("PATCH", "/finding-exceptions/{exception_id}"), ("POST", "/fleet/join-tokens"),
    ("POST", "/fleet/nodes/{node_id}/revoke"),
    ("POST", "/hunts/{hunt_id}/authorization-investigations/{proposal_id}/approve"),
    ("POST", "/hunts/{hunt_id}/shell-plans/{plan_id}/confirm"), ("POST", "/hunts/{hunt_id}/budget-amendments"),
    ("POST", "/hunts/{hunt_id}/permission-grants/{grant_id}/revoke"),
    ("POST", "/hunts/{hunt_id}/permission-requests/{request_id}/decision"),
    ("POST", "/model-intake/submissions/{submission_id}/approvals"),
    ("POST", "/model-intake/submissions/{submission_id}/promote"), ("POST", "/model-intake/trust-anchors"),
    ("POST", "/targets/{target_id}/invariants/{contract_id}/approve"), ("PUT", "/settings/ai"),
    ("PUT", "/settings/automation"), ("PUT", "/settings/scan-execution"),
    ("POST", "/targets/{target_id}/instruction-proposals/{proposal_id}/accept"),
    ("POST", "/targets/{target_id}/instruction-proposals/{proposal_id}/reject"),
    ("POST", "/targets/{target_id}/findings/{finding_id}/dismiss"),
    # Changing or withdrawing what a person decided is the person's too.
    ("PATCH", "/model-intake/trust-anchors/{anchor_id}"), ("DELETE", "/model-intake/trust-anchors/{anchor_id}"),
    ("POST", "/model-intake/admissions/{admission_id}/revoke"),
    ("DELETE", "/finding-exceptions/{exception_id}"),
    ("DELETE", "/credential-profiles/{profile_id}/grants/{target_id}"),
    ("DELETE", "/targets/{target_id}/discovered-secrets/{secret_id}/grants/{grant_target_id}"),
    ("DELETE", "/fleet/join-tokens/{token_id}"),
    ("POST", "/credential-profiles/{profile_id}/grants"), ("POST", "/targets/{target_id}/skill/confirm"),
}

# Body-dependent ones besides: a finding's dismissal by status, a target registered with its
# authorization, a device probe confirmed as authorized.
BODY_DEPENDENT = {("PATCH", "/findings/{finding_id}"), ("POST", "/findings/bulk"), ("POST", "/targets"),
                  ("POST", "/targets/hosts"), ("POST", "/devices/{device_id}/verify-service")}

# Writes the engine serves on a decision's own resource that are NOT a person's decision, each
# with the reason. A new verb on such a resource fails test_every_verb_on_a_decision_resource_is_
# classified until it is listed in ROUTES or named here.
NOT_A_DECISION = {
    ("POST", "/settings/ai/test"): "tests the saved AI connection; changes no setting",
    ("POST", "/finding-exceptions/lifecycle/sweep"):
        "expires exceptions whose own end date has passed; accepts, renews and deletes nothing",
    ("DELETE", "/findings/{finding_id}"):
        "not classified by this guard: the engine's own rule decides which findings a caller may delete "
        "(a Hunt's own unverified ones); dismissal by status or verdict is the listed decision",
    # Reviewed and left to the agent, though they sit beside a decision:
    ("POST", "/model-intake/submissions/{submission_id}/policy-decisions"):
        "the engine evaluates its embedded policy over the reviewers' recorded approvals; the caller decides nothing",
    ("POST", "/hunts/{hunt_id}/authorization-investigations/{proposal_id}/skip"):
        "records a deferral that sends nothing, grants nothing and can be reconsidered",
}


def _served() -> set[tuple[str, str]]:
    manifest = json.loads((ROOT / "docs" / "generated" / "public-openapi-manifest.json").read_text(encoding="utf-8"))
    return {tuple(key.split(" ", 1)) for key in manifest["operations"]}


def test_every_person_only_decision_is_listed():
    listed = {(entry.method, entry.template) for entry in routes.ROUTES}
    assert len(PERSON_ONLY) == 38
    assert PERSON_ONLY <= listed
    assert BODY_DEPENDENT <= listed
    assert listed == PERSON_ONLY | BODY_DEPENDENT, "a new entry is named here as well"
    assert not set(NOT_A_DECISION) & listed
    assert set(NOT_A_DECISION) <= _served(), "a route the engine no longer serves is taken off this list"


def test_every_verb_on_a_decision_resource_is_classified():
    """Every write the engine serves on a listed route's path, or beneath the path of a route that
    is always a decision (``…/grants`` and ``…/grants/{target_id}``), is listed or named above with
    its reason. PATCH and DELETE of a trust anchor were served beside the listed POST and missed."""
    listed = {(entry.method, entry.template) for entry in routes.ROUTES}
    paths = {entry.template for entry in routes.ROUTES}
    resources = {entry.template for entry in routes.ROUTES if entry.when is routes._always}
    unclassified = sorted(
        (method, path) for method, path in _served()
        if method not in {"GET", "HEAD", "OPTIONS"} and (method, path) not in listed
        and (method, path) not in NOT_A_DECISION
        and (path in paths or any(path.startswith(resource + "/") for resource in resources)))
    assert unclassified == [], f"classify these in ROUTES or NOT_A_DECISION: {unclassified}"


def test_the_classification_reads_every_method_the_engine_serves(monkeypatch):
    # The check has teeth: with one listed verb taken away, the route it leaves is reported.
    kept = tuple(entry for entry in routes.ROUTES
                 if (entry.method, entry.template) != ("PATCH", "/model-intake/trust-anchors/{anchor_id}"))
    monkeypatch.setattr(routes, "ROUTES", kept)
    with pytest.raises(AssertionError, match="PATCH.*trust-anchors"):
        test_every_verb_on_a_decision_resource_is_classified()


def test_every_listed_route_is_an_engine_route():
    served = (ROOT / "docs" / "generated" / "public-openapi-manifest.json").read_text(encoding="utf-8")
    for entry in routes.ROUTES:
        assert f'"{entry.method} {entry.template}"' in served, (entry.method, entry.template)


def _example(entry):
    """A request of this route that is the person's decision."""
    path = entry.template
    for name in entry.pattern.groupindex:
        path = path.replace("{" + name + "}", ID)
    body = {
        ("PATCH", "/findings/{finding_id}"): {"status": "accepted_risk"},
        ("POST", "/findings/bulk"): {"finding_ids": [ID], "status": "false_positive"},
        ("POST", "/targets"): {"url": "https://app.example.com", "authorized_by": "agent"},
        ("POST", "/targets/hosts"): {"locator": "10.0.0.5", "approved_by": "agent"},
        ("POST", "/devices/{device_id}/verify-service"): {"port": 22, "confirm_authorized": True},
    }.get((entry.method, entry.template), {})
    return entry.method, path, json.dumps(body)


@pytest.mark.parametrize("entry", routes.ROUTES, ids=lambda entry: f"{entry.method} {entry.template}")
def test_an_agent_is_refused_every_listed_decision_and_nothing_is_sent(entry, sent, monkeypatch, capsys):
    as_agent(monkeypatch)
    method, path, body = _example(entry)
    assert api_cli.main(["--api-url", API, method, path, body]) == 3
    assert sent == []
    err = capsys.readouterr().err
    assert err.startswith("shakerscan api: person decision required: " + entry.summary)
    assert "Nothing was sent" in err and "The person's command: shakerscan " in err


# The decisions an agent most often reaches for, through `shakerscan api` exactly as an agent types
# them. Before the guard each of these was sent.
NAMED = [
    ("POST", f"/hunts/{ID}/permission-requests/{ID}/decision",
     {"decision": "allow", "subject_digest": "0" * 64, "idempotency_key": "decide-0001"}, f"shakerscan approve --url {API} {ID}"),
    ("POST", f"/hunts/{ID}/permission-requests/{ID}/decision",
     {"decision": "deny", "subject_digest": "0" * 64, "idempotency_key": "decide-0001"}, f"shakerscan deny --url {API} {ID}"),
    ("POST", f"/targets/{ID}/authorization", {"approved_by": "me", "risk_tier": "active"},
     f"shakerscan targets --url {API} authorize {ID}"),
    ("PATCH", f"/findings/{ID}", {"status": "accepted_risk"}, f"shakerscan api --url {API} PATCH /findings/{ID}"),
    ("PATCH", f"/findings/{ID}", {"status": "false_positive"}, f"shakerscan api --url {API} PATCH /findings/{ID}"),
    ("PATCH", f"/findings/{ID}", {"analyst_verdict": "accepted_risk"}, f"shakerscan api --url {API} PATCH"),
    ("POST", f"/targets/{ID}/findings/{ID}/dismiss", {"reason": "accepted_risk", "note": "known; tracked"},
     f"shakerscan knowledge --url {API} dismiss {ID} {ID} --reason accepted_risk --note 'known; tracked'"),
    ("POST", "/arsenal/approvals", {"risk_tier": "dangerous", "approved_by": "the user"},
     f"shakerscan api --url {API} POST /arsenal/approvals"),
    ("POST", f"/targets/{ID}/discovered-secrets/{ID}/reveal", {}, f"shakerscan secrets --url {API} reveal {ID} {ID}"),
    ("POST", f"/targets/{ID}/invariants/{ID}/approve",
     {"approval_receipt_id": ID, "approved_by": "me", "confirm_authoritative": True},
     f"shakerscan api --url {API} POST /targets/{ID}/invariants/{ID}/approve"),
]


@pytest.mark.parametrize("method,path,body,command", NAMED)
def test_an_agent_gets_the_persons_command_for_each_named_decision(method, path, body, command, sent,
                                                                    monkeypatch, capsys):
    as_agent(monkeypatch, "opencode")
    assert api_cli.main(["--api-url", API, method, path, json.dumps(body)]) == 3
    assert sent == []
    assert command in capsys.readouterr().err


@pytest.mark.parametrize("method,path,body,command", NAMED[:3])
def test_the_person_in_their_own_terminal_sends_it(method, path, body, command, sent, capsys):
    assert api_cli.main(["--api-url", API, method, path, json.dumps(body)]) == 0
    assert len(sent) == 1 and sent[0].get_method() == method


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/findings?status=accepted_risk", None),
    ("PATCH", f"/findings/{ID}", {"status": "resolved"}),
    ("PATCH", f"/findings/{ID}", {"notes": "triaged", "analyst_verdict": "true_positive"}),
    ("POST", "/findings/bulk", {"finding_ids": [ID], "status": "active"}),
    ("POST", "/targets", {"url": "https://app.example.com"}),
    ("POST", "/targets/hosts", {"locator": "10.0.0.5", "approved_by": None}),
    ("POST", f"/devices/{ID}/verify-service", {"port": 22, "confirm_authorized": False}),
    ("GET", f"/targets/{ID}/authorization", None),
    ("POST", "/data-deletion/preview", {"kind": "target", "target_id": ID}),
])
def test_an_agent_still_reads_and_does_its_own_work(method, path, body, sent, monkeypatch):
    as_agent(monkeypatch)
    argv = ["--api-url", API, method, path] + ([json.dumps(body)] if body is not None else [])
    assert api_cli.main(argv) == 0
    assert len(sent) == 1


@pytest.mark.parametrize("path,body", [
    (f"//targets//{ID}/authorization/", "{}"),
    (f"targets/{ID}/authorization", "{}"),
    (f"/targets/{ID}%2Fauthorization", "{}"),
    (f"/targets/{ID}/authorization?x=1", "{}"),
    (f"/findings/{ID}", '{"status": "resolved", "status": "accepted_risk"}'),
    (f"/findings/{ID}", '["accepted_risk"]'),
])
def test_other_spellings_of_a_decision_are_refused_too(path, body, sent, monkeypatch):
    as_agent(monkeypatch)
    method = "PATCH" if path.startswith("/findings") else "POST"
    assert api_cli.main(["--api-url", API, method, path, body]) == 3
    assert sent == []


def test_a_streamed_decision_is_refused_before_anything_is_opened(sent, monkeypatch, capsys):
    as_agent(monkeypatch)
    assert api_cli.main(["--api-url", API, "--stream", "POST", f"/targets/{ID}/authorization", "{}"]) == 3
    assert sent == []


def test_an_agents_values_never_become_options_of_the_persons_command():
    method, path = "POST", f"/targets/{ID}/findings/{ID}/dismiss"
    hostile = json.dumps({"reason": "accepted_risk", "note": "--url=https://elsewhere.example"})
    line = routes.refusal(method, path, hostile, api_url=API)
    assert "knowledge" not in line and "shakerscan api --url https://scanner.example.com POST" in line
    grant = json.dumps({"target_id": "--url=https://elsewhere.example"})
    line = routes.refusal("POST", f"/targets/{ID}/discovered-secrets/{ID}/grants", grant, api_url=API)
    command = line.split("The person's command: ", 1)[1]
    assert command.startswith(f"shakerscan api --url {API} POST /targets/{ID}/discovered-secrets/{ID}/grants ")


def test_the_refusal_needs_the_agent_signal_or_the_lack_of_a_terminal():
    # Was: refused only with SHAKERSCAN_AGENT_NAME, so an agent started without the launcher sent
    # the decision from its shell tool. A person's decision now also needs a person's terminal.
    request = api_cli.build_request("POST", "/arsenal/approvals", "{}", api_url=API, token=None)

    def refused(environ, terminal):
        return api_cli.agent_refusal(request, "/arsenal/approvals", API, environ=environ, terminal=terminal)

    assert refused({}, True) is None
    assert refused({"SHAKERSCAN_AGENT_NAME": " "}, True) is None
    assert refused({"SHAKERSCAN_AGENT_NAME": "pi"}, True).startswith("person decision required")
    bare = refused({}, False)
    assert bare.startswith("person decision required") and "not a person's terminal" in bare
    assert "Nothing was sent" in bare and "The person's command: shakerscan api " in bare
    assert api_cli.PERSON_SCRIPT_ENV not in bare, "the line names where the opt-out is described, not the switch"
    # A person's own script says so; inside a launched agent that changes nothing.
    assert refused({api_cli.PERSON_SCRIPT_ENV: "1"}, False) is None
    assert refused({api_cli.PERSON_SCRIPT_ENV: "0"}, False) is not None
    assert refused({api_cli.PERSON_SCRIPT_ENV: "1", "SHAKERSCAN_AGENT_NAME": "pi"}, False) is not None
    assert refused({api_cli.PERSON_SCRIPT_ENV: "1", "SHAKERSCAN_AGENT_NAME": "pi"}, True) is not None


class _Stream:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


def test_a_persons_terminal_is_stdin_and_stdout_both():
    assert api_cli.person_terminal(_Stream(True), _Stream(True)) is True
    assert api_cli.person_terminal(_Stream(False), _Stream(True)) is False   # piped in
    assert api_cli.person_terminal(_Stream(True), _Stream(False)) is False   # piped out, a shell tool
    assert api_cli.person_terminal(object(), _Stream(True)) is False
    assert api_cli.person_terminal() is False, "the test runner itself has no terminal"


@pytest.mark.parametrize("entry", routes.ROUTES, ids=lambda entry: f"{entry.method} {entry.template}")
def test_without_a_terminal_every_listed_decision_is_refused_though_no_agent_is_named(entry, sent, monkeypatch, capsys):
    """An agent started bare after `shakerscan mcp install` runs `shakerscan api` from its shell tool."""
    at_terminal(monkeypatch, False)
    method, path, body = _example(entry)
    assert api_cli.main(["--api-url", API, method, path, body]) == 3
    assert sent == []
    err = capsys.readouterr().err
    assert err.startswith("shakerscan api: person decision required: " + entry.summary)
    assert "not a person's terminal" in err and "The person's command: shakerscan " in err


def test_without_a_terminal_the_real_streams_refuse_and_a_persons_script_sends(monkeypatch, capsys):
    # No double: pytest's own stdin and stdout are not terminals.
    recorder = Recorder()
    monkeypatch.setattr(api_cli, "_opener", lambda: recorder)
    monkeypatch.setattr(api_cli, "bearer_token", lambda: None)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    monkeypatch.delenv(api_cli.PERSON_SCRIPT_ENV, raising=False)
    decision = ["--api-url", API, "POST", f"/targets/{ID}/authorization", '{"approved_by": "x"}']
    assert api_cli.main(decision) == 3 and recorder.requests == []
    assert api_cli.main(["--api-url", API, "--stream", *decision[2:]]) == 3 and recorder.requests == []
    # Reads and an agent's own work need no terminal.
    assert api_cli.main(["--api-url", API, "GET", f"/targets/{ID}/authorization"]) == 0
    assert api_cli.main(["--api-url", API, "PATCH", f"/findings/{ID}", '{"status": "resolved"}']) == 0
    assert len(recorder.requests) == 2
    monkeypatch.setenv(api_cli.PERSON_SCRIPT_ENV, "1")
    assert api_cli.main(decision) == 0 and len(recorder.requests) == 3
    monkeypatch.setenv("SHAKERSCAN_AGENT_NAME", "codex")
    assert api_cli.main(decision) == 3 and len(recorder.requests) == 3


def test_an_http_error_path_is_unchanged_for_the_person(monkeypatch, capsys):
    class Refusing:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 409, "conflict", {}, io.BytesIO(b'{"detail": "stale"}'))

    monkeypatch.setattr(api_cli, "_opener", lambda: Refusing())
    monkeypatch.setattr(api_cli, "bearer_token", lambda: None)
    monkeypatch.delenv("SHAKERSCAN_AGENT_NAME", raising=False)
    at_terminal(monkeypatch)
    assert api_cli.main(["--api-url", API, "POST", "/arsenal/approvals", "{}"]) == 1
    assert "HTTP 409: stale" in capsys.readouterr().err
