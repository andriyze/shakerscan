"""A rejected verification must not poison a candidate for the life of the Hunt.

`candidate.verify` ran under a fixed idempotency key, so its result replayed forever. That is right
for a verification the moat actually executed -- re-running one costs target traffic and can promote
a finding -- but the server also caches rejections it raised *before dispatch*
(`invalid_workflow`: a missing principal context, an unapproved invariant contract, an unresolved
route). Those never ran a proof. Once the operator fixed the cause the error named, the same
candidate could never be verified again in that Hunt. The route now accepts an explicit attempt so
a fresh execution can be requested deliberately, while a repeat of the same attempt still replays.

The router pulls in the flat runtime layout of the container image and is not host-importable, so
these pin the contract from source the way the other Hunt contract tests do. The helpers resolve a
definition by name anywhere under api/, so the assertions survive a later router extraction.
"""

from tests.api_sources import definition_source, route_is_declared


def _model_source() -> str:
    return definition_source("HuntCandidateVerifyRequest")


def test_verify_route_takes_an_optional_body():
    assert route_is_declared("POST", "/hunts/{hunt_id}/candidates/{candidate_id}/verify")
    # A default instance, not Optional: it keeps the body optional for callers that post nothing
    # while publishing the strict model as the request schema. An `X | None` annotation would emit
    # anyOf(..., null), which drops the `additionalProperties: false` the release contract requires
    # of every state-changing JSON write.
    source = definition_source("verify_hunt_candidate")
    assert "request: HuntCandidateVerifyRequest = HuntCandidateVerifyRequest()" in source
    assert "| None = None" not in source


def test_attempt_defaults_to_one_and_is_bounded():
    source = _model_source()
    assert "attempt: int = Field(default=1, ge=1, le=20)" in source
    # Verification is expensive and promotes findings, so the body admits nothing else -- a caller
    # must not be able to smuggle a different candidate id or workflow past the route's own lookup.
    assert 'model_config = ConfigDict(extra="forbid")' in source


def test_attempt_one_keeps_the_original_idempotency_key():
    # Backward compatibility: an existing stored action must still replay for the default attempt,
    # so the fix cannot silently re-execute a verification that already ran.
    source = definition_source("verify_hunt_candidate")
    assert '"" if attempt == 1 else f":retry-{attempt}"' in source
    assert 'f"candidate-verify:{candidate_uuid}{suffix}"' in source


def test_attempt_is_reported_back_so_a_caller_can_tell_the_executions_apart():
    assert '"attempt": attempt,' in definition_source("verify_hunt_candidate")


def test_the_retry_reason_is_recorded_where_the_next_reader_will_look():
    # The non-obvious part is *why* a fixed key was wrong. Keep that with the model, not only in
    # the commit message, so the next person does not "simplify" the attempt away.
    source = _model_source()
    assert "invalid_workflow" in source and "before dispatch" in source
