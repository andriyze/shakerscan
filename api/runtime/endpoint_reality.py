"""Three-valued judgement of whether an inventoried endpoint is a real route.

Why this is not a boolean
-------------------------
Discovery writes every probed path into the inventory the Hunt later reads, so wordlist guesses
sit beside real routes. The obvious fix -- classify each row real/phantom and drop the phantoms --
cannot be done soundly, and two measured results say so:

* An evidence-based ranking (attempts, verdicts, reachability) promoted a wordlist phantom to the
  top of the frontier, because a probed phantom acquires attempts and a verdict whenever the app
  answers it.
* The existing decoy comparison identified 2 of 7 phantoms on a labeled sample and wrongly demoted
  a real route. Its failure is structural: under an auth-gated prefix the app returned exactly
  ``401 / 83 bytes`` for both the real protected routes and the wordlist guesses.

When authentication middleware short-circuits before routing, "absent" and "protected" are the same
response, and no comparison of that response can separate them. HTTP also permits answering 404 for
an existing but forbidden resource. The correct output in those cases is **unknown**, and a
classifier that says "phantom" there is not conservative, it is wrong.

So this module returns one of ``real`` / ``phantom`` / ``unknown`` with the reason, and it abstains
whenever the control is missing or the observation cannot discriminate. Callers persist the
evidence and the outcome; they must not collapse ``unknown`` into either side. Ordering may demote
an uncertain endpoint, but nothing here licenses deleting it -- an uncertain lead the pentester can
still see is far cheaper than a real endpoint silently removed.

Every rule is derived from the observation itself, never from route names or per-application facts.
"""

from __future__ import annotations

from typing import Iterable, NamedTuple

# Statuses an auth layer returns before it has decided whether the route exists. When a prefix's
# learned not-found signature carries one of these, that prefix's responses cannot distinguish an
# absent route from a protected one.
AUTH_MASKING_STATUSES = frozenset({"401", "403"})

REAL = "real"
PHANTOM = "phantom"
UNKNOWN = "unknown"


class RealityVerdict(NamedTuple):
    """One judgement plus the reason, so a reader can audit why it was reached."""

    outcome: str
    reason: str

    @property
    def decided(self) -> bool:
        return self.outcome != UNKNOWN


def classify_endpoint_reality(
    *,
    probe_status: str,
    probe_size: int,
    signatures: Iterable[tuple[str, int]],
    probed_method: str = "GET",
    declared_method: str | None = None,
    path: str | None = None,
    size_tolerance: int = 256,
    size_tolerance_fraction: float = 0.08,
) -> RealityVerdict:
    """Judge one endpoint from its probe, the prefix's not-found control, and the methods.

    ``signatures`` are the learned not-found responses for the endpoint's path prefix -- the
    control. No control means no judgement.
    """
    status = str(probe_status or "").strip()
    controls = [(str(s), int(z)) for s, z in signatures or ()]

    # A fragment route is resolved in the browser: the server returns the same application shell
    # for every fragment, so it necessarily matches its prefix's not-found signature. Judging it
    # from an HTTP probe says nothing about whether the client route exists, and calling it a
    # phantom would discard exactly the DOM surface the browser lane needs.
    if path is not None and "#" in str(path):
        return RealityVerdict(UNKNOWN, "client_side_route")

    # An error or empty status observed nothing at all.
    if not status or status in {"ERR", "0"}:
        return RealityVerdict(UNKNOWN, "inconclusive_probe")

    # A GET probe reports on GET. A route declared for another verb may legitimately answer
    # 404/405/500 to GET while existing, so the probe does not describe it. This is exactly how a
    # real POST-only login route was demoted in measurement.
    declared = str(declared_method or probed_method).strip().upper()
    if declared and declared != str(probed_method or "GET").strip().upper():
        return RealityVerdict(UNKNOWN, "probed_method_differs")

    # "Missing or ambiguous controls must remain unknown."
    if not controls:
        return RealityVerdict(UNKNOWN, "no_control")

    # If the control itself is an auth response, the middleware answered before routing, so every
    # same-status response under this prefix is undecidable -- including the real protected routes.
    if status in AUTH_MASKING_STATUSES and any(c[0] in AUTH_MASKING_STATUSES for c in controls):
        return RealityVerdict(UNKNOWN, "auth_masks_existence")

    # A literal 404 is the server stating the route is absent. Recorded as phantom, but the reason
    # is kept explicit: HTTP permits 404 for an existing forbidden resource, so a consumer that
    # needs certainty should treat this as weaker than a positive observation.
    if status == "404":
        return RealityVerdict(PHANTOM, "literal_not_found")

    for control_status, control_size in controls:
        if status != control_status:
            continue
        if probe_size < 0 or control_size < 0:
            # Status matches and size is unmeasurable: the comparison decided nothing.
            return RealityVerdict(UNKNOWN, "control_size_unknown")
        tolerance = max(size_tolerance, int(control_size * size_tolerance_fraction))
        if abs(probe_size - control_size) <= tolerance:
            return RealityVerdict(PHANTOM, "matches_not_found_signature")

    return RealityVerdict(REAL, "distinct_from_not_found")
