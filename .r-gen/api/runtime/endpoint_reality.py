"""Three-valued judgement of whether an observed response distinguishes a route. EXPERIMENTAL.

Status
------
This is an experimental component. It is NOT wired into the production reachability filter and has
NOT demonstrated any improvement over it. An earlier version of this docstring claimed it reduced
"real endpoints demoted 1 -> 0" and "client routes demoted 2 -> 0"; those numbers came from scoring
the low-level ``_soft404_matches`` matcher, not the shipping ``filter_reachable_worklist``, which
already keeps fragment routes and already drops only GET entries so a method-specific route
survives. Measured properly against the labeled sample, production made no errors for this module
to fix. The comparison was invalid and the claim is withdrawn.

What it may still be for
------------------------
Production learns its not-found control only at the first path segment. If controls are ever learned
deeper -- the current candidate experiment -- a real protected route and an absent one under the
same auth-gated namespace both answer with the same auth status, and a deeper control would start
demoting real routes. The ``auth_masks_existence`` abstention below exists for that case. Until
deeper controls are actually evaluated, this module earns nothing.

Read the outcomes as OBSERVATIONS, not proof of existence
---------------------------------------------------------
``REAL`` means only "this response is distinguishable from the control", and ``PHANTOM`` means only
"this response is indistinguishable from the control, or the server said 404". Neither establishes
that a route exists or does not: HTTP permits 404 for an existing forbidden resource, and an
unmatched response can still be an invalid sample of a perfectly real route template. A caller that
needs existence must not read these as existence.

Route templates versus request samples
--------------------------------------
Much of what looks like phantom endpoints is not separate endpoints at all. ``/api/Cards/search`` is
the real route ``/api/Cards/{id}`` carrying an invalid id. On the measured inventory 2,390 distinct
paths collapse to roughly 369 templates, so the dominant problem is GROUPING, not classification.
This module judges one observed request; it says nothing about which template that request belongs
to, and it should not be used as a de-noising strategy on its own.
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
