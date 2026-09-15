"""Insert budgeted health samples into the existing immutable Scan action graph."""
from dataclasses import replace
import re
from uuid import UUID


def with_authentication_health(blueprints, credentials, registry):
    from .action_plan import ScanActionPlanError

    selected = [ref for ref in credentials if "authentication_profile_ref" in ref]
    if not selected:
        return blueprints
    if len(selected) != len(credentials):
        raise ScanActionPlanError("every Scan identity requires a reviewed profile snapshot")
    health_refs = []
    for ref in selected:
        value = ref["authentication_profile_ref"]
        try:
            valid = (set(value) == {"profile_id", "revision", "configuration_digest"} and
                str(UUID(value["profile_id"])) == ref["profile_id"] and
                type(value["revision"]) is int and value["revision"] > 0 and
                re.fullmatch(r"[a-f0-9]{64}", value["configuration_digest"]) and
                ref["lane"] in {"primary", "secondary"})
        except (ValueError, TypeError, KeyError, AttributeError):
            valid = False
        if not valid:
            raise ScanActionPlanError("authentication health reference is invalid")
        health_refs.append((ref["lane"], value))
    if len({lane for lane, _ in health_refs}) != len(health_refs):
        raise ScanActionPlanError("authentication health principal lanes must be distinct")
    if "primary" not in {lane for lane, _ in health_refs}:
        raise ScanActionPlanError("authenticated profile Scan requires a primary identity")
    result, previous = [], ()
    for row in blueprints:
        spec = registry.require(row.capability_name)
        if spec.credential_transport == "not_used":
            if row.capability_name == "scan.finalize":
                row = replace(row, dependencies=tuple(item.action_id for item in result))
            result.append(row)
            continue
        if spec.credential_transport != "exact_origin" or spec.credential_interruption != "cooperative":
            raise ScanActionPlanError(f"authenticated profile consumer is unsupported: {row.capability_name}")
        before, after = [], []
        for lane, ref in health_refs:
            for position, dependencies, output in (
                ("before", tuple(dict.fromkeys((*row.dependencies, *previous))), before),
                ("after", (row.action_id,), after),
            ):
                output.append(replace(row, action_id=f"health.{position}.{lane}.{row.action_id}",
                    capability_name="http.request", capability_args={"authentication_profile_ref": ref},
                    dependencies=dependencies, required=True, supporting=True))
        result.extend(before)
        result.append(replace(row, dependencies=tuple(dict.fromkeys((*row.dependencies, *(item.action_id for item in before))))))
        result.extend(after)
        previous = tuple(item.action_id for item in after)
    return result
