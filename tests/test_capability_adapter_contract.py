"""Every scan capability adapter must satisfy the executor's identity contract.

``CapabilityExecutor.execute`` reads ``capability_name``, ``adapter_name`` and
``adapter_version`` off the adapter and compares them to the registry before it
runs anything. An adapter missing them raises ``AttributeError``, which the
orchestrator settles as a bare ``adapter_failed`` carrying no durable detail --
so the capability reports a failed action rather than an obviously broken one.

Two shipped adapters were dead this way: ``nosqli.verify_batch`` never ran a
single attempt, and ``sqli.prove_batch`` -- the escalation that promotes a
suspected SQL injection to verified -- never ran either.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from api.capabilities.nosqli_verify import NoSQLiVerifyAdapter
from api.capabilities.sqli_proof import SQLiProofAdapter
from api.runtime.capability_registry import CAPABILITY_REGISTRY


_CONTRACT = ("capability_name", "adapter_name", "adapter_version")
_CAPABILITIES = pathlib.Path("api/capabilities")


@pytest.mark.parametrize(
    "adapter", (NoSQLiVerifyAdapter, SQLiProofAdapter),
    ids=lambda item: item.__name__,
)
def test_adapter_identity_matches_its_registry_entry(adapter):
    for attribute in _CONTRACT:
        assert isinstance(getattr(adapter, attribute, None), str), (
            f"{adapter.__name__} does not declare {attribute}; "
            "CapabilityExecutor raises AttributeError before executing it"
        )
    specification = CAPABILITY_REGISTRY.require(adapter.capability_name)
    assert adapter.adapter_name == specification.adapter
    assert adapter.adapter_version == specification.adapter_version


def _declares(node: ast.ClassDef) -> set[str]:
    """Names assigned at class level or on ``self`` anywhere in the class."""
    found: set[str] = set()
    for child in ast.walk(node):
        targets = (
            child.targets if isinstance(child, ast.Assign)
            else [child.target] if isinstance(child, ast.AnnAssign) else []
        )
        for target in targets:
            if isinstance(target, ast.Name):
                found.add(target.id)
            elif (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                found.add(target.attr)
    return found


def test_every_capability_adapter_declares_the_executor_contract():
    """Source-level sweep, so a new adapter cannot ship without its identity.

    Adapters that inherit from a base declaring the contract are covered by it;
    this only requires that each class either declares the names itself or
    derives from something in the same module that does.
    """
    failures: list[str] = []
    for path in sorted(_CAPABILITIES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        classes = {
            node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
        }
        for name, node in classes.items():
            if not name.endswith("Adapter"):
                continue
            declared: set[str] = set()
            pending, seen = [node], set()
            while pending:
                current = pending.pop()
                if current.name in seen:
                    continue
                seen.add(current.name)
                declared |= _declares(current)
                pending.extend(
                    classes[base.id] for base in current.bases
                    if isinstance(base, ast.Name) and base.id in classes
                )
            missing = [item for item in _CONTRACT if item not in declared]
            if missing:
                failures.append(f"{path.name}:{name} missing {missing}")
    assert not failures, "\n".join(failures)


def test_every_batch_checkpoint_carries_a_terminal_status():
    """``checkpoint_batch_attempt`` rejects an attempt with no status.

    The authz-surface batch built its checkpoint without one, so every
    checkpoint was refused as invalid and the family could not complete a
    single batch -- every action it planned failed with adapter_failed and it
    proved nothing, ever.
    """
    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "api" / "scan" / "action_adapter.py"
    ).read_text(encoding="utf-8")

    for index, marker in enumerate(re.finditer(
        r"await checkpoint_attempt\(action\.action_id, (\w+)\)", source,
    )):
        name = marker.group(1)
        # Walk back to where this payload was built and require a status key.
        built = source.rfind(f"{name} = {{", 0, marker.start())
        assert built != -1, f"checkpoint payload {name} not found"
        payload = source[built:marker.start()]
        assert '"status"' in payload, (
            f"checkpoint payload #{index} ({name}) has no status; "
            "the durable contract rejects it"
        )
