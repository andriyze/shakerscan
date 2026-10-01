"""One canonical target must not change executor-specific persistence semantics."""
import ast
from pathlib import Path
import uuid

from api.targets.asset_execution import execution_target_refs


def test_device_with_canonical_target_retains_device_finding_writer():
    target = uuid.uuid4()
    refs = execution_target_refs({'target_id':target,'device_target_id':target,'ai_target_id':None})
    assert refs.canonical_target_id == str(target)
    assert refs.device_target_id == str(target)
    assert refs.web_target_id is None
    assert refs.ai_target_id is None


def test_application_service_keeps_exact_service_identity_not_root():
    service = uuid.uuid4()
    refs = execution_target_refs({'target_id':service,'device_target_id':None,'ai_target_id':None})
    assert refs.canonical_target_id == str(service)
    assert refs.web_target_id == str(service)
    assert refs.device_target_id is None


def test_legacy_device_and_model_rows_keep_their_executor():
    device, model = uuid.uuid4(), uuid.uuid4()
    legacy = execution_target_refs({'target_id':None,'device_target_id':device})
    assert legacy.canonical_target_id == str(device) and legacy.web_target_id is None
    ai = execution_target_refs({'target_id':uuid.uuid4(),'ai_target_id':model})
    assert ai.ai_target_id == str(model) and ai.web_target_id is None


def test_worker_uses_dispatch_projection_but_receipt_keeps_canonical_id():
    source=(Path(__file__).resolve().parents[1]/'api/worker.py').read_text()
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='process_scan_job')
    body=ast.get_source_segment(source,node)
    assert 'references = execution_target_refs(row)' in body
    assert 'target_id = references.web_target_id' in body
    assert 'canonical_target_id = references.canonical_target_id' in body
    assert 'target_id=canonical_target_id' in body
    assert 'elif device_target_id' in body
