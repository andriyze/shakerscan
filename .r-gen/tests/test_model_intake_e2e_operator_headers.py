from tests.e2e import harness as H

def test_operator_headers_propagate_explicit_origin(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN", "x" * 40)
    monkeypatch.setenv("SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_ORIGIN", "http://127.0.0.1:39001")
    assert H.model_intake_operator_headers() == {"Authorization": "Bearer " + "x" * 40, "Origin": "http://127.0.0.1:39001"}

def test_operator_headers_do_not_invent_origin(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN", "y" * 40)
    monkeypatch.delenv("SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_ORIGIN", raising=False)
    assert H.model_intake_operator_headers() == {"Authorization": "Bearer " + "y" * 40}
