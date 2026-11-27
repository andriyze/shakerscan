"""Static packaging guards supplement the Dockerfile's executed import checks."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_worker_and_slim_api_both_ship_deletion_package():
    scanner = (ROOT / 'scanner/Dockerfile').read_text()
    api = (ROOT / 'scanner/Dockerfile.api').read_text()
    assert 'COPY api/data_lifecycle /app/data_lifecycle' in scanner
    assert 'COPY --from=scanner-runtime /app/data_lifecycle /app/data_lifecycle' in api
    for dockerfile in (scanner, api):
        assert 'from data_lifecycle.router import router; assert len(router.routes) == 2' in dockerfile
