from api.asset_cohorts import normalize_target_cohort, target_cohort


def test_explicit_cohort_wins_and_environment_is_compatible():
    assert target_cohort(url="https://example.com", metadata={"cohort": "staging"}) == "staging"
    assert target_cohort(url="https://example.com", metadata={"environment": "production"}) == "production"
    assert normalize_target_cohort("development") == "lab"


def test_obvious_non_operational_assets_are_isolated_without_guessing_production():
    assert target_cohort(url="http://juice-shop.local:3000") == "demo"
    assert target_cohort(url="http://host.docker.internal:8080") == "internal"
    assert target_cohort(url="postgres:5432") == "internal"
    assert target_cohort(url="https://receipt-validation.example") == "calibration"
    assert target_cohort(url="https://customer.example") == "unclassified"
