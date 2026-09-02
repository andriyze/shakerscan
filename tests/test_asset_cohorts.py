from api.asset_cohorts import normalize_target_cohort, target_cohort


def test_explicit_cohort_wins_and_environment_is_compatible():
    assert target_cohort(url="https://example.com", metadata={"cohort": "staging"}) == "staging"
    assert target_cohort(url="https://example.com", metadata={"environment": "production"}) == "production"
    assert normalize_target_cohort("development") == "lab"


def test_only_explicit_metadata_excludes_public_targets_from_operations():
    assert target_cohort(url="http://juice-shop.local:3000") == "internal"
    assert target_cohort(url="http://host.docker.internal:8080") == "internal"
    assert target_cohort(url="postgres:5432") == "internal"
    assert target_cohort(url="https://receipt-validation.example") == "unclassified"
    assert target_cohort(
        url="https://sandbox.payments.example.com", name="Demo Portal",
    ) == "unclassified"
    assert target_cohort(url="https://customer.example") == "unclassified"
