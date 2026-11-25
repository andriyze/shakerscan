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


def test_a_wildcard_dns_name_is_classed_by_the_address_written_in_it():
    from api.asset_cohorts import target_exposure_class, wildcard_dns_address

    internal = (
        "http://billing.shop-10-0-0-5.sslip.io:8099",
        "https://10-0-0-5.sslip.io",
        "https://app.192.168.1.5.nip.io",
        "https://192.168.1.5.nip.io/path",
        "https://app-192-168-1-5.xip.io",
        "https://www.127-0-0-1.traefik.me",
        "https://APP.192.168.1.5.NIP.IO",           # uppercase
        "https://app.192.168.1.5.nip.io./",          # trailing dot
        "10-0-0-5.sslip.io:8080",                    # a locator without a scheme
        "https://0-0-0-0.sslip.io",                  # unspecified
        "https://169-254-169-254.sslip.io",          # link-local
        "https://100-64-0-1.sslip.io",               # CGNAT
        "https://172.16.0.1.nip.io",
        "https://--1.sslip.io",                      # sslip IPv6 ::1
        "https://www.fd00--5.sslip.io",              # sslip IPv6 ULA
        "https://fe80--1.sslip.io",                  # sslip IPv6 link-local
    )
    for url in internal:
        assert target_exposure_class(url) == "internal", url
        assert target_cohort(url=url, metadata={}) == "internal", url

    public = (
        "https://app.8.8.8.8.nip.io",                # a public address stays public
        "https://8-8-8-8.sslip.io",
        "https://2001-4860-4860--8888.sslip.io",     # public IPv6
        "https://deadbeef.sslip.io",                 # hex-like, not an address
        "https://cafe-babe.sslip.io",
        "https://c0a80105.nip.io",
        "https://abc-10-0-0.sslip.io",               # three octets only
        "https://app-10-0-0-256.sslip.io",           # an octet over 255
        "https://app-10-0-0-1000.sslip.io",
        "https://fd00--5.nip.io",                    # IPv6 dashes are an sslip.io form only
        "https://" + "a" * 64 + "-10-0-0-5.sslip.io",   # a label over 63 characters
        "https://" + "a." * 120 + "10-0-0-5.sslip.io",  # a name over 253 characters
        "https://sslip.io",
        "https://10-0-0-5.sslip.io.example.com",     # not under the service
        "https://10-0-0-5.notsslip.io",
    )
    for url in public:
        assert target_exposure_class(url) == "public", url
        assert target_cohort(url=url, metadata={}) == "unclassified", url

    assert str(wildcard_dns_address("billing.shop-10-0-0-5.sslip.io")) == "10.0.0.5"
    assert str(wildcard_dns_address("--1.sslip.io")) == "::1"
    assert wildcard_dns_address("example.com") is None
    # Explicit operator metadata still wins over the host.
    assert target_cohort(url="https://10-0-0-5.sslip.io", metadata={"cohort": "staging"}) == "staging"
