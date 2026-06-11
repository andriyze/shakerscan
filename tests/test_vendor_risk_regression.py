import asyncio
import os
import sys


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from scanner_tools.vendor_risk import vendor_risk_assessment  # noqa: E402

sys.path.pop(0)


def test_vendor_risk_handles_self_hosted_analytics_without_name_error():
    html = """
    <html>
      <head>
        <script src="https://tidyhelpers.com/umami/script.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/example@1.0.0/index.js"></script>
      </head>
    </html>
    """

    result = asyncio.run(
        vendor_risk_assessment(
            "https://tidyhelpers.com",
            page_content=html,
            check_security=False,
        )
    )

    assert result.total_third_parties == 1
    assert result.summary["first_party_like_resources"] == 0
    assert "cdn.jsdelivr.net" in result.third_party_domains
