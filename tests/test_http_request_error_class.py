"""A bound request that never got a response is named by its cause."""

from pathlib import Path
import ssl
import sys

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from capabilities.http import request_error_class  # noqa: E402
from scan.activity import diagnostic_error_class  # noqa: E402


def test_certificate_verification_failure_is_named_through_the_chain():
    cause = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    wrapped = httpx.ConnectError("all frozen target addresses failed before connect")
    wrapped.__cause__ = cause
    assert request_error_class(wrapped) == "tls_certificate_untrusted:ConnectError"


def test_other_connect_failures_keep_the_client_exception_name():
    assert request_error_class(httpx.ConnectError("connection refused")) == "request_error:ConnectError"
    assert request_error_class(httpx.ConnectTimeout("timed out")) == "request_error:ConnectTimeout"


def test_diagnostic_line_reports_the_tls_cause_instead_of_unclassified():
    assert diagnostic_error_class(["adapter_failed", "tls_certificate_untrusted:ConnectError"]) == "tls_certificate_untrusted"
    assert diagnostic_error_class(["request_error:ConnectError"]) == "request_error"
