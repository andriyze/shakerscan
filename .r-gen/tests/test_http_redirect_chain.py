from scanner.scanner_tools.http_scanner import _redirect_chain_from_header_blocks


def test_redirect_chain_recovers_relative_and_absolute_hops():
    blocks = [
        "HTTP/1.1 302 Found\r\nLocation: /login",
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://auth.example.com/continue",
        "HTTP/2 200 OK\r\nContent-Type: text/html",
    ]

    assert _redirect_chain_from_header_blocks("https://app.example.com/start", blocks) == [
        "https://app.example.com/login",
        "https://auth.example.com/continue",
    ]


def test_redirect_chain_ignores_non_redirect_and_missing_location_blocks():
    blocks = [
        "HTTP/1.1 200 Connection established",
        "HTTP/1.1 302 Found\r\nX-Test: no-location",
        "not-http\r\nLocation: https://evil.example.net",
    ]

    assert _redirect_chain_from_header_blocks("https://app.example.com", blocks) == []
