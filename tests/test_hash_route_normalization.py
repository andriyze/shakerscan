"""
Unit tests for hash route normalization in http_scanner.

Tests cover:
1. Hash route URL construction with subpaths
2. File path vs directory path handling
3. Preservation of hash route fragments

These tests exercise the production normalize_hash_route_url() function directly.
"""

import pytest
import sys
import os

# Add scanner directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

# Import the production function directly - tests will catch any regressions
from scanner_tools.common import normalize_hash_route_url as normalize_hash_route


class TestHashRouteNormalization:
    """Tests for hash route URL normalization."""

    def test_simple_hash_route(self):
        """Test basic hash route conversion."""
        result = normalize_hash_route("#/search", "https://example.com/")
        assert result == "https://example.com/#/search"

    def test_hashbang_route(self):
        """Test hashbang route conversion."""
        result = normalize_hash_route("#!/page", "https://example.com/")
        assert result == "https://example.com/#!/page"

    def test_hash_route_with_params(self):
        """Test hash route with query parameters."""
        result = normalize_hash_route("#/search?q=test&page=1", "https://example.com/")
        assert result == "https://example.com/#/search?q=test&page=1"

    def test_subpath_directory(self):
        """Test hash route with subpath directory."""
        result = normalize_hash_route("#/search", "https://host/app/")
        assert result == "https://host/app/#/search"

    def test_subpath_trailing_slash(self):
        """Test hash route with subpath without trailing slash."""
        result = normalize_hash_route("#/search", "https://host/app")
        assert result == "https://host/app/#/search"

    def test_subpath_file_index_html(self):
        """Test hash route normalizes index.html to directory."""
        result = normalize_hash_route("#/search", "https://host/app/index.html")
        assert result == "https://host/app/#/search"

    def test_subpath_file_other(self):
        """Test hash route normalizes other files to directory."""
        result = normalize_hash_route("#/route", "https://host/myapp/main.html")
        assert result == "https://host/myapp/#/route"

    def test_deep_subpath(self):
        """Test hash route with deep subpath."""
        result = normalize_hash_route("#/dashboard", "https://host/v1/apps/myapp/")
        assert result == "https://host/v1/apps/myapp/#/dashboard"

    def test_deep_subpath_with_file(self):
        """Test hash route with deep subpath ending in file."""
        result = normalize_hash_route("#/settings", "https://host/v1/apps/myapp/index.html")
        assert result == "https://host/v1/apps/myapp/#/settings"

    def test_anchor_only_rejected(self):
        """Test that anchor-only fragments are rejected."""
        result = normalize_hash_route("#top", "https://example.com/")
        assert result is None

    def test_section_anchor_rejected(self):
        """Test that section anchors are rejected."""
        result = normalize_hash_route("#section-1", "https://example.com/page")
        assert result is None

    def test_non_hash_rejected(self):
        """Test that non-hash strings are rejected."""
        result = normalize_hash_route("/page", "https://example.com/")
        assert result is None

    def test_port_preserved(self):
        """Test that port is preserved in output."""
        result = normalize_hash_route("#/search", "https://example.com:8080/app/")
        assert result == "https://example.com:8080/app/#/search"

    def test_http_scheme(self):
        """Test HTTP scheme is preserved."""
        result = normalize_hash_route("#/page", "http://example.com/")
        assert result == "http://example.com/#/page"


class TestHashRouteEdgeCases:
    """Edge case tests for hash route normalization."""

    def test_root_path(self):
        """Test hash route from root path."""
        result = normalize_hash_route("#/home", "https://example.com")
        assert result == "https://example.com/#/home"

    def test_empty_path(self):
        """Test hash route from URL with no path."""
        result = normalize_hash_route("#/page", "https://example.com")
        assert result == "https://example.com/#/page"

    def test_complex_fragment(self):
        """Test hash route with complex fragment path."""
        result = normalize_hash_route(
            "#/users/123/profile?tab=settings&lang=en",
            "https://app.example.com/dashboard/"
        )
        assert result == "https://app.example.com/dashboard/#/users/123/profile?tab=settings&lang=en"

    def test_file_with_query_string(self):
        """Test hash route from file URL with query string."""
        result = normalize_hash_route("#/route", "https://host/app/index.html?v=1.2.3")
        assert result == "https://host/app/#/route"

    def test_dotfile_not_treated_as_file(self):
        """Test that dotfiles in path are handled correctly."""
        # .well-known is a directory, not a file
        result = normalize_hash_route("#/route", "https://host/.well-known/")
        assert result == "https://host/.well-known/#/route"

    def test_version_path_not_treated_as_file(self):
        """Test that version paths like /v1.2/ are not treated as files."""
        result = normalize_hash_route("#/route", "https://host/api/v1.2/")
        assert result == "https://host/api/v1.2/#/route"

    def test_version_path_no_trailing_slash(self):
        """Test version path without trailing slash is preserved."""
        result = normalize_hash_route("#/route", "https://host/api/v1.2")
        # v1.2 doesn't have a file extension, so it's kept
        assert result == "https://host/api/v1.2/#/route"

    def test_dotted_directory_preserved(self):
        """Test that dotted directory names are preserved."""
        result = normalize_hash_route("#/page", "https://host/my.app/")
        assert result == "https://host/my.app/#/page"

    def test_unknown_extension_preserved(self):
        """Test that unknown extensions are not treated as files."""
        result = normalize_hash_route("#/page", "https://host/path/file.xyz")
        # .xyz is not in the file extensions list, so path is preserved
        assert result == "https://host/path/file.xyz/#/page"

    def test_php_file_normalized(self):
        """Test that PHP files are normalized to directory."""
        result = normalize_hash_route("#/page", "https://host/app/index.php")
        assert result == "https://host/app/#/page"

    def test_aspx_file_normalized(self):
        """Test that ASPX files are normalized to directory."""
        result = normalize_hash_route("#/page", "https://host/app/default.aspx")
        assert result == "https://host/app/#/page"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
