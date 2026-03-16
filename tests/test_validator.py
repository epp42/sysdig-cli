"""
Tests for input validation and security checks.
"""
from __future__ import annotations

import pytest

from sysdig_cli.validator import (
    validate_host,
    validate_path_param,
    validate_string_param,
    validate_params,
    validate_api_path,
    check_dangerous_endpoint,
    sanitize_for_logging,
    ValidationError,
    MAX_STRING_LENGTH,
    MAX_PARAM_LENGTH,
)


class TestValidateHost:
    def test_https_accepted(self):
        validate_host("https://us2.app.sysdig.com")  # Should not raise

    def test_http_rejected(self):
        with pytest.raises(ValidationError, match="HTTPS"):
            validate_host("http://us2.app.sysdig.com")

    def test_http_localhost_rejected(self):
        with pytest.raises(ValidationError):
            validate_host("http://localhost:8080")

    def test_all_https_regions(self):
        for host in [
            "https://us2.app.sysdig.com",
            "https://us4.app.sysdig.com",
            "https://eu1.app.sysdig.com",
            "https://app.au1.sysdig.com",
        ]:
            validate_host(host)  # Should not raise


class TestValidatePathParam:
    def test_valid_id(self):
        result = validate_path_param("id", "12345")
        assert result == "12345"

    def test_valid_name(self):
        result = validate_path_param("name", "my-policy")
        assert result == "my-policy"

    def test_path_traversal_blocked(self):
        with pytest.raises(ValidationError, match="dangerous"):
            validate_path_param("id", "../etc/passwd")

    def test_path_traversal_backslash(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "..\\windows\\system32")

    def test_null_byte_blocked(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "valid\x00evil")

    def test_url_encoded_traversal_blocked(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "%2e%2e/etc/passwd")

    def test_too_long_blocked(self):
        with pytest.raises(ValidationError, match="max length"):
            validate_path_param("id", "x" * (MAX_PARAM_LENGTH + 1))

    def test_non_string_converted(self):
        result = validate_path_param("id", 12345)  # type: ignore
        assert result == "12345"


class TestValidateStringParam:
    def test_valid_string(self):
        result = validate_string_param("filter", "kubernetes.cluster.name=prod")
        assert result == "kubernetes.cluster.name=prod"

    def test_crlf_injection_blocked(self):
        with pytest.raises(ValidationError, match="injection"):
            validate_string_param("filter", "value\r\nX-Evil: injected")

    def test_cr_blocked(self):
        with pytest.raises(ValidationError):
            validate_string_param("filter", "value\revil")

    def test_lf_blocked(self):
        with pytest.raises(ValidationError):
            validate_string_param("filter", "value\nevil")

    def test_too_long_blocked(self):
        with pytest.raises(ValidationError, match="max length"):
            validate_string_param("filter", "x" * (MAX_STRING_LENGTH + 1))

    def test_empty_string_allowed(self):
        result = validate_string_param("filter", "")
        assert result == ""


class TestValidateParams:
    def test_valid_params(self):
        result = validate_params({"limit": 100, "filter": "name=test"})
        assert result == {"limit": 100, "filter": "name=test"}

    def test_none_values_preserved(self):
        result = validate_params({"limit": None, "filter": "test"})
        assert result["limit"] is None

    def test_injection_blocked(self):
        with pytest.raises(ValidationError):
            validate_params({"filter": "test\r\nevil"})


class TestValidateApiPath:
    def test_valid_path(self):
        result = validate_api_path("/secure/vulnerability/v1/policies")
        assert result == "/secure/vulnerability/v1/policies"

    def test_traversal_blocked(self):
        with pytest.raises(ValidationError):
            validate_api_path("/api/../../../etc/passwd")


class TestCheckDangerousEndpoint:
    def test_prometheus_delete_warns(self, capsys):
        check_dangerous_endpoint(
            "/prometheus/api/v1/admin/tsdb/delete_series", "POST"
        )
        # Should have printed a warning to stderr
        captured = capsys.readouterr()
        assert "Warning" in captured.err or "dangerous" in captured.err.lower() or "Prometheus" in captured.err

    def test_prometheus_snapshot_warns(self, capsys):
        check_dangerous_endpoint(
            "/prometheus/api/v1/admin/tsdb/snapshot", "POST"
        )
        captured = capsys.readouterr()
        assert len(captured.err) > 0

    def test_safe_get_no_warning(self, capsys):
        check_dangerous_endpoint("/secure/vulnerability/v1/policies", "GET")
        captured = capsys.readouterr()
        assert captured.err == ""


class TestSanitizeForLogging:
    def test_token_masked(self):
        result = sanitize_for_logging({"token": "supersecret123"})
        assert result["token"] == "****"
        assert "supersecret123" not in str(result)

    def test_password_masked(self):
        result = sanitize_for_logging({"password": "mypassword"})
        assert result["password"] == "****"

    def test_normal_fields_preserved(self):
        result = sanitize_for_logging({"name": "test", "id": "123"})
        assert result["name"] == "test"
        assert result["id"] == "123"

    def test_nested_secrets_masked(self):
        result = sanitize_for_logging({
            "auth": {"token": "secret", "user": "alice"}
        })
        assert result["auth"]["token"] == "****"
        assert result["auth"]["user"] == "alice"

    def test_list_sanitized(self):
        result = sanitize_for_logging([
            {"token": "secret1"},
            {"name": "safe"},
        ])
        assert result[0]["token"] == "****"
        assert result[1]["name"] == "safe"
