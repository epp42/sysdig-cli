"""
Security tests: token not in logs, http rejected, destructive warnings.
"""
from __future__ import annotations

import logging

import httpx
import pytest
import respx

from sysdig_cli.auth import AuthConfig, AuthError
from sysdig_cli.client import SysdigClient
from sysdig_cli.validator import (
    validate_host,
    validate_path_param,
    sanitize_for_logging,
    ValidationError,
)


BASE_URL = "https://us2.app.sysdig.com"


class TestTokenSecurity:
    def test_token_not_in_request_logs(self, auth_fixture, caplog):
        """Token must not appear in log output."""
        with caplog.at_level(logging.DEBUG):
            with respx.mock(base_url=BASE_URL) as mock:
                mock.get("/api/test").mock(
                    return_value=httpx.Response(200, json={})
                )
                with SysdigClient(auth=auth_fixture) as client:
                    client.get("/api/test")
        for record in caplog.records:
            assert "testtoken12345" not in record.message

    def test_token_not_in_auth_repr(self):
        auth = AuthConfig(token="supersecrettoken", host="https://us2.app.sysdig.com")
        assert "supersecrettoken" not in repr(auth)

    def test_token_not_in_auth_str(self):
        auth = AuthConfig(token="supersecrettoken", host="https://us2.app.sysdig.com")
        assert "supersecrettoken" not in str(auth)

    def test_short_token_masked(self):
        auth = AuthConfig(token="abc", host="https://us2.app.sysdig.com")
        assert "abc" not in repr(auth)

    def test_sanitize_masks_authorization_header(self):
        data = {"Authorization": "Bearer supersecrettoken12345"}
        result = sanitize_for_logging(data)
        assert "supersecrettoken12345" not in str(result)

    def test_sanitize_masks_api_key(self):
        data = {"api_key": "secret123"}
        result = sanitize_for_logging(data)
        assert "secret123" not in str(result)


class TestHttpRejection:
    def test_http_host_rejected_in_auth_config(self):
        with pytest.raises(AuthError, match="HTTPS"):
            AuthConfig(token="valid-token", host="http://sysdig.example.com")

    def test_http_host_rejected_in_validator(self):
        with pytest.raises(ValidationError, match="HTTPS"):
            validate_host("http://sysdig.example.com")

    def test_https_accepted(self):
        auth = AuthConfig(token="valid-token", host="https://us2.app.sysdig.com")
        assert auth.host.startswith("https://")

    def test_http_with_credentials_rejected(self):
        """Even if someone tries to sneak in credentials via http://, reject it."""
        with pytest.raises(AuthError):
            AuthConfig(token="token", host="http://user:pass@evil.com")


class TestPathTraversalPrevention:
    def test_double_dot_slash_blocked(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "../../etc/passwd")

    def test_null_byte_blocked(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "valid\x00inject")

    def test_url_encoded_traversal_blocked(self):
        with pytest.raises(ValidationError):
            validate_path_param("id", "%2e%2e%2f")

    def test_normal_uuid_allowed(self):
        result = validate_path_param("id", "550e8400-e29b-41d4-a716-446655440000")
        assert result == "550e8400-e29b-41d4-a716-446655440000"

    def test_normal_integer_id_allowed(self):
        result = validate_path_param("id", "12345")
        assert result == "12345"


class TestDestructiveEndpointWarnings:
    def test_prometheus_admin_delete_warns(self, capsys):
        from sysdig_cli.validator import check_dangerous_endpoint
        check_dangerous_endpoint(
            "/prometheus/api/v1/admin/tsdb/delete_series", "POST"
        )
        captured = capsys.readouterr()
        # Should have printed a warning to stderr
        assert len(captured.err) > 0

    def test_prometheus_clean_tombstones_warns(self, capsys):
        from sysdig_cli.validator import check_dangerous_endpoint
        check_dangerous_endpoint(
            "/prometheus/api/v1/admin/tsdb/clean_tombstones", "POST"
        )
        captured = capsys.readouterr()
        assert len(captured.err) > 0

    def test_safe_endpoint_no_warning(self, capsys):
        from sysdig_cli.validator import check_dangerous_endpoint
        check_dangerous_endpoint("/secure/vulnerability/v1/policies", "GET")
        captured = capsys.readouterr()
        assert captured.err == ""


@pytest.fixture
def auth_fixture():
    return AuthConfig(token="testtoken12345", host=BASE_URL)
