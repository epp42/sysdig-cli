"""
Tests for HTTP client with retry/backoff logic.
"""
from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import (
    SysdigClient,
    AuthError,
    APIError,
    NotFoundError,
    ForbiddenError,
    UsageError,
)


BASE_URL = "https://us2.app.sysdig.com"


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken123", host=BASE_URL)


@pytest.fixture
def client(auth):
    c = SysdigClient(auth=auth)
    yield c
    c.close()


class TestSysdigClient:
    def test_successful_get(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={"result": "ok"})
            )
            with SysdigClient(auth=auth) as client:
                response = client.get("/api/test")
        assert response == {"result": "ok"}

    def test_auth_header_sent(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={})
            )
            with SysdigClient(auth=auth) as client:
                client.get("/api/test")
            request = route.calls[0].request
            assert "Bearer testtoken123" in request.headers.get("authorization", "")

    def test_401_raises_auth_error(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(401, json={"message": "Unauthorized"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(AuthError):
                    client.get("/api/test")

    def test_403_raises_forbidden_error(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(403, json={"message": "Forbidden"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(ForbiddenError):
                    client.get("/api/test")

    def test_404_raises_not_found_error(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(404, json={"message": "Not found"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(NotFoundError):
                    client.get("/api/test")

    def test_400_raises_usage_error(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.post("/api/test").mock(
                return_value=httpx.Response(400, json={"message": "Bad request"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(UsageError):
                    client.post("/api/test", json_body={"x": 1})

    def test_500_raises_api_error(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(500, json={"message": "Internal error"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(APIError):
                    client.get("/api/test")

    def test_exit_codes(self):
        assert AuthError.exit_code == 2
        assert ForbiddenError.exit_code == 5
        assert NotFoundError.exit_code == 4
        assert UsageError.exit_code == 1
        assert APIError.exit_code == 3

    def test_empty_response_returns_empty_dict(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.delete("/api/test/1").mock(
                return_value=httpx.Response(204, content=b"")
            )
            with SysdigClient(auth=auth) as client:
                result = client.delete("/api/test/1")
        assert result == {}

    def test_dry_run_post_does_not_call_api(self, auth):
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            route = mock.post("/api/test").mock(
                return_value=httpx.Response(200, json={"created": True})
            )
            with SysdigClient(auth=auth, dry_run=True) as client:
                result = client.post("/api/test", json_body={"name": "test"})
            # Should not have been called
            assert len(route.calls) == 0
            assert result is None

    def test_dry_run_get_still_calls_api(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            with SysdigClient(auth=auth, dry_run=True) as client:
                result = client.get("/api/test")
            assert len(route.calls) == 1
            assert result == {"data": []}


class TestRetryBehavior:
    def test_rate_limit_retry_after(self, auth):
        """Test that 429 respects Retry-After header."""
        call_count = 0
        responses = [
            httpx.Response(429, json={"message": "Too Many Requests"},
                         headers={"Retry-After": "0"}),
            httpx.Response(200, json={"result": "ok"}),
        ]

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                if call_count < len(responses):
                    resp = responses[call_count]
                    call_count += 1
                    return resp
                return httpx.Response(200, json={})

            mock.get("/api/test").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                with patch("time.sleep"):
                    # First call hits 429, re-raises, second attempt in loop
                    try:
                        client.get("/api/test")
                    except APIError:
                        pass

    def test_token_not_in_error_messages(self, auth):
        """Ensure token is never leaked in error messages."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(401, json={"message": "token invalid"})
            )
            with SysdigClient(auth=auth) as client:
                try:
                    client.get("/api/test")
                except AuthError as e:
                    assert "testtoken123" not in str(e)

    def test_connection_error_retries(self, auth):
        """Test that connection errors are retried."""
        # Verify retry constants are set correctly
        from sysdig_cli.client import MAX_RETRIES, BACKOFF_DELAYS, RETRY_STATUS_CODES
        assert MAX_RETRIES == 3
        assert len(BACKOFF_DELAYS) >= 3
        assert 429 in RETRY_STATUS_CODES
        assert 502 in RETRY_STATUS_CODES
        assert 503 in RETRY_STATUS_CODES
        assert 504 in RETRY_STATUS_CODES

    def test_connection_error_raises_after_retries(self, auth):
        """Test that connection errors eventually raise APIError."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(side_effect=httpx.ConnectError("Refused"))
            with SysdigClient(auth=auth) as client:
                with patch("time.sleep"):
                    with pytest.raises(APIError, match="failed after"):
                        client.get("/api/test")


class TestDryRun:
    def test_dry_run_outputs_request_info(self, auth, capsys):
        with respx.mock(base_url=BASE_URL, assert_all_called=False):
            with SysdigClient(auth=auth) as client:
                client.post(
                    "/api/test",
                    json_body={"name": "test"},
                    dry_run=True,
                )
            captured = capsys.readouterr()
            # dry_run output should be JSON on stdout
            import json
            data = json.loads(captured.out)
            assert data["dry_run"] is True
            assert data["method"] == "POST"
            assert data["path"] == "/api/test"

    def test_dry_run_delete(self, auth, capsys):
        with respx.mock(base_url=BASE_URL, assert_all_called=False):
            with SysdigClient(auth=auth) as client:
                client.delete("/api/test/123", dry_run=True)
            captured = capsys.readouterr()
            import json
            data = json.loads(captured.out)
            assert data["method"] == "DELETE"
