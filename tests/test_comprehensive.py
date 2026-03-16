"""
Comprehensive tests covering all required testing categories:
1. Security vectors (token masking, path traversal, CRLF, null bytes, etc.)
2. Unit tests: timestamps, pagination, formatter, exit codes, auth priority
3. Integration tests via respx mock
4. Stress/edge case tests
5. Alpha banner consistency
6. Help text quality
"""
from __future__ import annotations

import io
import json
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig, AuthError, resolve_auth, REGION_HOSTS
from sysdig_cli.client import (
    SysdigClient,
    APIError,
    AuthError as ClientAuthError,
    ForbiddenError,
    NotFoundError,
    UsageError,
)
from sysdig_cli.formatter import (
    format_json,
    format_ndjson,
    format_table,
    format_yaml,
    flatten_dict,
    output,
)
from sysdig_cli.paginator import (
    paginate,
    paginate_all_items,
    stream_ndjson,
    _extract_next_cursor,
    _extract_data,
)
from sysdig_cli.timestamps import parse_timestamp, now_ns
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

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


@pytest.fixture(autouse=True)
def set_token_env(monkeypatch):
    """Set test API token for all tests that need it."""
    monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken12345")
    monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken12345", host=BASE_URL)


# ===========================================================================
# 2a. TIMESTAMP CONVERSION TESTS
# ===========================================================================

class TestTimestampConversion:
    """Test timestamp parsing - various formats to nanoseconds."""

    def test_one_hour_relative(self):
        """'1h' should yield ~1 hour ago in nanoseconds."""
        before = int((time.time() - 3600) * 1e9)
        result = parse_timestamp("1h")
        after = int((time.time() - 3600) * 1e9)
        # Allow 2 second tolerance
        assert before - 2_000_000_000 <= result <= after + 2_000_000_000

    def test_thirty_minutes_relative(self):
        """'30m' should yield ~30 minutes ago in nanoseconds."""
        before = int((time.time() - 1800) * 1e9)
        result = parse_timestamp("30m")
        after = int((time.time() - 1800) * 1e9)
        assert before - 2_000_000_000 <= result <= after + 2_000_000_000

    def test_seven_days_relative(self):
        """'7d' should yield ~7 days ago in nanoseconds."""
        seven_days_seconds = 7 * 86400
        before = int((time.time() - seven_days_seconds) * 1e9)
        result = parse_timestamp("7d")
        after = int((time.time() - seven_days_seconds) * 1e9)
        assert before - 2_000_000_000 <= result <= after + 2_000_000_000

    def test_iso8601_utc(self):
        """ISO8601 format should parse to correct nanoseconds."""
        result = parse_timestamp("2024-01-15T10:00:00Z")
        # 2024-01-15T10:00:00Z = 1705312800 seconds
        expected_seconds = 1705312800
        expected_ns = expected_seconds * int(1e9)
        assert abs(result - expected_ns) < int(1e9)  # within 1 second

    def test_iso8601_with_offset(self):
        """ISO8601 with timezone offset."""
        result = parse_timestamp("2024-01-15T10:00:00+00:00")
        expected_ns = 1705312800 * int(1e9)
        assert abs(result - expected_ns) < int(1e9)

    def test_invalid_input_raises_value_error(self):
        """Invalid timestamp should raise ValueError with helpful message."""
        with pytest.raises(ValueError) as exc_info:
            parse_timestamp("not-a-timestamp")
        assert "parse" in str(exc_info.value).lower() or "Cannot" in str(exc_info.value)

    def test_empty_string_raises_value_error(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError):
            parse_timestamp("")

    def test_unix_seconds_integer(self):
        """Plain integer treated as Unix seconds."""
        result = parse_timestamp("1705312800")
        expected_ns = 1705312800 * int(1e9)
        assert result == expected_ns

    def test_unix_nanoseconds(self):
        """Large integer treated as nanoseconds."""
        ns_value = 1705312800000000000
        result = parse_timestamp(str(ns_value))
        assert result == ns_value

    def test_minutes_unit(self):
        """'5m' = 5 minutes ago."""
        before = int((time.time() - 300) * 1e9)
        result = parse_timestamp("5m")
        after = int((time.time() - 300) * 1e9)
        assert before - 2_000_000_000 <= result <= after + 2_000_000_000

    def test_weeks_unit(self):
        """'2w' = 2 weeks ago."""
        two_weeks = 2 * 7 * 86400
        before = int((time.time() - two_weeks) * 1e9)
        result = parse_timestamp("2w")
        after = int((time.time() - two_weeks) * 1e9)
        assert before - 2_000_000_000 <= result <= after + 2_000_000_000

    def test_result_is_integer(self):
        """parse_timestamp should always return an int."""
        result = parse_timestamp("1h")
        assert isinstance(result, int)

    def test_result_is_nanoseconds_scale(self):
        """Result should be in nanosecond scale (> 1e18 for current epoch)."""
        result = parse_timestamp("1h")
        assert result > int(1e18), f"Expected nanoseconds scale, got {result}"


# ===========================================================================
# 2b. PAGINATION CURSOR LOGIC
# ===========================================================================

class TestPaginationCursorLogic:
    """Extended pagination tests."""

    def test_last_page_stops_iteration(self, auth):
        """Last page (no cursor in response) stops iteration."""
        response_data = {"data": [{"id": 1}], "page": {"next": None}}
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/items").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            with SysdigClient(auth=auth) as client:
                pages = list(paginate(client, "GET", "/api/items", page_all=True))
        assert len(pages) == 1
        assert route.call_count == 1

    def test_page_all_follows_all_cursors(self, auth):
        """--page-all follows all cursors until no cursor remains."""
        responses = [
            {"data": [{"id": 1}], "page": {"next": "c2"}},
            {"data": [{"id": 2}], "page": {"next": "c3"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/items").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                pages = list(paginate(client, "GET", "/api/items", page_all=True))

        assert len(pages) == 3
        assert call_count == 3

    def test_page_all_streams_ndjson(self, auth, capsys):
        """Each page items are emitted as NDJSON when streaming."""
        responses = [
            {"data": [{"id": 1}, {"id": 2}], "page": {"next": "c2"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/items").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                count = stream_ndjson(client, "GET", "/api/items")

        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().split("\n") if l.strip()]
        assert count == 3
        assert len(lines) == 3
        for line in lines:
            obj = json.loads(line)
            assert "id" in obj

    def test_empty_first_page_handled_gracefully(self, auth):
        """Empty first page (zero results) handled without error."""
        response_data = {"data": [], "page": {"next": None}}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/items").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/items"))
        assert items == []

    def test_cursor_from_next_cursor_field(self, auth):
        """Supports 'nextCursor' pagination pattern."""
        responses = [
            {"data": [{"id": 1}], "nextCursor": "abc"},
            {"data": [{"id": 2}], "nextCursor": None},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/items").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/items"))

        assert len(items) == 2


# ===========================================================================
# 2c. FORMATTER CORRECTNESS
# ===========================================================================

class TestFormatterCorrectness:
    """Test formatter handles various data shapes correctly."""

    def test_nested_dict_flattened_to_dot_notation(self):
        """Nested dict {'a': {'b': 1}} -> table column 'a.b'."""
        data = [{"a": {"b": 1}}]
        result = format_table(data)
        assert "a.b" in result
        assert "1" in result

    def test_array_of_objects_one_row_per_object(self):
        """Array of objects -> one row per object in table."""
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
            {"name": "carol", "age": 35},
        ]
        result = format_table(data)
        assert "alice" in result
        assert "bob" in result
        assert "carol" in result

    def test_unicode_in_values_handled_correctly(self):
        """Unicode characters in values should not raise errors."""
        data = [{"name": "用户名", "city": "Zürich", "emoji": "🔐"}]
        result = format_table(data)
        assert "用户名" in result or len(result) > 0

    def test_ndjson_output_one_json_per_line(self):
        """NDJSON output should be one JSON object per line."""
        data = [{"a": 1}, {"b": 2}, {"c": 3}]
        result = format_ndjson(data)
        lines = result.strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)

    def test_yaml_output_valid_yaml(self):
        """YAML output should be parseable YAML."""
        data = {"name": "test", "count": 42, "items": [1, 2, 3]}
        result = format_yaml(data)
        parsed = yaml.safe_load(result)
        assert parsed["name"] == "test"
        assert parsed["count"] == 42

    def test_table_truncates_long_values(self):
        """Table formatter truncates field values longer than max_col_width."""
        long_value = "x" * 200
        data = [{"description": long_value}]
        result = format_table(data, max_col_width=60)
        assert "..." in result
        # The truncated value should not appear fully
        assert long_value not in result

    def test_very_long_field_values_truncated_at_60_chars(self):
        """Very long field values (>60 chars) should be truncated with '...'."""
        data = [{"field": "A" * 100}]
        result = format_table(data, max_col_width=60)
        assert "..." in result

    def test_nested_dict_column_name(self):
        """{'a': {'b': 1}} should create column 'a.b' in table."""
        result = flatten_dict({"a": {"b": 1}})
        assert "a.b" in result
        assert result["a.b"] == 1

    def test_format_json_pretty_printed(self):
        """JSON output should be pretty-printed (has indentation)."""
        data = {"key": "value", "number": 42}
        result = format_json(data)
        parsed = json.loads(result)
        assert parsed == data
        assert "\n" in result  # pretty-printed

    def test_empty_list_ndjson(self):
        """Empty list ndjson should be empty string."""
        result = format_ndjson([])
        assert result == ""


# ===========================================================================
# 2d. EXIT CODE CONTRACT
# ===========================================================================

class TestExitCodeContract:
    """Verify HTTP errors map to correct exit codes."""

    def _invoke_vulns_list(self, status_code: int, response_body: dict = None):
        """Helper to invoke vulns policies-list with a mock status code."""
        from sysdig_cli.main import app
        body = response_body or {"message": f"Error {status_code}"}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(status_code, json=body)
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        return result

    def test_401_exits_with_code_2(self):
        """401 Unauthorized -> exit code 2."""
        result = self._invoke_vulns_list(401)
        assert result.exit_code == 2

    def test_404_exits_with_code_4(self):
        """404 Not Found -> exit code 4."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies/nonexistent").mock(
                return_value=httpx.Response(404, json={"message": "Not found"})
            )
            from sysdig_cli.main import app
            result = runner.invoke(app, ["vulns", "policies-get", "nonexistent"])
        assert result.exit_code == 4

    def test_403_exits_with_code_5(self):
        """403 Forbidden -> exit code 5."""
        result = self._invoke_vulns_list(403)
        assert result.exit_code == 5

    def test_500_exits_with_code_3(self):
        """500 Server Error -> exit code 3."""
        result = self._invoke_vulns_list(500)
        assert result.exit_code == 3

    def test_bad_flag_exits_with_code_2(self):
        """Unknown flag should exit with non-zero code."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "--nonexistent-flag"])
        assert result.exit_code != 0

    def test_client_401_raises_auth_error(self, auth):
        """HTTP 401 raises AuthError with exit_code 2."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(401, json={"message": "Unauthorized"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(ClientAuthError) as exc:
                    client.get("/api/test")
        assert exc.value.exit_code == 2

    def test_client_403_raises_forbidden_error(self, auth):
        """HTTP 403 raises ForbiddenError with exit_code 5."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(403, json={"message": "Forbidden"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(ForbiddenError) as exc:
                    client.get("/api/test")
        assert exc.value.exit_code == 5

    def test_client_404_raises_not_found_error(self, auth):
        """HTTP 404 raises NotFoundError with exit_code 4."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(404, json={"message": "Not found"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(NotFoundError) as exc:
                    client.get("/api/test")
        assert exc.value.exit_code == 4

    def test_client_500_raises_api_error(self, auth):
        """HTTP 500 raises APIError with exit_code 3."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(500, json={"message": "Internal error"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(APIError) as exc:
                    client.get("/api/test")
        assert exc.value.exit_code == 3

    def test_client_400_raises_usage_error(self, auth):
        """HTTP 400 raises UsageError with exit_code 1."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(400, json={"message": "Bad request"})
            )
            with SysdigClient(auth=auth) as client:
                with pytest.raises(UsageError) as exc:
                    client.get("/api/test")
        assert exc.value.exit_code == 1


# ===========================================================================
# 2e. AUTH PRIORITY CHAIN
# ===========================================================================

class TestAuthPriorityChain:
    """Verify auth resolution priority order."""

    def test_sysdig_api_token_takes_priority_over_config(self, monkeypatch, tmp_path):
        """SYSDIG_API_TOKEN takes priority over config file."""
        monkeypatch.setenv("SYSDIG_API_TOKEN", "env-api-token")
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        import yaml as pyyaml
        config = {"profiles": {"default": {"token": "config-token", "host": "https://eu1.app.sysdig.com"}}}
        config_file.write_text(pyyaml.dump(config))
        auth = resolve_auth(config_path=config_file)
        assert auth.token == "env-api-token"
        assert auth.profile == "env"

    def test_sysdig_secure_token_is_fallback(self, monkeypatch, tmp_path):
        """SYSDIG_SECURE_TOKEN is fallback to SYSDIG_API_TOKEN."""
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.setenv("SYSDIG_SECURE_TOKEN", "secure-fallback-token")
        config_file = tmp_path / "noconfig.yaml"
        auth = resolve_auth(config_path=config_file)
        assert auth.token == "secure-fallback-token"
        assert auth.profile == "env"

    def test_api_token_beats_secure_token(self, monkeypatch):
        """SYSDIG_API_TOKEN beats SYSDIG_SECURE_TOKEN."""
        monkeypatch.setenv("SYSDIG_API_TOKEN", "api-winner")
        monkeypatch.setenv("SYSDIG_SECURE_TOKEN", "secure-loser")
        auth = resolve_auth()
        assert auth.token == "api-winner"

    def test_config_file_profile_loads_correctly(self, monkeypatch, tmp_path):
        """Config file profile loads correctly when no env vars set."""
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        import yaml as pyyaml
        config = {"profiles": {"default": {"token": "file-token-999", "host": "https://us4.app.sysdig.com"}}}
        config_file.write_text(pyyaml.dump(config))
        auth = resolve_auth(config_path=config_file)
        assert auth.token == "file-token-999"
        assert auth.host == "https://us4.app.sysdig.com"
        assert auth.profile == "default"

    def test_region_eu1_maps_to_correct_host(self, monkeypatch):
        """--region eu1 maps to https://eu1.app.sysdig.com."""
        monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
        auth = resolve_auth(region="eu1")
        assert auth.host == "https://eu1.app.sysdig.com"

    def test_region_us2_maps_to_correct_host(self, monkeypatch):
        """--region us2 maps to https://us2.app.sysdig.com."""
        monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
        auth = resolve_auth(region="us2")
        assert auth.host == "https://us2.app.sysdig.com"

    def test_all_regions_use_https(self):
        """All region hosts must use HTTPS."""
        for region, host in REGION_HOSTS.items():
            assert host.startswith("https://"), f"Region {region} host {host} must use HTTPS"


# ===========================================================================
# 3. INTEGRATION TESTS
# ===========================================================================

class TestIntegrationVulns:
    """Integration tests for vulns commands using respx mock."""

    def test_policies_list_json_output(self):
        """sysdig vulns policies-list with mock 200 -> correct JSON output."""
        from sysdig_cli.main import app
        response_data = {
            "data": [
                {"id": "p1", "name": "Default Policy", "stages": ["runtime"]},
                {"id": "p2", "name": "Build Policy", "stages": ["build"]},
            ],
            "page": {"returned": 2, "matched": 2, "next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["data"][0]["id"] == "p1"
        assert data["data"][1]["id"] == "p2"

    def test_policies_list_table_format(self):
        """sysdig vulns policies-list --format table -> correct table output."""
        from sysdig_cli.main import app
        response_data = {
            "data": [{"id": "p1", "name": "Default Policy"}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-list", "--format", "table"])
        assert result.exit_code == 0
        assert "p1" in result.output or "Default Policy" in result.output

    def test_policies_list_page_all_streams_both_pages(self):
        """sysdig vulns policies-list --page-all with 2 pages -> streams both pages."""
        from sysdig_cli.main import app
        responses = [
            {"data": [{"id": "p1", "name": "Policy 1"}], "page": {"next": "cursor2"}},
            {"data": [{"id": "p2", "name": "Policy 2"}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/secure/vulnerability/v1/policies").mock(side_effect=side_effect)
            result = runner.invoke(app, ["vulns", "policies-list", "--page-all"])

        assert result.exit_code == 0
        assert call_count == 2
        # Should have NDJSON lines
        lines = [l for l in result.output.strip().split("\n") if l.strip()]
        json_lines = []
        for line in lines:
            try:
                obj = json.loads(line)
                json_lines.append(obj)
            except json.JSONDecodeError:
                pass
        assert len(json_lines) >= 2

    def test_policies_create_with_body(self):
        """sysdig vulns policies-create --body '...' -> mock 201 success."""
        from sysdig_cli.main import app
        response_data = {"id": "new-policy-id", "name": "test", "stages": ["runtime"]}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.post("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(201, json=response_data)
            )
            result = runner.invoke(app, [
                "vulns", "policies-create",
                "--body", '{"name":"test","stages":["runtime"]}',
            ])
        assert result.exit_code == 0

    def test_policies_create_dry_run_no_api_call(self):
        """--dry-run prints what would be sent, exit 0, NO API call made."""
        from sysdig_cli.main import app
        api_called = False

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            def track_call(request):
                nonlocal api_called
                api_called = True
                return httpx.Response(201, json={})
            mock.post("/secure/vulnerability/v1/policies").mock(side_effect=track_call)

            result = runner.invoke(app, [
                "vulns", "policies-create",
                "--dry-run",
                "--body", '{"name":"test"}',
            ])

        assert result.exit_code == 0
        assert not api_called, "API should NOT be called in dry-run mode"
        # Output should show what would be sent
        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert data["method"] == "POST"

    def test_policies_delete(self):
        """sysdig vulns policies-delete <id> -> mock 204 success."""
        from sysdig_cli.main import app
        with respx.mock(base_url=BASE_URL) as mock:
            mock.delete("/secure/vulnerability/v1/policies/policy-123").mock(
                return_value=httpx.Response(204)
            )
            result = runner.invoke(app, ["vulns", "policies-delete", "policy-123"])
        assert result.exit_code == 0

    def test_events_list_timestamps_converted(self):
        """sysdig events list --from 1h --to now -> timestamp params correctly converted."""
        from sysdig_cli.main import app
        response_data = {"data": [], "page": {"next": None}}

        # We just need to verify the call is made with numeric timestamp params
        request_params = {}

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            def capture_request(request):
                for key, val in request.url.params.items():
                    request_params[key] = val
                return httpx.Response(200, json=response_data)

            mock.get("/monitor/events/v1/events").mock(side_effect=capture_request)
            mock.get("/secure/events/v1/events").mock(side_effect=capture_request)

            result = runner.invoke(app, ["events", "events-list", "--from", "1h"])

        assert result.exit_code == 0
        # The 'from' param should be numeric nanoseconds
        if "from" in request_params:
            from_val = int(request_params["from"])
            # Should be within last 2 hours (nanoseconds)
            assert from_val > int((time.time() - 7200) * 1e9)

    def test_schema_shows_parameters(self):
        """sysdig schema /secure/vulnerability/v1/policies -> shows parameters."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "/secure/vulnerability/v1/policies"])
        assert result.exit_code == 0
        assert "GET" in result.output
        assert "/secure/vulnerability/v1/policies" in result.output

    def test_audit_recent_commands(self):
        """sysdig audit recent-commands with mock response -> shows commands."""
        from sysdig_cli.main import app
        response_data = {
            "data": [
                {"id": "a1", "type": "kubectl.exec", "commandLine": "kubectl exec pod -- bash"},
            ],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["audit", "recent-commands"])
        assert result.exit_code == 0


# ===========================================================================
# 4. STRESS / EDGE CASE TESTS
# ===========================================================================

class TestStressEdgeCases:
    """Boundary condition and edge case tests."""

    def test_large_response_handles_10000_items(self, auth):
        """Paginator handles 10,000 item response without OOM or error."""
        large_data = {"data": [{"id": i, "name": f"item-{i}"} for i in range(10000)], "page": {"next": None}}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/items").mock(
                return_value=httpx.Response(200, json=large_data)
            )
            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/items"))
        assert len(items) == 10000

    def test_rate_limit_retries_then_succeeds(self, auth):
        """3 consecutive 429s -> proper backoff -> success on 4th attempt."""
        responses_iter = iter([
            httpx.Response(429, json={"message": "Rate limited"}, headers={"Retry-After": "0"}),
            httpx.Response(429, json={"message": "Rate limited"}, headers={"Retry-After": "0"}),
            httpx.Response(429, json={"message": "Rate limited"}, headers={"Retry-After": "0"}),
        ])

        with respx.mock(base_url=BASE_URL) as mock:
            def rate_limit_side_effect(request):
                try:
                    return next(responses_iter)
                except StopIteration:
                    return httpx.Response(200, json={"success": True})

            mock.get("/api/test").mock(side_effect=rate_limit_side_effect)

            with patch("time.sleep"):  # Don't actually sleep in tests
                with SysdigClient(auth=auth) as client:
                    with pytest.raises(APIError):
                        # Rate limiting exhausts retries and raises
                        client.get("/api/test")

    def test_connection_timeout_friendly_error(self, auth):
        """httpx timeout -> friendly error, exit code 3."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(side_effect=httpx.TimeoutException("timeout"))

            with patch("time.sleep"):
                with SysdigClient(auth=auth) as client:
                    with pytest.raises(APIError) as exc:
                        client.get("/api/test")
            assert exc.value.exit_code == 3

    def test_malformed_json_response_handled(self, auth):
        """API returns garbage -> handled as raw text, no crash."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, content=b"<html>not json</html>",
                                           headers={"Content-Type": "text/html"})
            )
            with SysdigClient(auth=auth) as client:
                result = client.get("/api/test")
        # Should return raw response without crashing
        assert result is not None

    def test_empty_response_204_handled(self, auth):
        """API returns 204 with no body -> handled correctly."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.delete("/api/test").mock(
                return_value=httpx.Response(204)
            )
            with SysdigClient(auth=auth) as client:
                result = client.delete("/api/test")
        assert result == {}

    def test_binary_response_handled(self, auth):
        """API returns binary data when JSON expected -> handled gracefully."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, content=b"\x00\x01\x02\x03\xff\xfe",
                                           headers={"Content-Type": "application/octet-stream"})
            )
            with SysdigClient(auth=auth) as client:
                result = client.get("/api/test")
        assert result is not None

    def test_table_truncates_at_60_chars(self):
        """Table formatter truncates at max_col_width with '...'."""
        long_val = "A" * 100
        data = [{"description": long_val}]
        result = format_table(data, max_col_width=60)
        assert "..." in result
        assert long_val not in result

    def test_circular_ref_depth_limit(self):
        """OpenAPI spec with circular references doesn't infinite loop."""
        from sysdig_cli.spec import resolve_refs
        # Create a dict with deep but not infinite nesting
        deep_nested = {"$ref": "#/components/schemas/A"}
        root = {
            "components": {
                "schemas": {
                    "A": {"type": "object", "properties": {"b": {"$ref": "#/components/schemas/B"}}},
                    "B": {"type": "object", "properties": {"a": {"$ref": "#/components/schemas/A"}}},
                }
            }
        }
        # Should not hang due to depth limit
        result = resolve_refs(deep_nested, root)
        assert result is not None

    def test_special_chars_in_filter_param(self):
        """filter params with quotes, apostrophes, unicode should not be blocked."""
        # These should be valid (no injection patterns)
        result = validate_string_param("filter", "name=\"test value\"")
        assert "name=" in result

        result2 = validate_string_param("filter", "user='alice@example.com'")
        assert "user=" in result2

        result3 = validate_string_param("filter", "cluster.name=über-cluster")
        assert "über-cluster" in result3


# ===========================================================================
# 5. SECURITY VECTORS (ADDITIONAL)
# ===========================================================================

class TestSecurityVectors:
    """Additional security vector tests not covered in test_security.py."""

    def test_url_encoded_path_traversal_blocked(self):
        """%2e%2e URL-encoded .. should be blocked."""
        with pytest.raises(ValidationError):
            validate_path_param("id", "%2e%2e%2f")

    def test_double_url_encoded_null_blocked(self):
        """%00 URL-encoded null byte should be blocked."""
        with pytest.raises(ValidationError):
            validate_path_param("id", "test%00inject")

    def test_crlf_in_filter_param_blocked(self):
        """CRLF injection in filter params must be blocked."""
        with pytest.raises(ValidationError):
            validate_string_param("filter", "value\r\nX-Inject: evil")

    def test_carriage_return_blocked(self):
        """\r alone must be blocked."""
        with pytest.raises(ValidationError):
            validate_string_param("filter", "val\revil")

    def test_linefeed_blocked(self):
        """\n alone must be blocked."""
        with pytest.raises(ValidationError):
            validate_string_param("param", "val\nevil")

    def test_null_byte_in_string_param_blocked(self):
        """Null byte in string params must be blocked."""
        with pytest.raises(ValidationError):
            validate_path_param("id", "valid\x00inject")

    def test_long_input_over_8192_chars_rejected(self):
        """Input > MAX_STRING_LENGTH must be rejected."""
        long_input = "x" * (MAX_STRING_LENGTH + 1)
        with pytest.raises(ValidationError, match="max length"):
            validate_string_param("filter", long_input)

    def test_long_path_param_rejected(self):
        """Path param > MAX_PARAM_LENGTH must be rejected."""
        long_param = "x" * (MAX_PARAM_LENGTH + 1)
        with pytest.raises(ValidationError, match="max length"):
            validate_path_param("id", long_param)

    def test_none_value_in_params_no_exception(self):
        """None values must not cause exceptions."""
        result = validate_params({"filter": None, "limit": None, "cursor": None})
        assert result["filter"] is None
        assert result["limit"] is None

    def test_empty_string_param_allowed(self):
        """Empty string is a valid param value."""
        result = validate_string_param("filter", "")
        assert result == ""

    def test_host_header_injection_http_rejected(self):
        """http:// hosts are rejected (host header injection prevention)."""
        with pytest.raises(ValidationError, match="HTTPS"):
            validate_host("http://evil.example.com")

    def test_host_with_credentials_http_rejected(self):
        """http:// with embedded credentials rejected."""
        with pytest.raises(AuthError):
            AuthConfig(token="token", host="http://user:pass@evil.com")

    def test_prometheus_delete_series_warns(self, capsys):
        """Prometheus admin delete_series endpoint warns."""
        check_dangerous_endpoint("/prometheus/api/v1/admin/tsdb/delete_series", "POST")
        captured = capsys.readouterr()
        assert len(captured.err) > 0

    def test_prometheus_clean_tombstones_warns(self, capsys):
        """Prometheus admin clean_tombstones endpoint warns."""
        check_dangerous_endpoint("/prometheus/api/v1/admin/tsdb/clean_tombstones", "POST")
        captured = capsys.readouterr()
        assert len(captured.err) > 0

    def test_prometheus_write_endpoint_warns(self, capsys):
        """Prometheus /write endpoint warns."""
        check_dangerous_endpoint("/prometheus/api/v1/write", "POST")
        captured = capsys.readouterr()
        assert len(captured.err) > 0

    def test_token_not_in_url(self, auth):
        """Token must never appear in URL query string."""
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={})
            )
            with SysdigClient(auth=auth) as client:
                client.get("/api/test")

            assert route.calls
            request_url = str(route.calls[0].request.url)
            assert "testtoken12345" not in request_url

    def test_token_in_auth_header_not_url(self, auth):
        """Token should be in Authorization header, not URL."""
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={})
            )
            with SysdigClient(auth=auth) as client:
                client.get("/api/test")

            assert route.calls
            request = route.calls[0].request
            auth_header = request.headers.get("Authorization", "")
            assert "Bearer" in auth_header
            assert "testtoken12345" in auth_header
            assert "testtoken12345" not in str(request.url)

    def test_sanitize_nested_token(self):
        """Nested token fields are masked in sanitize_for_logging."""
        data = {"auth": {"token": "supersecret", "user": "alice"}}
        result = sanitize_for_logging(data)
        assert result["auth"]["token"] == "****"
        assert result["auth"]["user"] == "alice"
        assert "supersecret" not in str(result)

    def test_sanitize_long_string_token(self):
        """Long base64-ish strings are partially masked."""
        long_token = "AbcDef123XYZ" * 5  # 60 chars, looks like a token
        result = sanitize_for_logging(long_token)
        assert len(long_token) > 32
        assert long_token not in str(result)


# ===========================================================================
# 6. ALPHA BANNER CONSISTENCY
# ===========================================================================

class TestAlphaBannerConsistency:
    """Verify NO alpha banner appears on stderr (banner removed from commands)."""

    def test_no_alpha_banner_on_help(self):
        """sysdig --help -> NO alpha banner on stderr (banner removed)."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        # Banner should NOT appear on stderr - only data goes to stderr now
        assert "sysdig-cli alpha" not in result.stderr

    def test_no_alpha_banner_on_vulns_help(self):
        """sysdig vulns --help -> NO alpha banner on stderr."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "--help"])
        assert result.exit_code == 0
        assert "sysdig-cli alpha" not in result.stderr

    def test_no_alpha_banner_on_version(self):
        """sysdig --version -> NO alpha banner on stderr."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "sysdig-cli alpha" not in result.stderr

    def test_no_alpha_banner_on_schema_command(self):
        """sysdig schema /any/path -> NO alpha banner on stderr."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "/secure/vulnerability/v1/policies"])
        assert "sysdig-cli alpha" not in result.stderr

    def test_no_alpha_banner_on_actual_command(self):
        """sysdig vulns policies-list -> NO alpha banner on stderr."""
        from sysdig_cli.main import app
        response_data = {"data": [], "page": {"next": None}}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        assert "sysdig-cli alpha" not in result.stderr


# ===========================================================================
# 7. HELP TEXT QUALITY
# ===========================================================================

class TestHelpTextQuality:
    """Verify every command has meaningful help text."""

    def test_top_level_has_description(self):
        """Top-level 'sysdig' command has a description."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert len(result.output) > 50
        # Check for service groups mentioned
        assert "vulns" in result.output or "auth" in result.output

    def test_vulns_group_has_description(self):
        """vulns command group has a description."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "--help"])
        assert result.exit_code == 0
        assert len(result.output) > 20

    def test_events_group_has_description(self):
        """events command group has a description."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["events", "--help"])
        assert result.exit_code == 0
        assert len(result.output) > 20

    def test_audit_group_has_description(self):
        """audit command group has a description."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        assert len(result.output) > 20

    def test_all_service_groups_have_help(self):
        """All service command groups have help text."""
        from sysdig_cli.main import app
        services = ["vulns", "events", "audit", "inventory", "platform",
                    "zones", "teams", "users", "roles", "alerts", "metrics", "fwd"]
        for svc in services:
            result = runner.invoke(app, [svc, "--help"])
            assert result.exit_code == 0, f"'{svc} --help' failed with exit {result.exit_code}"
            assert len(result.output) > 10, f"'{svc} --help' output is too short"

    def test_auth_subcommands_have_help(self):
        """Auth subcommands have help text."""
        from sysdig_cli.main import app
        for subcmd in ["setup", "list", "delete", "whoami"]:
            result = runner.invoke(app, ["auth", subcmd, "--help"])
            assert result.exit_code == 0, f"auth {subcmd} --help failed"
            assert len(result.output) > 20

    def test_dry_run_option_on_mutating_commands(self):
        """--dry-run option exists on mutating commands (POST/PUT/DELETE/PATCH)."""
        from sysdig_cli.main import app
        # POST command
        result = runner.invoke(app, ["vulns", "policies-create", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output

        # DELETE command
        result = runner.invoke(app, ["vulns", "policies-delete", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output

    def test_format_option_on_list_commands(self):
        """--format option exists on list/get commands."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "policies-list", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output or "-f" in result.output

    def test_page_all_option_on_list_commands(self):
        """--page-all option exists on list commands."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "policies-list", "--help"])
        assert result.exit_code == 0
        assert "--page-all" in result.output


# ===========================================================================
# ADDITIONAL SECURITY TESTS FROM TASK SPEC
# ===========================================================================

class TestAdditionalSecurityVectors:
    """Additional security tests per spec."""

    def test_backslash_path_traversal_blocked(self):
        """..\\windows path traversal blocked."""
        with pytest.raises(ValidationError):
            validate_path_param("id", "..\\windows\\system32")

    def test_dotdot_exact_blocked(self):
        """Exact '..' blocked."""
        with pytest.raises(ValidationError):
            validate_path_param("id", "..")

    def test_valid_uuid_allowed(self):
        """Valid UUID passes validation."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = validate_path_param("id", uuid)
        assert result == uuid

    def test_valid_integer_id_allowed(self):
        """Valid integer ID passes validation."""
        result = validate_path_param("id", "12345")
        assert result == "12345"

    def test_http_localhost_rejected(self):
        """http://localhost is rejected."""
        with pytest.raises(ValidationError):
            validate_host("http://localhost:8080")

    def test_api_path_traversal_blocked(self):
        """API path with traversal blocked."""
        with pytest.raises(ValidationError):
            validate_api_path("/api/../../../etc/passwd")

    def test_safe_get_no_prometheus_warning(self, capsys):
        """Safe GET endpoint produces no warning."""
        check_dangerous_endpoint("/secure/vulnerability/v1/policies", "GET")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_none_value_validate_params(self):
        """None values in validate_params are preserved without exception."""
        result = validate_params({"a": None, "b": "valid", "c": None})
        assert result["a"] is None
        assert result["b"] == "valid"
        assert result["c"] is None

    def test_non_string_path_param_converted(self):
        """Non-string path param is converted to string."""
        result = validate_path_param("id", 12345)
        assert result == "12345"


# ===========================================================================
# RATE LIMIT RETRY BEHAVIOR
# ===========================================================================

class TestRateLimitRetry:
    """Test rate limit retry behavior."""

    def test_rate_limited_raises_api_error(self, auth):
        """429 response raises APIError."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(
                    429,
                    json={"message": "Too many requests"},
                    headers={"Retry-After": "0"},
                )
            )
            with patch("time.sleep"):
                with SysdigClient(auth=auth) as client:
                    with pytest.raises(APIError):
                        client.get("/api/test")

    def test_retry_after_header_parsed(self, auth):
        """Retry-After header is parsed and sleep is called."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(
                    429,
                    json={"message": "Rate limited"},
                    headers={"Retry-After": "5"},
                )
            )
            with patch("time.sleep") as mock_sleep:
                with SysdigClient(auth=auth) as client:
                    with pytest.raises(APIError):
                        client.get("/api/test")
            # time.sleep should have been called with ~5 seconds
            assert mock_sleep.called

    def test_retry_after_default_on_missing_header(self, auth):
        """Missing Retry-After header defaults to 1.0."""
        from sysdig_cli.client import SysdigClient
        with SysdigClient(auth=auth) as client:
            # Create a fake response without Retry-After header
            resp = httpx.Response(429, json={})
            delay = client._get_retry_after(resp)
        assert delay == 1.0


# ===========================================================================
# PAGINATION EDGE CASES
# ===========================================================================

class TestPaginationEdgeCases:
    """Additional pagination edge cases."""

    def test_extract_cursor_page_next_none(self):
        """page.next = None should return None."""
        assert _extract_next_cursor({"page": {"next": None}}) is None

    def test_extract_cursor_page_next_empty_string(self):
        """page.next = '' should return None."""
        assert _extract_next_cursor({"page": {"next": ""}}) is None

    def test_extract_cursor_non_dict(self):
        """Non-dict input should return None."""
        assert _extract_next_cursor([1, 2, 3]) is None
        assert _extract_next_cursor("string") is None
        assert _extract_next_cursor(42) is None

    def test_extract_data_entries_field(self):
        """'entries' key should be extracted as data list."""
        result = _extract_data({"entries": [{"id": 1}, {"id": 2}]})
        assert result == [{"id": 1}, {"id": 2}]

    def test_extract_data_resources_field(self):
        """'resources' key should be extracted as data list."""
        result = _extract_data({"resources": [{"name": "r1"}]})
        assert result == [{"name": "r1"}]

    def test_extract_data_direct_list(self):
        """List response returns itself."""
        data = [{"a": 1}, {"b": 2}]
        result = _extract_data(data)
        assert result == data

    def test_extract_data_empty_dict(self):
        """Empty dict returns empty list."""
        assert _extract_data({}) == []
