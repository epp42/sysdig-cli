"""
Comprehensive unit tests for core modules:
- sysdig_cli/paginator.py
- sysdig_cli/timestamps.py
- sysdig_cli/commands.py (and schema_cmd.py)
- sysdig_cli/main.py (CLI integration)

All tests are NEW — they do NOT duplicate test_comprehensive.py,
test_paginator.py, or test_commands.py.
"""
from __future__ import annotations

import io
import json
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, call

import httpx
import pytest
import respx
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import SysdigClient
from sysdig_cli.paginator import (
    _extract_next_cursor,
    _extract_data,
    paginate_all_items,
    stream_ndjson,
)
from sysdig_cli.timestamps import (
    now_ns,
    parse_timestamp,
    unix_to_ns,
    ns_to_unix,
    ns_to_datetime,
    format_ns,
)

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken", host=BASE_URL)


# ===========================================================================
# paginator.py — new tests
# ===========================================================================


class TestExtractNextCursorNew:
    """Covers cursor extraction patterns not already tested in test_paginator.py."""

    def test_page_cursor_field(self):
        """Pattern: response.page.cursor (not .page.next)."""
        response = {"page": {"cursor": "next-page-cursor", "returned": 5}}
        # .page.next takes priority; if absent, falls to top-level cursor
        # page dict exists but no 'next' key → page.get('next') returns None → None
        assert _extract_next_cursor(response) is None

    def test_top_level_cursor_pattern(self):
        """Pattern 2: response.cursor field."""
        response = {"cursor": "cursor-abc", "data": [1, 2]}
        assert _extract_next_cursor(response) == "cursor-abc"

    def test_next_cursor_camelcase(self):
        """Pattern 3: response.nextCursor camelCase field."""
        response = {"nextCursor": "nc-xyz", "results": []}
        assert _extract_next_cursor(response) == "nc-xyz"

    def test_empty_string_cursor_returns_none(self):
        """An empty string cursor should stop pagination."""
        # top-level cursor field, empty string
        response = {"cursor": ""}
        assert _extract_next_cursor(response) is None

    def test_null_next_cursor(self):
        """nextCursor explicitly null → None."""
        response = {"nextCursor": None}
        assert _extract_next_cursor(response) is None

    def test_empty_next_cursor_string(self):
        """nextCursor empty string → None (falsy check)."""
        response = {"nextCursor": ""}
        assert _extract_next_cursor(response) is None

    def test_missing_cursor_all_patterns_absent(self):
        """No cursor of any kind present."""
        response = {"total": 100, "items": [1, 2, 3]}
        assert _extract_next_cursor(response) is None

    def test_page_dict_but_next_missing(self):
        """page dict exists but has no 'next' key → returns None."""
        response = {"page": {"prev": "prev-cursor"}}
        assert _extract_next_cursor(response) is None


class TestPaginateAllItemsCursorExclusiveKeys:
    """Tests cursor_exclusive_keys behaviour in paginate_all_items."""

    def test_from_to_dropped_on_cursor_pages(self, auth):
        """After first page, 'from' and 'to' keys must be removed from params."""
        pages = [
            {"data": [{"id": 1}], "page": {"next": "cursor2"}},
            {"data": [{"id": 2}], "page": {"next": None}},
        ]
        call_count = 0
        captured_params: List[str] = []

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                captured_params.append(str(request.url.query))
                resp = pages[min(call_count, len(pages) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/events").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                items = list(
                    paginate_all_items(
                        client,
                        "GET",
                        "/api/events",
                        params={"from": 1000, "to": 2000},
                        cursor_exclusive_keys=["from", "to"],
                    )
                )

        assert len(items) == 2
        assert call_count == 2
        # First call should include from/to
        assert "from" in captured_params[0] or "1000" in captured_params[0]
        # Second call should NOT include from/to
        assert "from" not in captured_params[1]
        assert "to" not in captured_params[1]
        # Second call should include the cursor
        assert "cursor2" in captured_params[1]

    def test_multi_page_real_cursor_progression(self, auth):
        """Cursors progress correctly across 3 pages."""
        pages = [
            {"data": [{"n": 0}, {"n": 1}], "page": {"next": "page2cursor"}},
            {"data": [{"n": 2}, {"n": 3}], "page": {"next": "page3cursor"}},
            {"data": [{"n": 4}], "page": {"next": None}},
        ]
        call_count = 0
        captured_cursors: List[str] = []

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                captured_cursors.append(
                    str(request.url.params.get("cursor", ""))
                )
                resp = pages[min(call_count, len(pages) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/items").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                items = list(
                    paginate_all_items(client, "GET", "/api/items")
                )

        assert len(items) == 5
        assert items[0] == {"n": 0}
        assert items[4] == {"n": 4}
        # First request has no cursor
        assert captured_cursors[0] == ""
        # Second request has page2cursor
        assert captured_cursors[1] == "page2cursor"
        # Third request has page3cursor
        assert captured_cursors[2] == "page3cursor"

    def test_stops_when_cursor_is_empty_string(self, auth):
        """Pagination stops when next cursor is empty string."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(
                    200,
                    json={"data": [{"id": 1}], "page": {"next": ""}},
                )
            )
            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/test"))

        # Only one page should have been fetched (empty cursor stops)
        assert items == [{"id": 1}]

    def test_stops_when_cursor_is_null(self, auth):
        """Pagination stops when next cursor is null."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(
                    200,
                    json={"data": [{"id": 99}], "page": {"next": None}},
                )
            )
            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/test"))

        assert items == [{"id": 99}]

    def test_post_method_pagination(self, auth):
        """POST-based pagination yields items correctly."""
        pages = [
            {"results": [{"a": 1}], "nextCursor": "nc1"},
            {"results": [{"a": 2}], "nextCursor": None},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = pages[min(call_count, 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.post("/api/query").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                items = list(
                    paginate_all_items(
                        client,
                        "POST",
                        "/api/query",
                        json_body={"q": "test"},
                    )
                )

        assert len(items) == 2
        assert call_count == 2


class TestStreamNdjsonEdgeCases:
    """New stream_ndjson edge cases."""

    def test_writes_to_custom_file(self, auth):
        """stream_ndjson accepts a file= argument and writes there."""
        buf = io.StringIO()
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/data").mock(
                return_value=httpx.Response(
                    200,
                    json={"data": [{"x": 1}, {"x": 2}], "page": {"next": None}},
                )
            )
            with SysdigClient(auth=auth) as client:
                count = stream_ndjson(
                    client, "GET", "/api/data", file=buf
                )

        assert count == 2
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"x": 1}
        assert json.loads(lines[1]) == {"x": 2}

    def test_returns_zero_on_empty_response(self, auth):
        """stream_ndjson returns 0 when no items are present."""
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/empty").mock(
                return_value=httpx.Response(
                    200, json={"data": [], "page": {"next": None}}
                )
            )
            buf = io.StringIO()
            with SysdigClient(auth=auth) as client:
                count = stream_ndjson(client, "GET", "/api/empty", file=buf)

        assert count == 0
        assert buf.getvalue() == ""

    def test_generator_raises_midway(self, auth):
        """If the HTTP call raises midway, stream_ndjson propagates the error."""
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return httpx.Response(
                        200,
                        json={"data": [{"id": 1}], "page": {"next": "c2"}},
                    )
                # Simulate network failure on second page
                raise httpx.NetworkError("Connection refused")

            mock.get("/api/stream").mock(side_effect=side_effect)

            buf = io.StringIO()
            with SysdigClient(auth=auth) as client:
                with pytest.raises(httpx.NetworkError):
                    stream_ndjson(client, "GET", "/api/stream", file=buf)

    def test_serializes_non_standard_values_via_default_str(self, auth):
        """stream_ndjson uses default=str so items with non-JSON-native types
        are serialised without raising TypeError.  We inject a mock item that
        contains a set (not JSON-native) directly via paginate_all_items."""
        buf = io.StringIO()

        # Patch paginate_all_items to yield an item containing a set
        class _NonSerializable:
            def __str__(self):
                return "custom-obj"

        non_std_item = {"key": _NonSerializable()}

        with patch(
            "sysdig_cli.paginator.paginate_all_items",
            return_value=iter([non_std_item]),
        ):
            with SysdigClient(auth=auth) as client:
                count = stream_ndjson(client, "GET", "/api/nonstd", file=buf)

        assert count == 1
        line = buf.getvalue().strip()
        parsed = json.loads(line)
        assert parsed["key"] == "custom-obj"


# ===========================================================================
# timestamps.py — new tests
# ===========================================================================


class TestNowNs:
    def test_returns_int(self):
        result = now_ns()
        assert isinstance(result, int)

    def test_in_nanosecond_range(self):
        """Result must be larger than 1e18 (nanoseconds since 2001+)."""
        result = now_ns()
        assert result > int(1e18), f"Expected > 1e18, got {result}"

    def test_monotonically_non_decreasing(self):
        """Two successive calls should not go backwards."""
        t1 = now_ns()
        t2 = now_ns()
        assert t2 >= t1


class TestParseTimestampRelative:
    """Relative time formats: Nh, Nm, Nd, Nw."""

    def _approx_ns_ago(self, seconds: float, tolerance: float = 2.0) -> int:
        """Expected nanosecond timestamp `seconds` ago, with tolerance."""
        return int((time.time() - seconds) * 1e9)

    def test_1h_returns_int(self):
        result = parse_timestamp("1h")
        assert isinstance(result, int)

    def test_1h_approximately_one_hour_ago(self):
        before = self._approx_ns_ago(3600)
        result = parse_timestamp("1h")
        after = self._approx_ns_ago(3600)
        # result should be within 3 seconds of 1h ago
        assert abs(result - before) < int(3e9)

    def test_30m_approximately_30min_ago(self):
        expected = self._approx_ns_ago(1800)
        result = parse_timestamp("30m")
        assert abs(result - expected) < int(3e9)

    def test_7d_approximately_7days_ago(self):
        expected = self._approx_ns_ago(7 * 86400)
        result = parse_timestamp("7d")
        assert abs(result - expected) < int(3e9)

    def test_2w_approximately_14days_ago(self):
        expected = self._approx_ns_ago(14 * 86400)
        result = parse_timestamp("2w")
        assert abs(result - expected) < int(3e9)

    def test_0h_is_approximately_now(self):
        """0h means zero seconds ago → essentially now."""
        before = now_ns()
        result = parse_timestamp("0h")
        after = now_ns()
        assert before <= result <= after + int(1e9)

    def test_large_value_24h(self):
        result = parse_timestamp("24h")
        assert isinstance(result, int)
        assert result > 0

    def test_case_insensitive_uppercase_H(self):
        r1 = parse_timestamp("1h")
        r2 = parse_timestamp("1H")
        # Both valid; values should be within a second of each other
        assert abs(r1 - r2) < int(2e9)


class TestParseTimestampISO8601:
    def test_utc_z_suffix(self):
        result = parse_timestamp("2024-01-15T10:00:00Z")
        assert isinstance(result, int)
        assert result > 0
        # 2024-01-15T10:00:00Z = 1705312800 seconds
        expected = unix_to_ns(1705312800)
        assert abs(result - expected) < int(1e9)

    def test_timezone_offset_plus_02(self):
        """2024-01-15T12:00:00+02:00 == 2024-01-15T10:00:00Z."""
        result_z = parse_timestamp("2024-01-15T10:00:00Z")
        result_tz = parse_timestamp("2024-01-15T12:00:00+02:00")
        assert abs(result_z - result_tz) < int(1e9)

    def test_returns_int(self):
        result = parse_timestamp("2024-06-01T00:00:00Z")
        assert isinstance(result, int)

    def test_iso_date_only(self):
        """Date-only string like '2024-01-15'."""
        result = parse_timestamp("2024-01-15")
        assert isinstance(result, int)
        assert result > 0


class TestParseTimestampUnixValues:
    def test_unix_seconds(self):
        """Plain integer treated as unix seconds when < 1e12."""
        result = parse_timestamp("1705312800")
        expected = unix_to_ns(1705312800)
        assert result == expected

    def test_unix_nanoseconds_passthrough(self):
        """Value > 1e18 treated as already-nanoseconds."""
        ns_val = 1705312800_000_000_000
        result = parse_timestamp(str(ns_val))
        assert result == ns_val

    def test_unix_milliseconds_range(self):
        """Value > 1e12 but < 1e18 treated as milliseconds."""
        ms_val = 1705312800_000  # milliseconds
        result = parse_timestamp(str(ms_val))
        # Should be converted: ms * 1e6
        expected = ms_val * int(1e6)
        assert result == expected


class TestParseTimestampEdgeCases:
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Empty timestamp"):
            parse_timestamp("")

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            parse_timestamp("not-a-timestamp")

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace should be handled gracefully."""
        result = parse_timestamp("  1h  ")
        assert isinstance(result, int)


# ===========================================================================
# commands.py — new tests
# ===========================================================================


class TestGetOperationsForServiceNew:
    """Checks not covered in test_commands.py: specific services + field check."""

    def test_vulns_operations_non_empty(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("vulns")
        assert len(ops) > 0

    def test_events_operations_non_empty(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("events")
        assert len(ops) > 0

    def test_audit_operations_non_empty(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("audit")
        assert len(ops) > 0

    def test_users_operations_non_empty(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("users")
        assert len(ops) > 0

    def test_each_operation_has_method(self):
        from sysdig_cli.spec import get_operations_for_service
        for svc in ("vulns", "events", "audit", "users"):
            ops = get_operations_for_service(svc)
            for op in ops:
                assert "method" in op, f"Missing 'method' in op for {svc}: {op}"

    def test_each_operation_has_path(self):
        from sysdig_cli.spec import get_operations_for_service
        for svc in ("vulns", "events", "audit", "users"):
            ops = get_operations_for_service(svc)
            for op in ops:
                assert "path" in op, f"Missing 'path' in op for {svc}: {op}"

    def test_each_operation_has_summary(self):
        from sysdig_cli.spec import get_operations_for_service
        for svc in ("vulns", "events", "audit", "users"):
            ops = get_operations_for_service(svc)
            for op in ops:
                assert "summary" in op, f"Missing 'summary' in op for {svc}: {op}"


class TestBuildServiceAppNew:
    """build_service_app tests beyond those in test_commands.py."""

    def test_events_app_created(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("events")
        assert isinstance(app, typer.Typer)

    def test_audit_app_created(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("audit")
        assert isinstance(app, typer.Typer)

    def test_users_app_created(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("users")
        assert isinstance(app, typer.Typer)

    def test_no_duplicate_commands_events(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("events")
        cmd = typer.main.get_command(app)
        names = list(cmd.commands.keys())
        assert len(names) == len(set(names)), "Duplicate command names in events app"

    def test_no_duplicate_commands_audit(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("audit")
        cmd = typer.main.get_command(app)
        names = list(cmd.commands.keys())
        assert len(names) == len(set(names)), "Duplicate command names in audit app"

    def test_no_duplicate_commands_users(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("users")
        cmd = typer.main.get_command(app)
        names = list(cmd.commands.keys())
        assert len(names) == len(set(names)), "Duplicate command names in users app"

    def test_vulns_app_has_multiple_commands(self):
        import typer
        from sysdig_cli.commands import build_service_app
        app = build_service_app("vulns")
        cmd = typer.main.get_command(app)
        assert len(cmd.commands) >= 5

    def test_get_method_generates_list_verb_no_id(self):
        """GET on a collection path generates a command with 'list' in name."""
        from sysdig_cli.commands import _path_to_subcommand
        name = _path_to_subcommand("/platform/v1/users", "get", "users")
        assert "list" in name

    def test_get_method_with_id_generates_get_verb(self):
        """GET on a resource path generates a command with 'get' in name."""
        from sysdig_cli.commands import _path_to_subcommand
        name = _path_to_subcommand("/platform/v1/users/{userId}", "get", "users")
        assert "get" in name

    def test_post_generates_create_verb(self):
        """POST generates a command with 'create' in name."""
        from sysdig_cli.commands import _path_to_subcommand
        name = _path_to_subcommand("/platform/v1/users", "post", "users")
        assert "create" in name

    def test_delete_generates_delete_verb(self):
        """DELETE generates a command with 'delete' in name."""
        from sysdig_cli.commands import _path_to_subcommand
        name = _path_to_subcommand("/platform/v1/users/{userId}", "delete", "users")
        assert "delete" in name


# ===========================================================================
# main.py — CLI integration tests
# ===========================================================================


class TestTopLevelHelp:
    """Top-level --help shows expected sub-commands."""

    def _get_help_output(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        return result.output

    def test_help_exit_code_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_help_shows_events(self):
        output = self._get_help_output()
        assert "events" in output

    def test_help_shows_audit(self):
        output = self._get_help_output()
        assert "audit" in output

    def test_help_shows_vulns(self):
        output = self._get_help_output()
        assert "vulns" in output

    def test_help_shows_users(self):
        output = self._get_help_output()
        assert "users" in output

    def test_help_shows_iam(self):
        output = self._get_help_output()
        assert "iam" in output

    def test_help_shows_alerts(self):
        output = self._get_help_output()
        assert "alerts" in output

    def test_help_shows_inventory(self):
        output = self._get_help_output()
        assert "inventory" in output

    def test_help_shows_cost(self):
        output = self._get_help_output()
        assert "cost" in output


class TestVersionFlag:
    def test_version_exit_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_contains_sysdig_cli(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["--version"])
        assert "sysdig-cli" in result.output

    def test_version_short_flag(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert "sysdig-cli" in result.output


class TestEventsSubcommands:
    def _events_help(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["events", "--help"])
        assert result.exit_code == 0
        return result.output

    def test_events_help_exit_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["events", "--help"])
        assert result.exit_code == 0

    def test_events_help_shows_list(self):
        output = self._events_help()
        assert "list" in output

    def test_events_help_shows_tail(self):
        output = self._events_help()
        assert "tail" in output

    def test_events_help_shows_hunt(self):
        output = self._events_help()
        assert "hunt" in output

    def test_events_help_shows_id(self):
        output = self._events_help()
        assert "id" in output


class TestAuditSubcommands:
    def _audit_help(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        return result.output

    def test_audit_help_exit_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0

    def test_audit_help_shows_platform_events(self):
        output = self._audit_help()
        assert "platform-events" in output

    def test_audit_help_shows_recent_commands(self):
        output = self._audit_help()
        assert "recent-commands" in output


class TestVulnsSubcommands:
    def _vulns_help(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "--help"])
        assert result.exit_code == 0
        return result.output

    def test_vulns_help_exit_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["vulns", "--help"])
        assert result.exit_code == 0

    def test_vulns_help_shows_list(self):
        output = self._vulns_help()
        assert "list" in output

    def test_vulns_help_shows_overview(self):
        output = self._vulns_help()
        assert "overview" in output

    def test_vulns_help_shows_id(self):
        output = self._vulns_help()
        assert "id" in output

    def test_vulns_help_shows_new(self):
        output = self._vulns_help()
        assert "new" in output

    def test_vulns_help_shows_reachable(self):
        output = self._vulns_help()
        assert "reachable" in output

    def test_vulns_help_shows_accept_risks(self):
        output = self._vulns_help()
        assert "accept-risks" in output


class TestIamSubcommands:
    def _iam_help(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["iam", "--help"])
        assert result.exit_code == 0
        return result.output

    def test_iam_help_exit_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["iam", "--help"])
        assert result.exit_code == 0

    def test_iam_help_shows_access_keys(self):
        output = self._iam_help()
        assert "access-keys" in output

    def test_iam_help_shows_roles(self):
        output = self._iam_help()
        assert "roles" in output

    def test_iam_help_shows_group_mappings(self):
        output = self._iam_help()
        assert "group-mappings" in output

    def test_iam_help_shows_sso_settings(self):
        output = self._iam_help()
        assert "sso-settings" in output


class TestExitCodes:
    """Exit code semantics: auth failure → 2, forbidden → 5."""

    def test_auth_failure_exits_2(self):
        """When auth config is missing/invalid, exit code is 2."""
        from sysdig_cli.main import app
        from sysdig_cli.auth import AuthError

        with patch("sysdig_cli.commands.resolve_auth", side_effect=AuthError("bad config")):
            result = runner.invoke(app, ["vulns", "runtime-results-list"])
        assert result.exit_code == 2

    def test_forbidden_exits_5(self):
        """ForbiddenError from the API yields exit code 5."""
        from sysdig_cli.main import app
        from sysdig_cli.auth import AuthConfig
        from sysdig_cli.client import ForbiddenError

        mock_auth = AuthConfig(token="tok", host=BASE_URL)

        with patch("sysdig_cli.commands.resolve_auth", return_value=mock_auth):
            with patch("sysdig_cli.commands.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.request.side_effect = ForbiddenError("Forbidden")
                result = runner.invoke(app, ["vulns", "runtime-results-list"])

        assert result.exit_code == 5


# ===========================================================================
# schema_cmd.py — new tests
# ===========================================================================


class TestSchemaList:
    """schema list outputs API path lines."""

    def test_schema_list_exits_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "list"])
        assert result.exit_code == 0

    def test_schema_list_contains_paths(self):
        """Output should contain API paths starting with '/'."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "list"])
        assert "/" in result.output

    def test_schema_list_with_prefix_filter(self):
        """schema list /platform should only show /platform paths."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "list", "/platform"])
        assert result.exit_code == 0
        # Every path line should contain /platform
        for line in result.output.splitlines():
            line = line.strip()
            if line and not line.startswith("Total:"):
                assert "/platform" in line, f"Unexpected path in filtered output: {line}"

    def test_schema_list_shows_http_methods(self):
        """Each line should show HTTP methods (GET, POST, etc.)."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "list"])
        output = result.output
        assert any(m in output for m in ("GET", "POST", "PUT", "DELETE"))


class TestSchemaShow:
    def test_schema_show_known_path_exits_zero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/platform/v1/users"])
        assert result.exit_code == 0

    def test_schema_show_displays_path(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/platform/v1/users"])
        assert "/platform/v1/users" in result.output

    def test_schema_show_displays_summary(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/platform/v1/users"])
        assert "Summary" in result.output

    def test_schema_show_unknown_path_exits_nonzero(self):
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/totally/unknown/endpoint"])
        assert result.exit_code != 0

    def test_schema_show_unknown_path_exit_code_4(self):
        """Unknown path exits with code 4 (not found)."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/totally/unknown/endpoint"])
        assert result.exit_code == 4

    def test_schema_show_json_format(self):
        """schema show --format json emits valid JSON."""
        from sysdig_cli.main import app
        result = runner.invoke(
            app, ["schema", "show", "/platform/v1/users", "--format", "json"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_schema_show_columns_for_known_path(self):
        """Text output for a known path includes field names."""
        from sysdig_cli.main import app
        result = runner.invoke(app, ["schema", "show", "/platform/v1/users"])
        # Should include at least Summary and Operation ID labels
        assert "Summary" in result.output or "Parameters" in result.output


class TestDisplaySchemas:
    """Validate DISPLAY_SCHEMAS registry."""

    def test_display_schemas_contains_vulns_runtime(self):
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        assert "vulns_runtime" in DISPLAY_SCHEMAS

    def test_display_schemas_contains_events(self):
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        assert "events" in DISPLAY_SCHEMAS

    def test_display_schemas_contains_audit(self):
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        assert "audit" in DISPLAY_SCHEMAS

    def test_display_schemas_contains_users(self):
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        assert "users" in DISPLAY_SCHEMAS

    def test_display_schemas_non_empty_columns(self):
        """Every schema entry should have at least one column."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        for name, cols in DISPLAY_SCHEMAS.items():
            assert len(cols) > 0, f"Schema {name!r} has no columns"

    def test_display_schema_columns_are_triples(self):
        """Each column should be a 3-tuple: (field, header, width)."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        for name, cols in DISPLAY_SCHEMAS.items():
            for col in cols:
                assert len(col) == 3, (
                    f"Schema {name!r} column {col!r} is not a triple"
                )
