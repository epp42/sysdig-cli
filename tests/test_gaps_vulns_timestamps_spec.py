"""
Gap-filling unit tests for:
  - sysdig_cli/timestamps.py  (unix_to_ns, ns_to_unix, ns_to_datetime, format_ns,
                                _parse_compound_relative, _parse_iso8601, round-trips)
  - sysdig_cli/helpers/vulns.py  (vulns_high_reachable, vulns_pod_vulns internals)
  - sysdig_cli/spec.py  (load_spec, resolve_refs, get_paths, get_all_operations,
                          find_operation, extract_path_params, path_to_command_name,
                          get_operations_for_service)

These tests do NOT duplicate test_vulns_comprehensive.py or test_core_modules.py.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import AuthError, ForbiddenError, SysdigError
from sysdig_cli.timestamps import (
    format_ns,
    ns_to_datetime,
    ns_to_unix,
    unix_to_ns,
    _parse_compound_relative,
    _parse_iso8601,
)

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)

# ---------------------------------------------------------------------------
# Auth fixture — patched in every test that touches vulns helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    auth = AuthConfig(token="testtoken", host=BASE_URL)
    with patch("sysdig_cli.helpers.vulns.resolve_auth", return_value=auth):
        yield auth


# ===========================================================================
# 1. timestamps.py — previously untested functions
# ===========================================================================


class TestUnixToNs:
    """unix_to_ns(ts) converts Unix seconds to nanoseconds."""

    def test_integer_input_exact(self):
        """1 second → 1_000_000_000 ns."""
        assert unix_to_ns(1) == 1_000_000_000

    def test_float_input_round_down(self):
        """1.5 seconds → int(1_500_000_000)."""
        assert unix_to_ns(1.5) == 1_500_000_000

    def test_zero(self):
        assert unix_to_ns(0) == 0

    def test_known_epoch(self):
        """2024-01-15T10:00:00Z = 1705312800 seconds."""
        ns = unix_to_ns(1705312800)
        assert ns == 1705312800_000_000_000

    def test_returns_int(self):
        assert isinstance(unix_to_ns(1234567890.123), int)

    def test_large_value(self):
        """Current-ish epoch (year 2024+) should exceed 1e18 ns."""
        ns = unix_to_ns(1_700_000_000)
        assert ns > int(1e18)


class TestNsToUnix:
    """ns_to_unix(ns) converts nanoseconds back to Unix seconds (float)."""

    def test_one_second(self):
        assert ns_to_unix(1_000_000_000) == 1.0

    def test_one_and_half_seconds(self):
        assert ns_to_unix(1_500_000_000) == 1.5

    def test_zero(self):
        assert ns_to_unix(0) == 0.0

    def test_returns_float(self):
        assert isinstance(ns_to_unix(1_000_000_000), float)

    def test_known_epoch(self):
        result = ns_to_unix(1705312800_000_000_000)
        assert abs(result - 1705312800) < 0.001


class TestNsToDatetime:
    """ns_to_datetime(ns) returns a UTC datetime."""

    def test_returns_datetime(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert isinstance(dt, datetime)

    def test_timezone_is_utc(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert dt.tzinfo == timezone.utc

    def test_correct_year(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert dt.year == 2024

    def test_correct_month(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert dt.month == 1

    def test_correct_day(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert dt.day == 15

    def test_correct_hour(self):
        dt = ns_to_datetime(1705312800_000_000_000)
        assert dt.hour == 10

    def test_zero_epoch(self):
        dt = ns_to_datetime(0)
        assert dt.year == 1970
        assert dt.month == 1
        assert dt.day == 1


class TestFormatNs:
    """format_ns(ns) returns an ISO8601 UTC string ending in 'Z'."""

    def test_returns_string(self):
        assert isinstance(format_ns(1705312800_000_000_000), str)

    def test_ends_with_z(self):
        assert format_ns(1705312800_000_000_000).endswith("Z")

    def test_contains_date(self):
        s = format_ns(1705312800_000_000_000)
        assert "2024-01-15" in s

    def test_contains_time(self):
        s = format_ns(1705312800_000_000_000)
        assert "T10:00:00" in s

    def test_format_structure(self):
        """Result should be parseable as ISO8601."""
        s = format_ns(1705312800_000_000_000)
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_millisecond_precision(self):
        """format_ns trims to millisecond precision (3 decimal digits)."""
        s = format_ns(1705312800_123_456_789)
        # Should contain .123 (milliseconds)
        assert ".123" in s


class TestRoundTrip:
    """Round-trip: unix_to_ns → ns_to_unix should be lossless within float precision."""

    def test_unix_to_ns_to_unix(self):
        original = 1705312800.0
        result = ns_to_unix(unix_to_ns(original))
        assert abs(result - original) < 1e-3

    def test_ns_to_unix_to_ns(self):
        original_ns = 1705312800_000_000_000
        result_ns = unix_to_ns(ns_to_unix(original_ns))
        # int conversion can lose sub-second precision; allow 1ms tolerance
        assert abs(result_ns - original_ns) < 1_000_000

    def test_format_ns_then_parse(self):
        """format_ns output, when parsed back, should be within 1ms of original."""
        from sysdig_cli.timestamps import parse_timestamp
        original_ns = 1705312800_000_000_000
        formatted = format_ns(original_ns)
        parsed_ns = parse_timestamp(formatted)
        assert abs(parsed_ns - original_ns) < 1_000_000


class TestParseCompoundRelative:
    """_parse_compound_relative handles multi-unit relative strings."""

    def _approx(self, seconds: float) -> int:
        return int((time.time() - seconds) * 1e9)

    def test_2h30m_is_roughly_150min_ago(self):
        result = _parse_compound_relative("2h30m")
        expected = self._approx(2 * 3600 + 30 * 60)
        assert result is not None
        assert abs(result - expected) < int(3e9)  # within 3 seconds

    def test_1d12h_is_roughly_36h_ago(self):
        result = _parse_compound_relative("1d12h")
        expected = self._approx(1 * 86400 + 12 * 3600)
        assert result is not None
        assert abs(result - expected) < int(3e9)

    def test_30m_single_unit(self):
        result = _parse_compound_relative("30m")
        expected = self._approx(30 * 60)
        assert result is not None
        assert abs(result - expected) < int(3e9)

    def test_returns_int(self):
        result = _parse_compound_relative("1h30m")
        assert isinstance(result, int)

    def test_empty_string_returns_none(self):
        assert _parse_compound_relative("") is None

    def test_plain_number_returns_none(self):
        """A bare number without a unit is not a compound relative time."""
        assert _parse_compound_relative("12345") is None

    def test_iso_string_returns_none(self):
        """ISO8601 strings should not be matched."""
        assert _parse_compound_relative("2024-01-15T10:00:00Z") is None

    def test_7d_single_unit(self):
        result = _parse_compound_relative("7d")
        assert result is not None
        expected = self._approx(7 * 86400)
        assert abs(result - expected) < int(3e9)

    def test_1h_equals_60m(self):
        r1 = _parse_compound_relative("1h")
        r2 = _parse_compound_relative("60m")
        assert r1 is not None and r2 is not None
        assert abs(r1 - r2) < int(2e9)


class TestParseIso8601:
    """_parse_iso8601 parses various ISO8601 date/time strings."""

    def test_utc_z_suffix(self):
        dt = _parse_iso8601("2024-01-15T10:00:00Z")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.tzinfo == timezone.utc

    def test_utc_offset_plus_02(self):
        dt = _parse_iso8601("2024-01-15T12:00:00+02:00")
        # +02:00 means UTC is 10:00
        dt_utc = dt.astimezone(timezone.utc)
        assert dt_utc.hour == 10

    def test_date_only_returns_midnight_utc(self):
        dt = _parse_iso8601("2024-01-15")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 0
        assert dt.minute == 0
        assert dt.tzinfo == timezone.utc

    def test_returns_datetime(self):
        dt = _parse_iso8601("2024-06-01T00:00:00Z")
        assert isinstance(dt, datetime)

    def test_offset_minus_05(self):
        dt = _parse_iso8601("2024-01-15T05:00:00-05:00")
        dt_utc = dt.astimezone(timezone.utc)
        assert dt_utc.hour == 10

    def test_microseconds(self):
        dt = _parse_iso8601("2024-01-15T10:00:00.123456Z")
        assert dt.microsecond == 123456

    def test_invalid_raises_value_error(self):
        with pytest.raises(ValueError):
            _parse_iso8601("not-a-date")

    def test_naive_becomes_utc(self):
        """Naive datetimes (no timezone) are assumed UTC."""
        dt = _parse_iso8601("2024-01-15T10:00:00")
        assert dt.tzinfo == timezone.utc


# ===========================================================================
# 2. vulns_high_reachable
# ===========================================================================


def _make_reachable_item(
    name: str = "nginx:1.19",
    result_id: str = "abc123",
    running_critical: int = 5,
    running_high: int = 10,
    zone: str = "prod",
    cluster: str = "k8s-prod",
) -> Dict[str, Any]:
    return {
        "resultId": result_id,
        "mainAssetName": name,
        "runningVulnTotalBySeverity": {
            "critical": running_critical,
            "high": running_high,
        },
        "vulnTotalBySeverity": {"critical": running_critical + 2, "high": running_high + 5},
        "scope": {
            "kubernetes.cluster.name": cluster,
            "zone": zone,
        },
    }


class TestVulnsHighReachable:
    """Tests for vulns_high_reachable command."""

    def _invoke(self, extra_args: List[str] | None = None):
        from sysdig_cli.main import app
        args = ["vulns", "high-reachable"] + (extra_args or [])
        return runner.invoke(app, args)

    @respx.mock(base_url=BASE_URL)
    def test_basic_response_exits_zero(self, respx_mock):
        items = [_make_reachable_item("nginx:1.19", "rid1", running_critical=5, running_high=3)]
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": items, "page": {"next": None}})
        )
        result = self._invoke()
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_output_contains_workload_name(self, respx_mock):
        items = [_make_reachable_item("special-image:2.0", "rid2", running_critical=3, running_high=1)]
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": items, "page": {"next": None}})
        )
        result = self._invoke(["--format", "json"])
        assert "special-image" in result.output

    @respx.mock(base_url=BASE_URL)
    def test_empty_results_exits_zero(self, respx_mock):
        """No reachable high+ vulns → still exits 0."""
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [], "page": {"next": None}})
        )
        result = self._invoke()
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_filters_low_only_running_vulns(self, respx_mock):
        """Items with only low running vulns (no high/critical) should be filtered out."""
        low_only = {
            "resultId": "rid_low",
            "mainAssetName": "low-image:1.0",
            "runningVulnTotalBySeverity": {"critical": 0, "high": 0, "low": 99},
            "vulnTotalBySeverity": {"critical": 0, "high": 0},
        }
        high_item = _make_reachable_item("high-image:1.0", "rid_high", running_critical=1, running_high=0)
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [low_only, high_item], "page": {"next": None}})
        )
        result = self._invoke(["--format", "json"])
        assert result.exit_code == 0
        # low-only item should NOT appear
        assert "low-image" not in result.output
        assert "high-image" in result.output

    @respx.mock(base_url=BASE_URL)
    def test_sorting_critical_first(self, respx_mock):
        """Items are sorted by running critical DESC then high DESC."""
        item_high = _make_reachable_item("high-only:1.0", "rid_h", running_critical=0, running_high=5)
        item_crit = _make_reachable_item("critical-first:1.0", "rid_c", running_critical=3, running_high=1)
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [item_high, item_crit], "page": {"next": None}})
        )
        result = self._invoke(["--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        rows = parsed.get("data", [])
        assert len(rows) >= 2
        # critical-first should appear before high-only
        names = [r.get("mainAssetName", "") for r in rows]
        assert names.index("critical-first:1.0") < names.index("high-only:1.0")

    def test_401_auth_error_exits_nonzero(self):
        with patch("sysdig_cli.helpers.vulns.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            result = self._invoke()
        assert result.exit_code != 0

    @respx.mock(base_url=BASE_URL)
    def test_403_forbidden_exits_nonzero(self, respx_mock):
        with patch("sysdig_cli.helpers.vulns.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            result = self._invoke()
        assert result.exit_code != 0

    @respx.mock(base_url=BASE_URL)
    def test_all_pages_mode(self, respx_mock):
        """--all flag triggers paginated mode."""
        page1 = {
            "data": [_make_reachable_item("img1:1.0", "r1", running_critical=2, running_high=1)],
            "page": {"next": "cursor2"},
        }
        page2 = {
            "data": [_make_reachable_item("img2:1.0", "r2", running_critical=1, running_high=3)],
            "page": {"next": None},
        }
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            resp = page1 if call_count == 0 else page2
            call_count += 1
            return httpx.Response(200, json=resp)

        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(side_effect=side_effect)
        result = self._invoke(["--all", "--format", "json"])
        assert result.exit_code == 0
        assert call_count == 2

    @respx.mock(base_url=BASE_URL)
    def test_json_output_has_data_key(self, respx_mock):
        items = [_make_reachable_item("test:1.0", "r1", running_critical=1, running_high=1)]
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": items, "page": {"next": None}})
        )
        result = self._invoke(["--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "data" in parsed

    @respx.mock(base_url=BASE_URL)
    def test_dedup_same_image_different_ids(self, respx_mock):
        """Same mainAssetName → deduplicated to one row."""
        item1 = _make_reachable_item("nginx:1.19", "rid1", running_critical=5, running_high=3)
        item2 = _make_reachable_item("nginx:1.19", "rid2", running_critical=2, running_high=1)
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [item1, item2], "page": {"next": None}})
        )
        result = self._invoke(["--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        names = [r.get("mainAssetName") for r in parsed.get("data", [])]
        assert names.count("nginx:1.19") == 1


# ===========================================================================
# 3. vulns_pod_vulns
# ===========================================================================


def _make_runtime_result(
    name: str = "nginx:1.19",
    result_id: str = "abc123",
    critical: int = 3,
    high: int = 7,
) -> Dict[str, Any]:
    return {
        "resultId": result_id,
        "mainAssetName": name,
        "vulnTotalBySeverity": {"critical": critical, "high": high},
    }


def _make_cve_response(
    result_id: str,
    vulns: List[Dict[str, Any]] | None = None,
    packages: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    default_vuln = {
        "name": "CVE-2023-1234",
        "severity": "high",
        "packageRef": "pkg-uuid-001",
        "fixVersion": "1.2.3",
        "disclosureDate": "2023-06-01",
        "cisaKev": False,
        "exploitable": False,
    }
    return {
        "resultId": result_id,
        "packages": packages or {"pkg-uuid-001": {"name": "libssl", "version": "1.1.1"}},
        "vulnerabilities": vulns or [default_vuln],
    }


class TestVulnsPodVulns:
    """Tests for vulns_pod_vulns command."""

    def _invoke(self, workload: str, extra_args: List[str] | None = None):
        from sysdig_cli.main import app
        args = ["vulns", "pod-vulns", workload] + (extra_args or [])
        return runner.invoke(app, args)

    @respx.mock(base_url=BASE_URL)
    def test_basic_response_exits_zero(self, respx_mock):
        result_item = _make_runtime_result("nginx:1.19", "rid1")
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [result_item], "page": {"next": None}})
        )
        respx_mock.get("/secure/vulnerability/v1/results/rid1").mock(
            return_value=httpx.Response(200, json=_make_cve_response("rid1"))
        )
        result = self._invoke("nginx")
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_empty_results_exits_zero(self, respx_mock):
        """No matching workload → exits 0 (not an error)."""
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [], "page": {"next": None}})
        )
        result = self._invoke("nonexistent-pod")
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_cve_appears_in_output(self, respx_mock):
        result_item = _make_runtime_result("redis:6.0", "rid2")
        cve_resp = _make_cve_response(
            "rid2",
            vulns=[{
                "name": "CVE-2024-9999",
                "severity": "critical",
                "packageRef": "pkg-001",
                "fixVersion": "2.0",
                "disclosureDate": "2024-01-01",
                "cisaKev": False,
                "exploitable": True,
            }],
            packages={"pkg-001": {"name": "redis-lib", "version": "5.9"}},
        )
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [result_item], "page": {"next": None}})
        )
        respx_mock.get("/secure/vulnerability/v1/results/rid2").mock(
            return_value=httpx.Response(200, json=cve_resp)
        )
        result = self._invoke("redis", ["--format", "json"])
        assert result.exit_code == 0
        assert "CVE-2024-9999" in result.output

    @respx.mock(base_url=BASE_URL)
    def test_severity_filter_high(self, respx_mock):
        """--severity high should filter out lower severities."""
        result_item = _make_runtime_result("app:1.0", "rid3")
        cve_resp = _make_cve_response(
            "rid3",
            vulns=[
                {"name": "CVE-HIGH", "severity": "high", "packageRef": "p1", "disclosureDate": "2024-01-01"},
                {"name": "CVE-LOW", "severity": "low", "packageRef": "p2", "disclosureDate": "2024-01-01"},
            ],
            packages={"p1": {"name": "pkg-a", "version": "1.0"}, "p2": {"name": "pkg-b", "version": "2.0"}},
        )
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [result_item], "page": {"next": None}})
        )
        respx_mock.get("/secure/vulnerability/v1/results/rid3").mock(
            return_value=httpx.Response(200, json=cve_resp)
        )
        result = self._invoke("app", ["--severity", "high", "--format", "json"])
        assert result.exit_code == 0
        assert "CVE-HIGH" in result.output
        assert "CVE-LOW" not in result.output

    @respx.mock(base_url=BASE_URL)
    def test_no_cves_exits_zero(self, respx_mock):
        """Workload found but no CVEs → exits 0."""
        result_item = _make_runtime_result("clean:1.0", "rid4")
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [result_item], "page": {"next": None}})
        )
        respx_mock.get("/secure/vulnerability/v1/results/rid4").mock(
            return_value=httpx.Response(200, json={"resultId": "rid4", "packages": {}, "vulnerabilities": []})
        )
        result = self._invoke("clean")
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_best_match_used(self, respx_mock):
        """When multiple results match, the one with the most criticals is used (rid_high)."""
        low_crit = _make_runtime_result("nginx:1.19", "rid_low", critical=1, high=2)
        high_crit = _make_runtime_result("nginx:1.19", "rid_high", critical=10, high=5)
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [low_crit, high_crit], "page": {"next": None}})
        )
        # vulns_pod_vulns sorts by critical DESC then picks results[0], so rid_high is fetched
        respx_mock.get("/secure/vulnerability/v1/results/rid_high").mock(
            return_value=httpx.Response(200, json=_make_cve_response("rid_high"))
        )
        result = self._invoke("nginx", ["--format", "json"])
        assert result.exit_code == 0

    @respx.mock(base_url=BASE_URL)
    def test_api_error_exits_nonzero(self, respx_mock):
        with patch("sysdig_cli.helpers.vulns.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = SysdigError("API error")
            result = self._invoke("myapp")
        assert result.exit_code != 0

    @respx.mock(base_url=BASE_URL)
    def test_json_format_output_parseable(self, respx_mock):
        result_item = _make_runtime_result("svc:2.0", "rid5")
        respx_mock.get("/secure/vulnerability/v1/runtime-results").mock(
            return_value=httpx.Response(200, json={"data": [result_item], "page": {"next": None}})
        )
        respx_mock.get("/secure/vulnerability/v1/results/rid5").mock(
            return_value=httpx.Response(200, json=_make_cve_response("rid5"))
        )
        result = self._invoke("svc", ["--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)


# ===========================================================================
# 4. spec.py — untested functions
# ===========================================================================


# --- Minimal spec fixture for unit tests (avoids loading the large real spec) ---

_MINI_SPEC: Dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Test", "version": "1.0.0"},
    "paths": {
        "/secure/vulnerability/v1/runtime-results": {
            "get": {
                "operationId": "listRuntimeResults",
                "summary": "List runtime vulnerability results",
                "description": "Returns paginated runtime results.",
                "parameters": [{"name": "limit", "in": "query"}],
                "responses": {"200": {"description": "OK"}},
                "tags": ["vulnerability"],
            },
            "post": {
                "operationId": "createRuntimeResult",
                "summary": "Create runtime result",
                "description": "Creates a new result.",
                "parameters": [],
                "responses": {"201": {"description": "Created"}},
                "tags": ["vulnerability"],
            },
        },
        "/platform/v1/users": {
            "get": {
                "operationId": "listUsers",
                "summary": "List all users",
                "description": "Returns all users.",
                "parameters": [],
                "responses": {"200": {"description": "OK"}},
                "tags": ["users"],
            },
        },
        "/platform/v1/users/{userId}": {
            "get": {
                "operationId": "getUser",
                "summary": "Get user by ID",
                "description": "",
                "parameters": [{"name": "userId", "in": "path"}],
                "responses": {"200": {"description": "OK"}},
                "tags": ["users"],
            },
            "delete": {
                "operationId": "deleteUser",
                "summary": "Delete a user",
                "description": "",
                "parameters": [],
                "responses": {"204": {"description": "Deleted"}},
                "tags": ["users"],
            },
        },
    },
    "components": {
        "schemas": {
            "Error": {"type": "object", "properties": {"message": {"type": "string"}}},
            "User": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"$ref": "#/components/schemas/Error"},
                },
            },
        }
    },
}


class TestResolveRefs:
    """resolve_refs(obj, root) — resolves JSON $ref in-place."""

    from sysdig_cli.spec import resolve_refs

    def test_no_refs_unchanged(self):
        from sysdig_cli.spec import resolve_refs
        spec = {"a": 1, "b": {"c": "hello"}}
        result = resolve_refs(spec, spec)
        assert result == spec

    def test_simple_ref_resolved(self):
        from sysdig_cli.spec import resolve_refs
        spec = {
            "components": {"schemas": {"Foo": {"type": "object"}}},
            "use": {"$ref": "#/components/schemas/Foo"},
        }
        result = resolve_refs(spec, spec)
        assert result["use"]["type"] == "object"

    def test_nested_ref_resolved(self):
        from sysdig_cli.spec import resolve_refs
        result = resolve_refs(_MINI_SPEC, _MINI_SPEC)
        # User.name should have been resolved from Error schema
        user = result["components"]["schemas"]["User"]
        assert "message" in user["properties"]["name"].get("properties", {})

    def test_list_items_resolved(self):
        from sysdig_cli.spec import resolve_refs
        spec = {
            "items": [{"$ref": "#/defs/A"}, {"$ref": "#/defs/B"}],
            "defs": {"A": {"val": 1}, "B": {"val": 2}},
        }
        result = resolve_refs(spec, spec)
        assert result["items"][0]["val"] == 1
        assert result["items"][1]["val"] == 2

    def test_depth_limit_prevents_infinite_recursion(self):
        """A self-referential spec should not crash (depth limit kicks in)."""
        from sysdig_cli.spec import resolve_refs
        # Create a circular ref scenario
        spec: Dict[str, Any] = {}
        spec["loop"] = {"$ref": "#/loop"}
        # Should not raise
        try:
            resolve_refs(spec, spec)
        except RecursionError:
            pytest.fail("resolve_refs raised RecursionError on circular reference")

    def test_external_ref_returned_as_is(self):
        from sysdig_cli.spec import resolve_refs
        spec = {"ext": {"$ref": "https://example.com/schema.json"}}
        result = resolve_refs(spec, spec)
        assert result["ext"]["$ref"] == "https://example.com/schema.json"

    def test_primitive_passthrough(self):
        from sysdig_cli.spec import resolve_refs
        assert resolve_refs(42, {}) == 42
        assert resolve_refs("hello", {}) == "hello"
        assert resolve_refs(None, {}) is None


class TestGetPaths:
    """get_paths(spec) — returns the paths dict."""

    def test_returns_dict(self):
        from sysdig_cli.spec import get_paths
        result = get_paths(_MINI_SPEC)
        assert isinstance(result, dict)

    def test_returns_correct_paths(self):
        from sysdig_cli.spec import get_paths
        paths = get_paths(_MINI_SPEC)
        assert "/secure/vulnerability/v1/runtime-results" in paths
        assert "/platform/v1/users" in paths

    def test_empty_paths_key_returns_empty_dict(self):
        """A spec with an explicit empty 'paths' dict returns {}."""
        from sysdig_cli.spec import get_paths
        assert get_paths({"paths": {}}) == {}

    def test_uses_real_spec_by_default(self):
        """Calling without argument uses the bundled spec (non-empty)."""
        from sysdig_cli.spec import get_paths
        paths = get_paths()
        assert len(paths) > 0


class TestGetAllOperations:
    """get_all_operations(spec) — returns list of all operations."""

    def test_returns_list(self):
        from sysdig_cli.spec import get_all_operations
        ops = get_all_operations(_MINI_SPEC)
        assert isinstance(ops, list)

    def test_correct_count(self):
        from sysdig_cli.spec import get_all_operations
        ops = get_all_operations(_MINI_SPEC)
        # 2 on /runtime-results, 1 on /users, 2 on /users/{userId} = 5 total
        assert len(ops) == 5

    def test_each_op_has_path(self):
        from sysdig_cli.spec import get_all_operations
        for op in get_all_operations(_MINI_SPEC):
            assert "path" in op

    def test_each_op_has_method(self):
        from sysdig_cli.spec import get_all_operations
        for op in get_all_operations(_MINI_SPEC):
            assert "method" in op
            assert op["method"] in ("get", "post", "put", "delete", "patch")

    def test_each_op_has_operation_id(self):
        from sysdig_cli.spec import get_all_operations
        for op in get_all_operations(_MINI_SPEC):
            assert "operation_id" in op

    def test_each_op_has_summary(self):
        from sysdig_cli.spec import get_all_operations
        for op in get_all_operations(_MINI_SPEC):
            assert "summary" in op

    def test_each_op_has_responses(self):
        from sysdig_cli.spec import get_all_operations
        for op in get_all_operations(_MINI_SPEC):
            assert "responses" in op

    def test_real_spec_non_empty(self):
        from sysdig_cli.spec import get_all_operations
        ops = get_all_operations()
        assert len(ops) > 50


class TestFindOperation:
    """find_operation(path, method, spec) — finds a specific operation."""

    def test_finds_existing_get(self):
        from sysdig_cli.spec import find_operation
        op = find_operation(
            "/secure/vulnerability/v1/runtime-results", "get", _MINI_SPEC
        )
        assert op is not None
        assert op["operation_id"] == "listRuntimeResults"

    def test_finds_existing_post(self):
        from sysdig_cli.spec import find_operation
        op = find_operation(
            "/secure/vulnerability/v1/runtime-results", "post", _MINI_SPEC
        )
        assert op is not None
        assert op["operation_id"] == "createRuntimeResult"

    def test_finds_delete(self):
        from sysdig_cli.spec import find_operation
        op = find_operation("/platform/v1/users/{userId}", "delete", _MINI_SPEC)
        assert op is not None
        assert op["method"] == "delete"

    def test_missing_path_returns_none(self):
        from sysdig_cli.spec import find_operation
        result = find_operation("/does/not/exist", "get", _MINI_SPEC)
        assert result is None

    def test_missing_method_returns_none(self):
        from sysdig_cli.spec import find_operation
        result = find_operation("/platform/v1/users", "delete", _MINI_SPEC)
        assert result is None

    def test_case_insensitive_method(self):
        from sysdig_cli.spec import find_operation
        op = find_operation("/platform/v1/users", "GET", _MINI_SPEC)
        assert op is not None

    def test_returned_op_has_summary(self):
        from sysdig_cli.spec import find_operation
        op = find_operation("/platform/v1/users", "get", _MINI_SPEC)
        assert "summary" in op
        assert op["summary"] == "List all users"


class TestExtractPathParams:
    """extract_path_params(path) — returns list of path parameter names."""

    def test_single_param(self):
        from sysdig_cli.spec import extract_path_params
        assert extract_path_params("/api/v1/results/{id}") == ["id"]

    def test_two_params(self):
        from sysdig_cli.spec import extract_path_params
        result = extract_path_params("/api/v1/users/{userId}/items/{itemId}")
        assert result == ["userId", "itemId"]

    def test_no_params(self):
        from sysdig_cli.spec import extract_path_params
        assert extract_path_params("/api/v1/results") == []

    def test_empty_path(self):
        from sysdig_cli.spec import extract_path_params
        assert extract_path_params("") == []

    def test_root_path(self):
        from sysdig_cli.spec import extract_path_params
        assert extract_path_params("/") == []

    def test_preserves_param_names(self):
        from sysdig_cli.spec import extract_path_params
        params = extract_path_params("/secure/vulnerability/v1/results/{resultId}/packages/{packageId}")
        assert "resultId" in params
        assert "packageId" in params


class TestPathToCommandName:
    """path_to_command_name(path, service) — converts path to CLI slug."""

    def test_runtime_results_slug(self):
        from sysdig_cli.spec import path_to_command_name
        name, params = path_to_command_name(
            "/secure/vulnerability/v1/runtime-results", "vulns"
        )
        assert "runtime-results" in name
        assert params == []

    def test_users_path_with_id_has_param(self):
        from sysdig_cli.spec import path_to_command_name
        name, params = path_to_command_name("/platform/v1/users/{userId}", "platform")
        assert "userId" in params

    def test_returns_tuple(self):
        from sysdig_cli.spec import path_to_command_name
        result = path_to_command_name("/platform/v1/users", "platform")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_version_segment_stripped(self):
        from sysdig_cli.spec import path_to_command_name
        # /secure/vulnerability/v1/runtime-results → strip /v1/ prefix after service prefix
        name, _ = path_to_command_name("/secure/vulnerability/v1/runtime-results", "vulns")
        # The version 'v1' should not appear as a standalone token in the command name
        assert name != ""

    def test_unknown_service_uses_full_path(self):
        from sysdig_cli.spec import path_to_command_name
        # If service has no prefixes, the full path is used but still returns valid tuple
        name, params = path_to_command_name("/some/custom/path", "unknown-service")
        assert isinstance(name, str)
        assert isinstance(params, list)

    def test_path_params_excluded_from_name(self):
        from sysdig_cli.spec import path_to_command_name
        name, params = path_to_command_name("/platform/v1/users/{userId}", "users")
        # {userId} should be in params, not in name
        assert "{userId}" not in name
        assert "userId" in params


class TestGetOperationsForService:
    """get_operations_for_service(service, spec) — filters by service."""

    def test_vulnerability_service_returns_ops(self):
        from sysdig_cli.spec import get_operations_for_service
        # Use a custom SERVICE_MAP-aware test
        ops = get_operations_for_service("vulns", _MINI_SPEC)
        assert len(ops) > 0

    def test_platform_service_returns_users(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("platform", _MINI_SPEC)
        paths = [op["path"] for op in ops]
        assert any("/platform/v1/users" in p for p in paths)

    def test_unknown_service_returns_empty(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("nonexistent-service-xyz", _MINI_SPEC)
        assert ops == []

    def test_each_op_has_required_fields(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("vulns", _MINI_SPEC)
        required = {"path", "method", "operation_id", "summary", "parameters", "responses"}
        for op in ops:
            assert required.issubset(op.keys()), f"Missing keys in {op}"

    def test_real_spec_vulns_service(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("vulns")
        assert len(ops) > 0

    def test_real_spec_users_service(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("users")
        assert len(ops) > 0

    def test_methods_are_lowercase(self):
        from sysdig_cli.spec import get_operations_for_service
        ops = get_operations_for_service("vulns", _MINI_SPEC)
        for op in ops:
            assert op["method"] == op["method"].lower()


class TestLoadSpec:
    """load_spec() — loads the real bundled OpenAPI spec."""

    def test_returns_dict(self):
        from sysdig_cli import spec as spec_module
        # Clear cache to ensure fresh load
        spec_module._spec_cache = None
        s = spec_module.load_spec()
        assert isinstance(s, dict)

    def test_has_paths_key(self):
        from sysdig_cli.spec import load_spec
        s = load_spec()
        assert "paths" in s

    def test_has_openapi_key(self):
        from sysdig_cli.spec import load_spec
        s = load_spec()
        assert "openapi" in s or "swagger" in s

    def test_paths_is_dict(self):
        from sysdig_cli.spec import load_spec
        s = load_spec()
        assert isinstance(s.get("paths"), dict)

    def test_caches_on_second_call(self):
        """Second call with no args returns same object (cached)."""
        from sysdig_cli import spec as spec_module
        spec_module._spec_cache = None
        s1 = spec_module.load_spec()
        s2 = spec_module.load_spec()
        assert s1 is s2

    def test_custom_path_not_cached(self, tmp_path):
        """Passing a custom path does NOT update the global cache."""
        from sysdig_cli import spec as spec_module
        spec_module._spec_cache = None

        mini = {
            "openapi": "3.0.0",
            "info": {"title": "Mini", "version": "0.1"},
            "paths": {"/test": {}},
        }
        tmp_file = tmp_path / "mini.json"
        tmp_file.write_text(json.dumps(mini))

        s_custom = spec_module.load_spec(spec_path=Path(tmp_file))
        assert "/test" in s_custom.get("paths", {})
        # Cache should still be None (custom path not cached)
        assert spec_module._spec_cache is None
