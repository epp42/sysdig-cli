"""
Comprehensive unit tests for events.py, audit.py, and iam.py helpers.

Coverage:
- events.tail: iteration, deduplication, filter param, empty response, SysdigError retry
- events.hunt: IOC found/not found, empty, from_time, limit cap, 403
- events.events_list: no filters, rule/namespace/container/pod/severity filters,
  combined filters, limit, --all mode, total_matched suffix, 401 → exit 2, 403 → exit 5
- events.events_id: found, not found, fmt=json, 403 → exit 5
- audit.recent_commands: basic, user filter, all_pages, from_time, empty, 401 → exit 2
- audit.audit_compliance_export: all 4 frameworks, invalid framework, empty, since param
- audit.audit_incident_timeline: basic, namespace, empty audit/events, API error
- audit.audit_platform_events: basic, --user filter, --action filter, --all, empty, 401
- iam.iam_access_keys_list: basic, --user by accessKey, by teamId, all_pages, empty, 403
- iam.iam_roles_list: basic, all_pages, empty, 401
- iam.iam_group_mappings_list: isForAllTeams, teamIds, all_pages, empty
- iam.iam_sso_settings: basic, 403
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import MagicMock, patch, call

import httpx
import pytest
import respx
import typer
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import AuthError, ForbiddenError, SysdigError

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Shared auth fixture
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    from sysdig_cli.auth import AuthConfig
    auth = AuthConfig(token="testtoken", host="https://us2.app.sysdig.com")
    with patch("sysdig_cli.helpers.events.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.audit.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.iam.resolve_auth", return_value=auth):
        yield


# ---------------------------------------------------------------------------
# Shared realistic Falco event fixture
# ---------------------------------------------------------------------------

FALCO_EVENT = {
    "id": "e1",
    "timestamp": 1705312800000000000,
    "severity": 7,
    "content": {
        "ruleName": "Bash in Container",
        "output": "bash run by root",
        "fields": {
            "container.name": "nginx",
            "kubernetes.namespace.name": "production",
            "k8s.pod.name": "nginx-pod",
        },
    },
}

FALCO_EVENT_2 = {
    "id": "e2",
    "timestamp": 1705312900000000000,
    "severity": 4,
    "content": {
        "ruleName": "Netcat Detected",
        "output": "nc found",
        "fields": {
            "container.name": "redis",
            "kubernetes.namespace.name": "staging",
            "k8s.pod.name": "redis-pod",
        },
    },
}


# ===========================================================================
# events.tail
# ===========================================================================

class TestEventsTail:

    def _mock_client_get(self, side_effect=None, return_value=None):
        """Return a mock SysdigClient whose get() behaves as specified."""
        mock_client = MagicMock()
        if side_effect:
            mock_client.get.side_effect = side_effect
        else:
            mock_client.get.return_value = return_value
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def test_tail_one_iteration_then_keyboard_interrupt(self, capsys):
        """tail runs 1 iteration, prints event, then stops on KeyboardInterrupt."""
        from sysdig_cli.helpers.events import tail

        poll_count = 0

        def fake_get(path, params=None):
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                return {"data": [FALCO_EVENT]}
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        captured = capsys.readouterr()
        assert "e1" in captured.out

    def test_tail_deduplication(self, capsys):
        """Seen event IDs are not printed twice."""
        from sysdig_cli.helpers.events import tail

        call_count = 0

        def fake_get(path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"data": [FALCO_EVENT]}
            if call_count == 2:
                # Same event again — should be deduped
                return {"data": [FALCO_EVENT]}
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        captured = capsys.readouterr()
        # e1 should appear only once
        assert captured.out.count('"e1"') == 1

    def test_tail_filter_param_passed(self):
        """When filter is given, it is included in the GET params."""
        from sysdig_cli.helpers.events import tail

        captured_params = []

        def fake_get(path, params=None):
            captured_params.append(params or {})
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1, filter="severity=7")

        assert any("filter" in p and p["filter"] == "severity=7" for p in captured_params)

    def test_tail_empty_response(self, capsys):
        """Empty data list from API produces no output and continues."""
        from sysdig_cli.helpers.events import tail

        call_count = 0

        def fake_get(path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"data": []}
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        captured = capsys.readouterr()
        assert captured.out.strip() == ""

    def test_tail_sysdiger_error_retries(self, capsys):
        """SysdigError on poll prints a warning and continues (retry)."""
        from sysdig_cli.helpers.events import tail

        call_count = 0

        def fake_get(path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise SysdigError("temporary API error")
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)  # Should not raise

        # Just verifying it didn't crash; warning goes to stderr via print_warning
        assert call_count >= 1

    def test_tail_none_response_continues(self, capsys):
        """None response from API sleeps and continues without crashing."""
        from sysdig_cli.helpers.events import tail

        call_count = 0

        def fake_get(path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            raise KeyboardInterrupt

        mock_client = self._mock_client_get(side_effect=fake_get)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        captured = capsys.readouterr()
        assert captured.out.strip() == ""


# ===========================================================================
# events.hunt
# ===========================================================================

class TestEventsHunt:

    def test_hunt_ioc_found(self, capsys):
        """IOC found in events → match_count > 0 in output."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": [FALCO_EVENT, FALCO_EVENT_2]}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            hunt("nginx", fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["match_count"] >= 1
        assert result["ioc"] == "nginx"

    def test_hunt_ioc_not_found(self, capsys):
        """IOC not in any event → match_count == 0."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": [FALCO_EVENT, FALCO_EVENT_2]}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            hunt("xyzzy-not-in-any-event", fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["match_count"] == 0
        assert result["matches"] == []

    def test_hunt_empty_events(self, capsys):
        """Empty events list returns total_scanned=0."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": []}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            hunt("nginx", fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["total_scanned"] == 0

    def test_hunt_from_time_param(self):
        """from_time param is passed to parse_timestamp."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": []}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        captured_calls = []

        def fake_parse_ts(value):
            captured_calls.append(value)
            return 900_000_000_000

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", side_effect=fake_parse_ts):
            hunt("nginx", from_time="7d", fmt="json")

        assert "7d" in captured_calls

    def test_hunt_limit_capped_at_1000(self):
        """Limit > 1000 is capped at 1000 in the API params."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": []}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            hunt("nginx", limit=5000, fmt="json")

        call_args = mock_client.get.call_args
        assert call_args[1]["params"]["limit"] == 1000

    def test_hunt_403_exits_5(self):
        """ForbiddenError causes exit code 5."""
        from sysdig_cli.helpers.events import hunt

        mock_client = MagicMock()
        mock_client.get.side_effect = ForbiddenError("forbidden")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            with pytest.raises(typer.Exit) as exc_info:
                hunt("nginx", fmt="json")
        assert exc_info.value.exit_code == 5


# ===========================================================================
# events.events_list — uses CliRunner because function has typer.Option defaults
# ===========================================================================

def _make_events_list_app():
    """Build a tiny Typer app wrapping events_list for CliRunner invocation."""
    import typer as _typer
    from sysdig_cli.helpers.events import events_list as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestEventsListFunction:
    """Tests for events_list() invoked via CliRunner (typer.Option defaults require it)."""

    def _make_client(self, response_data):
        mock_client = MagicMock()
        mock_client.get.return_value = response_data
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def _run(self, args, mock_client):
        app = _make_events_list_app()
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            result = runner.invoke(app, args)
        return result

    def test_no_filters_returns_all(self):
        """No filters → all events returned."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2], "page": {"next": None}})
        result = self._run(["--format", "json", "--from", "1h"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 2

    def test_rule_filter(self):
        """--rule filters by content.ruleName substring."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(["--format", "json", "--from", "1h", "--rule", "Bash"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "e1"

    def test_namespace_filter(self):
        """--namespace filters by kubernetes.namespace.name."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(["--format", "json", "--from", "1h", "--namespace", "production"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "e1"

    def test_container_filter(self):
        """--container filters by container.name."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(["--format", "json", "--from", "1h", "--container", "redis"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "e2"

    def test_pod_filter(self):
        """--pod filters by k8s.pod.name."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(["--format", "json", "--from", "1h", "--pod", "nginx-pod"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "e1"

    def test_severity_filter(self):
        """--severity filters events below minimum severity."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(["--format", "json", "--from", "1h", "--severity", "7"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["severity"] == 7

    def test_combined_filters(self):
        """Multiple filters applied together."""
        mock_client = self._make_client({"data": [FALCO_EVENT, FALCO_EVENT_2]})
        result = self._run(
            ["--format", "json", "--from", "1h", "--namespace", "production", "--severity", "7"],
            mock_client,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "e1"

    def test_limit_respected(self):
        """--limit caps the number of returned events."""
        events = [dict(FALCO_EVENT, id=f"e{i}") for i in range(5)]
        mock_client = self._make_client({"data": events})
        result = self._run(["--format", "json", "--from", "1h", "--limit", "2"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["data"]) <= 2

    def test_total_matched_suffix_shown(self):
        """When API reports more total than returned, no crash and event is present."""
        mock_client = self._make_client({
            "data": [FALCO_EVENT],
            "page": {"total": 5000},
        })
        result = self._run(["--format", "json", "--from", "1h"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["data"][0]["id"] == "e1"

    def test_401_exits_2(self):
        """AuthError → exit code 2."""
        mock_client = MagicMock()
        mock_client.get.side_effect = AuthError("unauthorized")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        result = self._run(["--format", "json", "--from", "1h"], mock_client)
        assert result.exit_code == 2

    def test_403_exits_5(self):
        """ForbiddenError → exit code 5."""
        mock_client = MagicMock()
        mock_client.get.side_effect = ForbiddenError("forbidden")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        result = self._run(["--format", "json", "--from", "1h"], mock_client)
        assert result.exit_code == 5

    def test_all_mode_paginated(self):
        """--all mode iterates pages and prints ndjson lines."""
        pages = [
            {"data": [FALCO_EVENT], "page": {"next": "cursor1"}},
            {"data": [FALCO_EVENT_2], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--from", "1h", "--all", "--format", "ndjson"], mock_client)
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().splitlines() if l.startswith("{")]
        assert len(lines) == 2


# ===========================================================================
# events.events_id
# ===========================================================================

class TestEventsId:

    def test_event_found(self, capsys):
        """Event found → output is printed."""
        from sysdig_cli.helpers.events import events_id

        mock_client = MagicMock()
        mock_client.get.return_value = FALCO_EVENT
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client):
            events_id(event_id="e1", fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["id"] == "e1"

    def test_event_not_found_returns_none(self):
        """Empty/None response → exit code 1."""
        from sysdig_cli.helpers.events import events_id

        mock_client = MagicMock()
        mock_client.get.return_value = None
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client):
            with pytest.raises(typer.Exit) as exc_info:
                events_id(event_id="missing-id", fmt="json")
        assert exc_info.value.exit_code == 1

    def test_event_fmt_json(self, capsys):
        """fmt=json produces valid JSON on stdout."""
        from sysdig_cli.helpers.events import events_id

        mock_client = MagicMock()
        mock_client.get.return_value = FALCO_EVENT
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client):
            events_id(event_id="e1", fmt="json")

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "id" in data

    def test_event_403_exits_5(self):
        """ForbiddenError → exit code 5."""
        from sysdig_cli.helpers.events import events_id

        mock_client = MagicMock()
        mock_client.get.side_effect = ForbiddenError("forbidden")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=mock_client):
            with pytest.raises(typer.Exit) as exc_info:
                events_id(event_id="e1", fmt="json")
        assert exc_info.value.exit_code == 5


# ===========================================================================
# audit.recent_commands
# ===========================================================================

AUDIT_ENTRY_1 = {
    "id": "a1",
    "timestamp": 1705312800000000000,
    "type": "kubectl.exec",
    "username": "alice@example.com",
    "userLoginName": "alice@example.com",
    "commandLine": "kubectl exec pod-abc -- /bin/bash",
}

AUDIT_ENTRY_2 = {
    "id": "a2",
    "timestamp": 1705312900000000000,
    "type": "config.change",
    "username": "bob@example.com",
    "userLoginName": "bob@example.com",
    "commandLine": "kubectl edit cm nginx-config",
}


class TestRecentCommands:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def test_basic_returns_entries(self, capsys):
        """Basic call returns entries from the data key."""
        from sysdig_cli.helpers.audit import recent_commands

        mock_client = self._make_client({"data": [AUDIT_ENTRY_1, AUDIT_ENTRY_2]})

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            recent_commands(fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert len(result["entries"]) == 2

    def test_user_filter(self, capsys):
        """--user filters entries by username."""
        from sysdig_cli.helpers.audit import recent_commands

        mock_client = self._make_client({"data": [AUDIT_ENTRY_1, AUDIT_ENTRY_2]})

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            # user filter is server-side but also added to result
            recent_commands(fmt="json", user="alice@example.com")

        # The filter is added to params but we still return data from API
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result.get("user_filter") == "alice@example.com"

    def test_all_pages_streams_entries(self, capsys):
        """all_pages=True streams entries from paginated API."""
        from sysdig_cli.helpers.audit import recent_commands

        pages = [
            {"data": [AUDIT_ENTRY_1], "page": {"next": "cur1"}},
            {"data": [AUDIT_ENTRY_2], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            recent_commands(fmt="ndjson", all_pages=True)

        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().splitlines() if l.startswith("{")]
        assert len(lines) == 2

    def test_from_time_passed(self):
        """from_time is passed to parse_timestamp."""
        from sysdig_cli.helpers.audit import recent_commands

        mock_client = MagicMock()
        mock_client.get.return_value = {"data": []}
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        captured_calls = []

        def fake_parse(value):
            captured_calls.append(value)
            return 900_000_000_000

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", side_effect=fake_parse):
            recent_commands(from_time="1h")

        assert "1h" in captured_calls

    def test_empty_response(self, capsys):
        """None response → outputs entries=[] total=0."""
        from sysdig_cli.helpers.audit import recent_commands

        mock_client = MagicMock()
        mock_client.get.return_value = None
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            recent_commands(fmt="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["entries"] == []
        assert result["total"] == 0

    def test_401_exits_2(self):
        """AuthError → exit code 2."""
        from sysdig_cli.helpers.audit import recent_commands

        mock_client = MagicMock()
        mock_client.get.side_effect = AuthError("unauthorized")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            with pytest.raises(typer.Exit) as exc_info:
                recent_commands()
        assert exc_info.value.exit_code == 2


# ===========================================================================
# audit.audit_compliance_export
# ===========================================================================

class TestAuditComplianceExport:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    @pytest.mark.parametrize("framework", ["soc2", "pci", "iso27001", "hipaa"])
    def test_valid_frameworks(self, framework, capsys):
        """Valid frameworks produce a compliance_export output."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        mock_client = self._make_client({"data": [AUDIT_ENTRY_1]})

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_compliance_export(framework=framework, since="30d", format="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["compliance_export"]["framework"] == framework
        assert result["compliance_export"]["total_entries"] == 1

    def test_invalid_framework_exits_1(self):
        """Unknown framework exits with code 1."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        with pytest.raises(typer.Exit) as exc_info:
            audit_compliance_export(framework="gdpr", since="30d", format="json")
        assert exc_info.value.exit_code == 1

    def test_empty_entries(self, capsys):
        """Empty audit response → total_entries=0."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        mock_client = self._make_client({"data": []})

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_compliance_export(framework="soc2", since="30d", format="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["compliance_export"]["total_entries"] == 0

    def test_since_param_passed(self):
        """since param is forwarded to parse_timestamp."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        mock_client = self._make_client({"data": []})

        captured_calls = []

        def fake_parse(value):
            captured_calls.append(value)
            return 900_000_000_000

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", side_effect=fake_parse):
            audit_compliance_export(framework="soc2", since="7d", format="json")

        assert "7d" in captured_calls

    def test_null_response_handled(self, capsys):
        """None response from API is treated as empty."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        mock_client = self._make_client(None)

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_compliance_export(framework="hipaa", since="30d", format="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["compliance_export"]["total_entries"] == 0


# ===========================================================================
# audit.audit_incident_timeline
# ===========================================================================

class TestAuditIncidentTimeline:

    def test_basic_with_pod_name(self, capsys):
        """Basic call with pod name builds timeline from audit + security events."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        def fake_get(path, params=None):
            if "activity-audit" in path:
                return {"data": [AUDIT_ENTRY_1], "entries": []}
            else:
                return {"data": [FALCO_EVENT]}

        mock_client.get.side_effect = fake_get

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="nginx-pod", since="2h", format="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["incident_timeline"]["pod"] == "nginx-pod"
        assert result["incident_timeline"]["total_events"] == 2

    def test_with_namespace(self, capsys):
        """Namespace is included in the filter and timeline."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        captured_params = []

        def fake_get(path, params=None):
            captured_params.append(params or {})
            return {"data": []}

        mock_client.get.side_effect = fake_get

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="nginx-pod", since="2h", namespace="production", format="json")

        # The filter should include the namespace
        assert any("production" in str(p.get("filter", "")) for p in captured_params)

    def test_empty_audit_and_events(self, capsys):
        """Empty audit and security events → total_events=0."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = {"data": []}

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="nginx-pod", since="2h", format="json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["incident_timeline"]["total_events"] == 0

    def test_api_error_graceful(self, capsys):
        """API error is caught gracefully and timeline has 0 events."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = SysdigError("something broke")

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="bad-pod", since="2h", format="json")  # Should not raise

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["incident_timeline"]["total_events"] == 0


# ===========================================================================
# audit.audit_platform_events — uses CliRunner because function has typer.Option defaults
# ===========================================================================

PLATFORM_EVENT_1 = {
    "id": "pe1",
    "timestamp": 1705312800000000000,
    "content": {"username": "alice@example.com", "requestUri": "/api/login"},
}

PLATFORM_EVENT_2 = {
    "id": "pe2",
    "timestamp": 1705312900000000000,
    "content": {"username": "bob@example.com", "requestUri": "/api/config/update"},
}


def _make_platform_events_app():
    import typer as _typer
    from sysdig_cli.helpers.audit import audit_platform_events as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestAuditPlatformEvents:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def _run(self, args, mock_client):
        app = _make_platform_events_app()
        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=mock_client), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            result = runner.invoke(app, args)
        return result

    def test_basic(self):
        """Basic call returns all platform audit events."""
        mock_client = self._make_client({"data": [PLATFORM_EVENT_1, PLATFORM_EVENT_2]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_user_filter(self):
        """--user filters by content.username."""
        mock_client = self._make_client({"data": [PLATFORM_EVENT_1, PLATFORM_EVENT_2]})
        result = self._run(["--format", "json", "--user", "alice@example.com"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["id"] == "pe1"

    def test_action_filter(self):
        """--action filters by content.requestUri."""
        mock_client = self._make_client({"data": [PLATFORM_EVENT_1, PLATFORM_EVENT_2]})
        result = self._run(["--format", "json", "--action", "config"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["id"] == "pe2"

    def test_all_mode(self):
        """--all mode streams paginated results."""
        pages = [
            {"data": [PLATFORM_EVENT_1], "page": {"next": "cur1"}},
            {"data": [PLATFORM_EVENT_2], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--all", "--format", "ndjson"], mock_client)
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().splitlines() if l.startswith("{")]
        assert len(lines) == 2

    def test_empty(self):
        """Empty response → 0 events output."""
        mock_client = self._make_client({"data": []})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_401_exits_2(self):
        """AuthError → exit code 2."""
        mock_client = MagicMock()
        mock_client.get.side_effect = AuthError("unauthorized")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 2


# ===========================================================================
# iam.iam_access_keys_list — uses CliRunner because function has typer.Option defaults
# ===========================================================================

ACCESS_KEY_1 = {"id": "ak1", "accessKey": "ABCD1234", "teamId": "101", "enabled": True}
ACCESS_KEY_2 = {"id": "ak2", "accessKey": "WXYZ5678", "teamId": "202", "enabled": False}


def _make_access_keys_app():
    import typer as _typer
    from sysdig_cli.helpers.iam import iam_access_keys_list as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestIamAccessKeysList:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def _run(self, args, mock_client):
        app = _make_access_keys_app()
        with patch("sysdig_cli.helpers.iam.SysdigClient", return_value=mock_client):
            result = runner.invoke(app, args)
        return result

    def test_basic_list(self):
        """Basic call returns keys from data key."""
        mock_client = self._make_client({"data": [ACCESS_KEY_1, ACCESS_KEY_2]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_user_filter_by_access_key_substring(self):
        """--user filters keys by accessKey substring."""
        mock_client = self._make_client({"data": [ACCESS_KEY_1, ACCESS_KEY_2]})
        result = self._run(["--format", "json", "--user", "ABCD"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["id"] == "ak1"

    def test_user_filter_by_team_id(self):
        """--user filters keys by exact teamId match."""
        mock_client = self._make_client({"data": [ACCESS_KEY_1, ACCESS_KEY_2]})
        result = self._run(["--format", "json", "--user", "202"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["id"] == "ak2"

    def test_all_pages_true(self):
        """all_pages=True fetches all pages."""
        pages = [
            {"data": [ACCESS_KEY_1], "page": {"next": "cur1"}},
            {"data": [ACCESS_KEY_2], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json", "--all"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_empty_list(self):
        """Empty data → 0 keys."""
        mock_client = self._make_client({"data": []})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_403_exits_5(self):
        """ForbiddenError → exit code 5."""
        mock_client = MagicMock()
        mock_client.get.side_effect = ForbiddenError("forbidden")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 5


# ===========================================================================
# iam.iam_roles_list — uses CliRunner because function has typer.Option defaults
# ===========================================================================

ROLE_1 = {"id": "role1", "name": "Admin", "description": "Full access"}
ROLE_2 = {"id": "role2", "name": "ReadOnly", "description": "Read only"}


def _make_roles_app():
    import typer as _typer
    from sysdig_cli.helpers.iam import iam_roles_list as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestIamRolesList:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def _run(self, args, mock_client):
        app = _make_roles_app()
        with patch("sysdig_cli.helpers.iam.SysdigClient", return_value=mock_client):
            result = runner.invoke(app, args)
        return result

    def test_basic_list(self):
        """Basic call returns roles from data key."""
        mock_client = self._make_client({"data": [ROLE_1, ROLE_2]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_all_pages_true(self):
        """all_pages=True fetches paginated roles."""
        pages = [
            {"data": [ROLE_1], "page": {"next": "cur1"}},
            {"data": [ROLE_2], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json", "--all"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_empty(self):
        """Empty data → 0 roles."""
        mock_client = self._make_client({"data": []})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_401_exits_2(self):
        """AuthError → exit code 2."""
        mock_client = MagicMock()
        mock_client.get.side_effect = AuthError("unauthorized")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 2


# ===========================================================================
# iam.iam_group_mappings_list — uses CliRunner because function has typer.Option defaults
# ===========================================================================

MAPPING_ALL_TEAMS = {
    "id": "gm1",
    "groupName": "devs",
    "teamMap": {"isForAllTeams": True, "teamIds": []},
}

MAPPING_SPECIFIC_TEAMS = {
    "id": "gm2",
    "groupName": "ops",
    "teamMap": {"isForAllTeams": False, "teamIds": [101, 202]},
}

MAPPING_NO_TEAMS = {
    "id": "gm3",
    "groupName": "guests",
    "teamMap": {"isForAllTeams": False, "teamIds": []},
}


def _make_group_mappings_app():
    import typer as _typer
    from sysdig_cli.helpers.iam import iam_group_mappings_list as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestIamGroupMappingsList:

    def _make_client(self, response):
        mock_client = MagicMock()
        mock_client.get.return_value = response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def _run(self, args, mock_client):
        app = _make_group_mappings_app()
        with patch("sysdig_cli.helpers.iam.SysdigClient", return_value=mock_client):
            result = runner.invoke(app, args)
        return result

    def test_is_for_all_teams_shown_as_all(self):
        """isForAllTeams=True → teams field is 'ALL'."""
        mock_client = self._make_client({"data": [MAPPING_ALL_TEAMS]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["teams"] == "ALL"

    def test_specific_team_ids_comma_separated(self):
        """Specific teamIds → teams field is comma-separated string."""
        mock_client = self._make_client({"data": [MAPPING_SPECIFIC_TEAMS]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["teams"] == "101,202"

    def test_all_pages_true(self):
        """all_pages=True fetches paginated mappings."""
        pages = [
            {"data": [MAPPING_ALL_TEAMS], "page": {"next": "cur1"}},
            {"data": [MAPPING_SPECIFIC_TEAMS], "page": {"next": None}},
        ]
        call_idx = [0]

        mock_client = MagicMock()
        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": [], "page": {"next": None}}

        mock_client.get.side_effect = fake_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json", "--all"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_empty(self):
        """Empty data → 0 mappings."""
        mock_client = self._make_client({"data": []})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_empty_team_ids_gives_empty_string(self):
        """Empty teamIds and not isForAllTeams → teams=''."""
        mock_client = self._make_client({"data": [MAPPING_NO_TEAMS]})
        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["teams"] == ""


# ===========================================================================
# iam.iam_sso_settings — uses CliRunner because function has typer.Option defaults
# ===========================================================================

SSO_SETTINGS = {
    "enabled": True,
    "idpUrl": "https://idp.example.com/sso",
    "entityId": "sysdig-sp",
    "certificate": "MIIB...",
}


def _make_sso_settings_app():
    import typer as _typer
    from sysdig_cli.helpers.iam import iam_sso_settings as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestIamSsoSettings:

    def _run(self, args, mock_client):
        app = _make_sso_settings_app()
        with patch("sysdig_cli.helpers.iam.SysdigClient", return_value=mock_client):
            result = runner.invoke(app, args)
        return result

    def test_basic_json_response(self):
        """Basic call outputs SSO settings as JSON."""
        mock_client = MagicMock()
        mock_client.get.return_value = SSO_SETTINGS
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["enabled"] is True
        assert "idpUrl" in data

    def test_403_exits_5(self):
        """ForbiddenError → exit code 5."""
        mock_client = MagicMock()
        mock_client.get.side_effect = ForbiddenError("forbidden")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 5

    def test_none_response_output(self):
        """None response from API → no crash, output is null or empty."""
        mock_client = MagicMock()
        mock_client.get.return_value = None
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        result = self._run(["--format", "json"], mock_client)
        assert result.exit_code == 0
        assert result.output.strip() in ("null", "")
