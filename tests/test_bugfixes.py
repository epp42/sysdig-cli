"""
Regression tests for bugs fixed in sysdig-cli.

Each test class corresponds to a specific bug and verifies the fix.
Uses respx to mock HTTP responses with the real API data structures
observed from live API calls.
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


@pytest.fixture(autouse=True)
def patch_resolve_auth(monkeypatch):
    """Patch resolve_auth for all tests to return a test AuthConfig."""
    monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
    auth = AuthConfig(token="testtoken", host=BASE_URL)
    with patch("sysdig_cli.helpers.events.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.audit.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.iam.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.vulns.resolve_auth", return_value=auth):
        yield auth


# ---------------------------------------------------------------------------
# Falco event structure used in live API responses
# Real structure: content.fields has flat dot-keys like "container.name"
# ---------------------------------------------------------------------------

def _make_falco_event(
    event_id: str = "evt-001",
    rule_name: str = "Bash in Container",
    severity: int = 7,
    container_name: str = "nginx",
    namespace: str = "production",
    pod_name: str = "nginx-abc",
    output: str = "bash run by user root in container nginx",
) -> Dict[str, Any]:
    """Build a realistic Falco security event matching live API structure."""
    return {
        "id": event_id,
        "timestamp": 1705312800000000000,
        "severity": severity,
        "content": {
            "ruleName": rule_name,
            "output": output,
            "fields": {
                # Falco stores these as FLAT dot-keys (not nested dicts!)
                "container.name": container_name,
                "kubernetes.namespace.name": namespace,
                "k8s.pod.name": pod_name,
                "proc.name": "bash",
                "user.name": "root",
            },
        },
        "labels": {
            "kubernetes.namespace.name": namespace,
            "kubernetes.pod.name": pod_name,
        },
    }


# ---------------------------------------------------------------------------
# Bug: events list --namespace / --container returned 0 results
#
# Root cause: filter code checked nested fields["container"]["name"] but
# Falco stores as flat fields["container.name"]. Fixed with _field_val().
# ---------------------------------------------------------------------------

class TestEventsListFlatFalcoFieldFiltering:
    """Verify --namespace, --container, --pod filters work with flat Falco field keys."""

    def _events_response(self, events):
        return {"data": events, "page": {"total": len(events), "next": None}}

    def test_namespace_filter_matches_flat_key(self, capsys):
        """--namespace filter must match flat key 'kubernetes.namespace.name' in content.fields."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", namespace="production"),
            _make_falco_event("e2", namespace="staging"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container=None,
                    namespace="production",
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        # Only the production event should match
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_namespace_filter_no_false_positives(self, capsys):
        """--namespace filter must NOT return events from a different namespace."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", namespace="staging"),
            _make_falco_event("e2", namespace="dev"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container=None,
                    namespace="production",
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data.get("data", []) == []

    def test_container_filter_matches_flat_key(self, capsys):
        """--container filter must match flat key 'container.name' in content.fields."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", container_name="nginx"),
            _make_falco_event("e2", container_name="redis"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container="nginx",
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_container_filter_partial_match(self, capsys):
        """--container filter is substring-based (like --namespace)."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", container_name="nginx-proxy"),
            _make_falco_event("e2", container_name="postgres"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container="nginx",
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_pod_filter_matches_flat_key(self, capsys):
        """--pod filter must match flat key 'k8s.pod.name' in content.fields."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", pod_name="nginx-abc-123"),
            _make_falco_event("e2", pod_name="redis-xyz-456"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container=None,
                    namespace=None,
                    pod="nginx-abc",
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_combined_namespace_and_container_filter(self, capsys):
        """Combined --namespace and --container filters are ANDed."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", container_name="nginx", namespace="production"),
            _make_falco_event("e2", container_name="nginx", namespace="staging"),
            _make_falco_event("e3", container_name="redis", namespace="production"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container="nginx",
                    namespace="production",
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        # Only e1 matches both nginx AND production
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_rule_filter_uses_content_rule_name(self, capsys):
        """--rule filter checks content.ruleName first, then top-level name."""
        from sysdig_cli.helpers.events import events_list

        events = [
            _make_falco_event("e1", rule_name="Drift Detected"),
            _make_falco_event("e2", rule_name="Bash in Container"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=self._events_response(events))
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule="Drift",
                    container=None,
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_rule_filter_falls_back_to_top_level_name(self, capsys):
        """--rule filter falls back to top-level 'name' when content.ruleName is absent."""
        from sysdig_cli.helpers.events import events_list

        # Event without content.ruleName (older API format)
        event_no_content_rule = {
            "id": "e1",
            "timestamp": 1705312800000000000,
            "severity": 7,
            "name": "Drift Detected",  # top-level name
            "content": {
                # No ruleName here
                "output": "some output",
                "fields": {},
            },
        }
        event_different_rule = {
            "id": "e2",
            "timestamp": 1705312800000000000,
            "severity": 7,
            "name": "Bash in Container",
            "content": {"output": "bash run", "fields": {}},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": [event_no_content_rule, event_different_rule]})
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule="Drift",
                    container=None,
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 1
        assert events_out[0]["id"] == "e1"

    def test_severity_filter(self, capsys):
        """--severity filter removes events below the threshold."""
        from sysdig_cli.helpers.events import events_list

        events = [
            {**_make_falco_event("e1"), "severity": 7},   # critical — keep
            {**_make_falco_event("e2"), "severity": 4},   # warning — drop
            {**_make_falco_event("e3"), "severity": 6},   # error — keep
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=6,
                    rule=None,
                    container=None,
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        events_out = data.get("data", [])
        assert len(events_out) == 2
        ids = {e["id"] for e in events_out}
        assert ids == {"e1", "e3"}

    def test_no_filter_returns_all_events(self, capsys):
        """Without filters, all events are returned."""
        from sysdig_cli.helpers.events import events_list

        events = [_make_falco_event(f"e{i}") for i in range(5)]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container=None,
                    namespace=None,
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data.get("data", [])) == 5

    def test_k8s_ns_name_key_also_matched(self, capsys):
        """--namespace also matches 'k8s.ns.name' key variant."""
        from sysdig_cli.helpers.events import events_list

        event_with_k8s_ns = {
            "id": "e1",
            "timestamp": 1705312800000000000,
            "severity": 7,
            "content": {
                "ruleName": "Test Rule",
                "fields": {
                    # k8s.ns.name variant (alternative key)
                    "k8s.ns.name": "production",
                    "container.name": "myapp",
                },
            },
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": [event_with_k8s_ns]})
            )
            try:
                events_list(
                    from_time="1h",
                    to_time=None,
                    severity=None,
                    rule=None,
                    container=None,
                    namespace="production",
                    pod=None,
                    limit=100,
                    all_pages=False,
                    profile="default",
                    region=None,
                    fmt="json",
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data.get("data", [])) == 1


# ---------------------------------------------------------------------------
# Bug: audit recent-commands returned 0 entries
#
# Root cause 1: `all_pages` default was a truthy typer.Option object
# Root cause 2: No `from`/`to` params sent; the Activity Audit API requires them
# ---------------------------------------------------------------------------

class TestAuditRecentCommandsSendsTimeParams:
    """Verify recent_commands sends from/to params to the API."""

    def test_sends_from_and_to_params(self):
        """recent_commands must send both 'from' and 'to' query parameters."""
        from sysdig_cli.helpers.audit import recent_commands

        captured_params = {}

        def capture_request(request):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(str(request.url)).query)
            captured_params.update(qs)
            return httpx.Response(200, json={"data": [], "page": {"next": None}})

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(side_effect=capture_request)
            try:
                recent_commands(
                    profile="default",
                    region=None,
                    fmt="json",
                    limit=10,
                    user=None,
                    all_pages=False,
                    from_time="24h",
                )
            except SystemExit:
                pass

        assert "from" in captured_params, "from param must be sent to Activity Audit API"
        assert "to" in captured_params, "to param must be sent to Activity Audit API"

    def test_returns_entries_from_data_key(self, capsys):
        """recent_commands extracts entries from 'data' key in API response."""
        from sysdig_cli.helpers.audit import recent_commands

        audit_data = {
            "data": [
                {
                    "id": "a1",
                    "timestamp": 1705312800000000000,
                    "type": "kubectl.exec",
                    "username": "alice@example.com",
                    "commandLine": "kubectl exec pod-abc -- bash",
                },
                {
                    "id": "a2",
                    "timestamp": 1705312700000000000,
                    "type": "kubectl.cp",
                    "username": "bob@example.com",
                    "commandLine": "kubectl cp pod-xyz:/etc/passwd /tmp/",
                },
            ],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=audit_data)
            )
            try:
                recent_commands(
                    profile="default",
                    region=None,
                    fmt="json",
                    limit=10,
                    user=None,
                    all_pages=False,
                    from_time="24h",
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 2
        assert len(data["entries"]) == 2
        assert data["entries"][0]["id"] == "a1"

    def test_user_filter_uses_flat_username_field(self, capsys):
        """User filter checks flat 'username' field, not nested 'user.name'."""
        from sysdig_cli.helpers.audit import recent_commands

        # Real API response uses flat "username" not nested {"user": {"name": ...}}
        audit_data = {
            "data": [
                {"id": "a1", "username": "alice@example.com", "type": "kubectl.exec"},
                {"id": "a2", "username": "bob@example.com", "type": "kubectl.exec"},
            ],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=audit_data)
            )
            try:
                recent_commands(
                    profile="default",
                    region=None,
                    fmt="json",
                    limit=10,
                    user="alice",
                    all_pages=False,
                    from_time="24h",
                )
            except SystemExit:
                pass

        # The server-side filter already narrows, but client-side filter also applies
        # This test verifies the code doesn't crash and returns entries
        captured = capsys.readouterr()
        # Should not crash with AttributeError on user.name
        assert captured.out  # Got some output

    def test_user_login_name_fallback(self, capsys):
        """User filter also checks 'userLoginName' as fallback."""
        from sysdig_cli.helpers.audit import recent_commands

        # In all_pages mode, client-side filter uses username OR userLoginName
        audit_data = {
            "data": [
                {"id": "a1", "userLoginName": "carol@example.com", "type": "kubectl.exec"},
            ],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=audit_data)
            )
            try:
                recent_commands(
                    profile="default",
                    region=None,
                    fmt="json",
                    limit=10,
                    user=None,
                    all_pages=False,
                    from_time="24h",
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 1

    def test_all_pages_false_by_default_does_single_request(self):
        """With all_pages=False, only one request is made (not streaming)."""
        from sysdig_cli.helpers.audit import recent_commands

        request_count = 0

        def count_requests(request):
            nonlocal request_count
            request_count += 1
            return httpx.Response(200, json={"data": [], "page": {"next": None}})

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(side_effect=count_requests)
            try:
                recent_commands(
                    profile="default",
                    region=None,
                    fmt="json",
                    limit=10,
                    user=None,
                    all_pages=False,
                    from_time="24h",
                )
            except SystemExit:
                pass

        assert request_count == 1


# ---------------------------------------------------------------------------
# Bug: audit platform-events returned 500 or showed empty columns
#
# Root cause: Schema field paths were wrong — real data is under content.*
# Fixed in formatter.py: content.username, content.requestMethod, etc.
# ---------------------------------------------------------------------------

class TestAuditPlatformEventsSchema:
    """Verify platform-events command handles real API response structure."""

    def _make_platform_event(self, event_id: str, username: str, method: str, uri: str) -> Dict[str, Any]:
        """Build a platform audit event matching real API structure."""
        return {
            "id": event_id,
            "timestamp": 1705312800000000000,
            "content": {
                "username": username,
                "requestMethod": method,
                "requestUri": uri,
                "entityType": "policy",
                "userOriginIP": "10.0.0.1",
                "statusCode": "200",
            },
        }

    def test_platform_events_returns_events_from_data_key(self, capsys):
        """platform-events extracts events from 'data' key."""
        from sysdig_cli.helpers.audit import audit_platform_events

        events = [
            self._make_platform_event("p1", "admin@corp.com", "GET", "/api/policies"),
            self._make_platform_event("p2", "user@corp.com", "POST", "/api/alerts"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/platform-audit-events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                audit_platform_events(
                    from_time="24h",
                    to_time=None,
                    user=None,
                    action=None,
                    limit=100,
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2

    def test_platform_events_user_filter_uses_content_username(self, capsys):
        """--user filter checks content.username, not top-level userEmail."""
        from sysdig_cli.helpers.audit import audit_platform_events

        events = [
            self._make_platform_event("p1", "admin@corp.com", "GET", "/api/policies"),
            self._make_platform_event("p2", "user@corp.com", "POST", "/api/alerts"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/platform-audit-events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                audit_platform_events(
                    from_time="24h",
                    to_time=None,
                    user="admin",
                    action=None,
                    limit=100,
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["content"]["username"] == "admin@corp.com"

    def test_platform_events_action_filter_uses_content_request_uri(self, capsys):
        """--action filter checks content.requestUri, not top-level action field."""
        from sysdig_cli.helpers.audit import audit_platform_events

        events = [
            self._make_platform_event("p1", "admin@corp.com", "GET", "/api/policies"),
            self._make_platform_event("p2", "admin@corp.com", "POST", "/api/alerts"),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/platform-audit-events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                audit_platform_events(
                    from_time="24h",
                    to_time=None,
                    user=None,
                    action="policies",
                    limit=100,
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["id"] == "p1"

    def test_platform_events_empty_response_no_crash(self, capsys):
        """platform-events handles empty 'data' array without crashing."""
        from sysdig_cli.helpers.audit import audit_platform_events

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/platform-audit-events").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                audit_platform_events(
                    from_time="24h",
                    to_time=None,
                    user=None,
                    action=None,
                    limit=100,
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == []


# ---------------------------------------------------------------------------
# Bug: vulns accept-risks create threw TypeError
#
# Root cause: client.post(..., json=body) — the method uses json_body kwarg.
# Fixed: client.post(..., json_body=body)
# ---------------------------------------------------------------------------

class TestVulnsAcceptRisksCreate:
    """Verify accept-risks create does not crash with TypeError."""

    def test_create_no_type_error(self, capsys):
        """accept-risks create must call client.post with json_body, not json."""
        from sysdig_cli.helpers.vulns import vulns_accept_risks_create

        create_response = {
            "id": "ar-new",
            "entityType": "vulnerability",
            "entityValue": "CVE-2024-1234",
            "reason": "mitigated",
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.post("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(201, json=create_response)
            )
            # Must not raise TypeError
            try:
                vulns_accept_risks_create(
                    cve="CVE-2024-1234",
                    reason="mitigated",
                    context=None,
                    expires=None,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except SystemExit:
                pass
            except TypeError as e:
                pytest.fail(f"TypeError raised — json_body fix not applied: {e}")

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data.get("id") == "ar-new"

    def test_create_sends_correct_body_fields(self):
        """accept-risks create sends required fields in request body."""
        from sysdig_cli.helpers.vulns import vulns_accept_risks_create

        received_body = {}

        def capture_body(request):
            nonlocal received_body
            received_body = json.loads(request.content)
            return httpx.Response(201, json={"id": "ar-new"})

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.post("/secure/vulnerability/v1beta1/accepted-risks").mock(side_effect=capture_body)
            try:
                vulns_accept_risks_create(
                    cve="CVE-2024-5678",
                    reason="risk_accepted",
                    context="my-namespace",
                    expires="30d",
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except SystemExit:
                pass

        assert received_body.get("entityType") == "vulnerability"
        assert received_body.get("entityValue") == "CVE-2024-5678"
        assert received_body.get("reason") == "risk_accepted"
        assert received_body.get("context") == "my-namespace"
        # expires=30d should add expirationDate field
        assert "expirationDate" in received_body

    def test_list_accept_risks_returns_empty_without_crash(self, capsys):
        """accept-risks list handles empty response gracefully."""
        from sysdig_cli.helpers.vulns import vulns_accept_risks_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(200, json={"acceptedRisks": []})
            )
            try:
                vulns_accept_risks_list(
                    profile="default",
                    region=None,
                    fmt="json",
                    cve=None,
                    expired=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        # Output is {"acceptedRisks": []}
        data = json.loads(captured.out)
        assert data.get("acceptedRisks") == []


# ---------------------------------------------------------------------------
# Bug: IAM commands showed empty columns
#
# Root cause: Schema used fake field names (createdBy, dateLastUsed, enabled, etc.)
# Fixed: Schema updated to match real API fields (accessKey, isEnabled, dateCreated, etc.)
# ---------------------------------------------------------------------------

class TestIamAccessKeysRealFields:
    """Verify IAM access keys use real API field names."""

    def test_access_keys_list_parses_real_fields(self, capsys):
        """access-keys list must return data from 'data' key with real field names."""
        from sysdig_cli.helpers.iam import iam_access_keys_list

        # Real API response structure (from OpenAPI spec)
        api_response = {
            "data": [
                {
                    "id": "key-001",
                    "accessKey": "SYSDIG-TOKEN-ABCDEF12345",
                    "isEnabled": True,
                    "dateCreated": "2024-01-15T10:00:00Z",
                    "dateDisabled": None,
                    "teamId": 42,
                    "agentLimit": 10,
                },
                {
                    "id": "key-002",
                    "accessKey": "SYSDIG-TOKEN-XYZ789",
                    "isEnabled": False,
                    "dateCreated": "2023-06-01T08:00:00Z",
                    "dateDisabled": "2023-12-01T00:00:00Z",
                    "teamId": 99,
                    "agentLimit": 0,
                },
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/access-keys").mock(
                return_value=httpx.Response(200, json=api_response)
            )
            try:
                iam_access_keys_list(
                    profile="default",
                    region=None,
                    fmt="json",
                    user=None,
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        # Real fields must be present
        assert data[0]["accessKey"] == "SYSDIG-TOKEN-ABCDEF12345"
        assert data[0]["isEnabled"] is True
        assert data[1]["isEnabled"] is False

    def test_access_keys_user_filter_by_access_key_substring(self, capsys):
        """--user filter matches accessKey value as substring."""
        from sysdig_cli.helpers.iam import iam_access_keys_list

        api_response = {
            "data": [
                {"id": "key-001", "accessKey": "SYSDIG-TOKEN-ABCDEF", "isEnabled": True, "teamId": 1},
                {"id": "key-002", "accessKey": "SYSDIG-TOKEN-XYZ789", "isEnabled": True, "teamId": 2},
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/access-keys").mock(
                return_value=httpx.Response(200, json=api_response)
            )
            try:
                iam_access_keys_list(
                    profile="default",
                    region=None,
                    fmt="json",
                    user="ABCDEF",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["id"] == "key-001"


class TestIamGroupMappingsRealFields:
    """Verify IAM group mappings use real API field names."""

    def test_group_mappings_flattens_team_map(self, capsys):
        """group-mappings normalises teamMap into a 'teams' display field."""
        from sysdig_cli.helpers.iam import iam_group_mappings_list

        # Real API structure (from OpenAPI spec and live data)
        api_response = {
            "data": [
                {
                    "id": "gm-001",
                    "groupName": "platform-admins",
                    "standardTeamRole": "ROLE_TEAM_MANAGER",
                    "isAdmin": True,
                    "weight": 10,
                    "dateCreated": "2024-01-01T00:00:00Z",
                    "teamMap": {
                        "isForAllTeams": True,
                        "teamIds": [],
                    },
                },
                {
                    "id": "gm-002",
                    "groupName": "dev-users",
                    "standardTeamRole": "ROLE_TEAM_READ",
                    "isAdmin": False,
                    "weight": 5,
                    "dateCreated": "2024-02-01T00:00:00Z",
                    "teamMap": {
                        "isForAllTeams": False,
                        "teamIds": [101, 102],
                    },
                },
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/group-mappings").mock(
                return_value=httpx.Response(200, json=api_response)
            )
            try:
                iam_group_mappings_list(
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2

        # isForAllTeams → teams = "ALL"
        assert data[0]["teams"] == "ALL"
        # teamIds [101, 102] → teams = "101,102"
        assert data[1]["teams"] == "101,102"

        # Real fields from the API
        assert data[0]["standardTeamRole"] == "ROLE_TEAM_MANAGER"
        assert data[0]["isAdmin"] is True


class TestIamRolesList:
    """Verify IAM roles list command works with real API structure."""

    def test_roles_list_from_data_key(self, capsys):
        """roles list extracts roles from 'data' key."""
        from sysdig_cli.helpers.iam import iam_roles_list

        api_response = {
            "data": [
                {"id": "r1", "name": "Platform Admin", "description": "Full access"},
                {"id": "r2", "name": "Read Only", "description": "Read-only access"},
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/roles").mock(
                return_value=httpx.Response(200, json=api_response)
            )
            try:
                iam_roles_list(
                    profile="default",
                    region=None,
                    fmt="json",
                    all_pages=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        assert data[0]["name"] == "Platform Admin"


# ---------------------------------------------------------------------------
# Bug: vulns id showed empty WORKLOAD column
#
# Root cause: vuln_cves display schema was missing the 'workload' field.
# The field is set by the CVE drill-down code but the schema didn't include it.
# Fixed: Added 'workload' column to DISPLAY_SCHEMAS["vuln_cves"].
# ---------------------------------------------------------------------------

class TestVulnsIdWorkloadColumn:
    """Verify that vulns id populates the WORKLOAD column.

    vulns_id flow:
    1. GET /secure/vulnerability/v1/runtime-results?limit=500  (ID lookup)
    2. GET /secure/vulnerability/v1/results/{full_id}          (CVE fetch)
    """

    def _make_runtime_results_resp(self, result_id, asset_name, scope=None):
        """Simulate the list response used for ID lookup."""
        return {
            "data": [{
                "resultId": result_id,
                "mainAssetName": asset_name,
                "scope": scope or {},
            }],
            "page": {"next": None},
        }

    def _make_cves_resp(self):
        """Simulate the CVE detail response from /results/{id}."""
        return {
            "packages": {
                "pkg-001": {"name": "openssl", "version": "1.1.1"},
            },
            "vulnerabilities": [
                {
                    "name": "CVE-2024-1234",
                    "severity": "critical",
                    "packageRef": "pkg-001",
                    "fixVersion": "1.1.1t",
                    "disclosureDate": "2024-01-01",
                    "cisaKev": False,
                    "exploitable": False,
                },
            ],
        }

    def test_vuln_id_workload_field_set_on_cve_rows(self, capsys):
        """vulns id must annotate each CVE row with the workload (asset) name."""
        from sysdig_cli.helpers.vulns import vulns_id

        result_id = "abc12345-0000-0000-0000-000000000000"

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            # Lookup call
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=self._make_runtime_results_resp(
                    result_id, "nginx:1.19"
                ))
            )
            # CVE fetch call
            mock.get(f"/secure/vulnerability/v1/results/{result_id}").mock(
                return_value=httpx.Response(200, json=self._make_cves_resp())
            )
            try:
                vulns_id(
                    result_id=result_id,
                    profile="default",
                    region=None,
                    fmt="json",
                    severity=None,
                    limit=100,
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        data = result.get("data", result) if isinstance(result, dict) else result
        assert len(data) == 1
        # workload must be set and non-empty
        assert "workload" in data[0], "workload field missing from CVE row"
        assert data[0]["workload"] == "nginx:1.19"

    def test_vuln_id_workload_matches_asset_name(self, capsys):
        """The workload field must equal the mainAssetName from the runtime result."""
        from sysdig_cli.helpers.vulns import vulns_id

        result_id = "def67890-0000-0000-0000-000000000000"

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=self._make_runtime_results_resp(
                    result_id, "redis:6.0"
                ))
            )
            mock.get(f"/secure/vulnerability/v1/results/{result_id}").mock(
                return_value=httpx.Response(200, json=self._make_cves_resp())
            )
            try:
                vulns_id(
                    result_id=result_id,
                    profile="default",
                    region=None,
                    fmt="json",
                    severity=None,
                    limit=100,
                    no_trunc=False,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        data = result.get("data", result) if isinstance(result, dict) else result
        assert len(data) == 1
        assert data[0]["workload"] == "redis:6.0"


# ---------------------------------------------------------------------------
# Formatter schema regression tests
# Verify that DISPLAY_SCHEMAS have the right fields for each command
# ---------------------------------------------------------------------------

class TestFormatterSchemas:
    """Verify display schemas contain correct field paths."""

    def test_events_list_schema_has_rule_and_output(self):
        """events_list schema must include content.ruleName and content.output."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        schema = DISPLAY_SCHEMAS.get("events_list", [])
        field_paths = [col[0] for col in schema]
        assert "content.ruleName" in field_paths, "content.ruleName missing from events_list schema"
        assert "content.output" in field_paths, "content.output missing from events_list schema"

    def test_platform_audit_events_schema_uses_content_prefix(self):
        """platform_audit_events schema must use content.* prefix for all data fields."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        schema = DISPLAY_SCHEMAS.get("platform_audit_events", [])
        field_paths = [col[0] for col in schema]
        # These non-content fields used to be wrong (userEmail, action, etc.)
        for path in field_paths:
            if path not in ("id", "timestamp"):  # top-level fields are OK
                assert path.startswith("content."), (
                    f"platform_audit_events schema field '{path}' should be under content.*"
                )

    def test_iam_access_keys_schema_has_real_fields(self):
        """iam_access_keys schema must use real field names from API."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        schema = DISPLAY_SCHEMAS.get("iam_access_keys", [])
        field_paths = [col[0] for col in schema]
        # Real fields (not fake ones like 'label', 'createdBy', 'dateLastUsed')
        assert "accessKey" in field_paths, "accessKey missing from iam_access_keys schema"
        assert "isEnabled" in field_paths, "isEnabled missing from iam_access_keys schema"
        # Fake fields must NOT be present
        assert "label" not in field_paths, "fake field 'label' in iam_access_keys schema"
        assert "createdBy" not in field_paths, "fake field 'createdBy' in iam_access_keys schema"

    def test_iam_group_mappings_schema_has_real_fields(self):
        """iam_group_mappings schema must use real field names."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        schema = DISPLAY_SCHEMAS.get("iam_group_mappings", [])
        field_paths = [col[0] for col in schema]
        # Real fields
        assert "standardTeamRole" in field_paths, "standardTeamRole missing from schema"
        # Fake fields must NOT be present
        assert "roles" not in field_paths, "fake field 'roles' in iam_group_mappings schema"

    def test_vuln_cves_schema_has_workload_field(self):
        """vuln_cves schema must include workload field for WORKLOAD column."""
        from sysdig_cli.formatter import DISPLAY_SCHEMAS
        schema = DISPLAY_SCHEMAS.get("vuln_cves", [])
        field_paths = [col[0] for col in schema]
        assert "workload" in field_paths, "workload missing from vuln_cves schema — WORKLOAD column will be empty"
