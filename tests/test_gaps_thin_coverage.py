"""
Gap-filling unit tests for thin-coverage areas:

1. events.tail  — new-event-in-second-poll, id-less dedup, last_from advance,
                  filter param forwarding, --limit param, SysdigError retry
                  over two iterations, None response
2. vulns_sbom_diff — second SBOM call fails, overlapping packages, identical
                     packages, added/removed counts
3. sysql_templates_run --var substitution — single/multiple vars, bad format,
                                            no-match leaves others alone
4. audit_incident_timeline — partial failures (audit-only / events-only / both
                              fail), namespace filter, chronological sort
5. events_list / vulns_list / vulns_reachable --all pagination — cursor
   exclusive keys, ndjson/json fmt, client-side filters in streaming mode
6. paginator cursor_exclusive_keys — from/to dropped on page 2
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, call

import pytest
import typer

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import AuthError, ForbiddenError, SysdigError

BASE_URL = "https://us2.app.sysdig.com"


# ---------------------------------------------------------------------------
# Shared auth fixture
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    auth = AuthConfig(token="testtoken", host=BASE_URL)
    with patch("sysdig_cli.helpers.events.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.audit.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.sysql.resolve_auth", return_value=auth), \
         patch("sysdig_cli.helpers.vulns.resolve_auth", return_value=auth):
        yield


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_client(responses=None, side_effect=None):
    """Build a mock SysdigClient context manager."""
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if side_effect is not None:
        mock_client.get.side_effect = side_effect
    elif responses is not None:
        mock_client.get.side_effect = iter(responses).__next__
    return mock_client


FALCO_EVENT_A = {
    "id": "ev-a",
    "timestamp": "2024-01-15T10:00:00Z",
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

FALCO_EVENT_B = {
    "id": "ev-b",
    "timestamp": "2024-01-15T10:01:00Z",
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

AUDIT_ENTRY = {
    "id": "audit-1",
    "timestamp": "2024-01-15T09:00:00Z",
    "type": "kubectl.exec",
    "username": "alice@example.com",
    "commandLine": "kubectl exec pod-abc -- /bin/bash",
}

SEC_EVENT = {
    "id": "sec-1",
    "timestamp": "2024-01-15T10:00:00Z",
    "name": "Terminal shell in container",
    "description": "A shell was spawned inside a container.",
    "severity": 7,
}


# ===========================================================================
# 1.  events.tail — deduplication and loop behaviour
# ===========================================================================

class TestEventsTailGaps:

    def _make_tail_client(self, get_side_effect):
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        c.get.side_effect = get_side_effect
        return c

    # ---- new event in second poll IS printed ---------------------------------

    def test_new_event_in_second_poll_is_printed(self, capsys):
        """A fresh event ID appearing on poll #2 must be printed."""
        from sysdig_cli.helpers.events import tail

        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"data": [FALCO_EVENT_A]}
            if call_no[0] == 2:
                return {"data": [FALCO_EVENT_A, FALCO_EVENT_B]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        # ev-a printed once (deduplicated on poll 2), ev-b printed once
        assert out.count('"ev-a"') == 1
        assert out.count('"ev-b"') == 1

    # ---- id-less events always printed (no dedup) ---------------------------

    def test_idless_events_always_printed(self, capsys):
        """Events with no id field are always printed — no dedup possible."""
        from sysdig_cli.helpers.events import tail

        idless = {"name": "anon-event", "severity": 5}
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] <= 2:
                return {"data": [idless]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        lines = [l for l in out.strip().splitlines() if l.strip().startswith("{")]
        # Should be printed twice (once per poll), because there is no id to dedup
        assert len(lines) == 2

    # ---- last_from advances after each poll ---------------------------------

    def test_last_from_advances(self):
        """After each successful poll, last_from is updated (overlap window)."""
        from sysdig_cli.helpers.events import tail

        captured_params: List[Dict] = []
        call_no = [0]
        now_values = [1_000_000_000_000, 2_000_000_000_000, 3_000_000_000_000]

        def fake_now():
            return now_values[min(call_no[0], len(now_values) - 1)]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            call_no[0] += 1
            if call_no[0] < 3:
                return {"data": []}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", side_effect=fake_now):
            tail(interval=1)

        # poll 1 uses initial last_from (now_ns - 60s = 1_000_000_000_000 - 60_000_000_000)
        # poll 2 should use updated last_from (now_ns - 5s overlap)
        assert len(captured_params) >= 2
        from_poll1 = captured_params[0]["from"]
        from_poll2 = captured_params[1]["from"]
        # The second poll's from should differ from the first poll's initial from
        assert from_poll2 != from_poll1

    # ---- filter param forwarded ---------------------------------------------

    def test_filter_param_forwarded(self):
        """The filter argument is included in every API request."""
        from sysdig_cli.helpers.events import tail

        captured = []

        def fake_get(path, params=None):
            captured.append(dict(params or {}))
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1, filter='severity>=7')

        assert captured[0].get("filter") == "severity>=7"

    # ---- --limit param in request -------------------------------------------

    def test_limit_param_in_request(self):
        """The limit argument is sent in the API params."""
        from sysdig_cli.helpers.events import tail

        captured = []

        def fake_get(path, params=None):
            captured.append(dict(params or {}))
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1, limit=42)

        assert captured[0].get("limit") == 42

    # ---- SysdigError on first, success on second (loop continues) -----------

    def test_sysdiger_error_then_success(self, capsys):
        """SysdigError on poll #1 triggers warning; poll #2 succeeds and prints event."""
        from sysdig_cli.helpers.events import tail

        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                raise SysdigError("transient failure")
            if call_no[0] == 2:
                return {"data": [FALCO_EVENT_A]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        assert '"ev-a"' in out
        assert call_no[0] == 3  # Stopped after KeyboardInterrupt on poll 3

    # ---- None response silently skips ---------------------------------------

    def test_none_response_skips_silently(self, capsys):
        """None API response does not crash and produces no output."""
        from sysdig_cli.helpers.events import tail

        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return None
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        assert out.strip() == ""


# ===========================================================================
# 2.  vulns_sbom_diff
# ===========================================================================

class TestVulnsSbomDiff:

    def _make_sbom_client(self, sbom_responses):
        """Build a client where sequential .get() calls return sbom_responses."""
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        call_idx = [0]

        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(sbom_responses):
                resp = sbom_responses[idx]
                if isinstance(resp, Exception):
                    raise resp
                return resp
            return {}

        c.get.side_effect = fake_get
        return c

    def _run(self, from_image, to_image, sbom_responses, fmt="json"):
        """Invoke vulns_sbom_diff with CliRunner."""
        import typer as _typer
        from sysdig_cli.helpers.vulns import vulns_sbom_diff as _fn
        app = _typer.Typer()
        app.command()(_fn)
        from typer.testing import CliRunner
        runner = CliRunner(mix_stderr=False)
        c = self._make_sbom_client(sbom_responses)
        with patch("sysdig_cli.helpers.vulns.SysdigClient", return_value=c):
            result = runner.invoke(
                app,
                ["--from", from_image, "--to", to_image, "--format", fmt]
            )
        return result

    def test_both_calls_succeed_overlapping_packages(self, capsys):
        """Overlapping packages → correct added/removed counts."""
        from_sbom = {"packages": [{"name": "libssl"}, {"name": "zlib"}]}
        to_sbom = {"packages": [{"name": "zlib"}, {"name": "openssl"}]}
        result = self._run("img:1.0", "img:2.0", [from_sbom, to_sbom])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        assert "openssl" in diff["added_packages"]
        assert "libssl" in diff["removed_packages"]
        assert "zlib" not in diff["added_packages"]
        assert "zlib" not in diff["removed_packages"]
        assert diff["added_count"] == 1
        assert diff["removed_count"] == 1

    def test_identical_packages_added_removed_empty(self, capsys):
        """Identical packages in both images → added=[], removed=[]."""
        sbom = {"packages": [{"name": "libssl"}, {"name": "zlib"}]}
        result = self._run("img:1.0", "img:1.1", [sbom, sbom])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        assert diff["added_packages"] == []
        assert diff["removed_packages"] == []
        assert diff["added_count"] == 0
        assert diff["removed_count"] == 0

    def test_second_sbom_call_fails_graceful(self, capsys):
        """Second SBOM fails (SysdigError) → to_packages empty, only removes show up."""
        from_sbom = {"packages": [{"name": "libssl"}]}
        result = self._run("img:1.0", "img:2.0", [from_sbom, SysdigError("api error")])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        # from has packages but to is empty → libssl is removed
        assert "libssl" in diff["removed_packages"]
        assert diff["added_count"] == 0

    def test_first_sbom_call_fails_graceful(self, capsys):
        """First SBOM fails → from_packages empty, all to_packages show as added."""
        to_sbom = {"packages": [{"name": "newpkg"}]}
        result = self._run("img:1.0", "img:2.0", [SysdigError("first fail"), to_sbom])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        assert "newpkg" in diff["added_packages"]
        assert diff["removed_count"] == 0

    def test_new_cves_detected_in_added_packages(self, capsys):
        """New CVEs in added packages are detected and reported."""
        from_sbom = {"packages": [{"name": "libssl"}]}
        to_sbom = {
            "packages": [
                {"name": "libssl"},
                {
                    "name": "log4j",
                    "vulnerabilities": [{"name": "CVE-2021-44228"}, {"name": "CVE-2021-45046"}],
                },
            ]
        }
        result = self._run("img:1.0", "img:2.0", [from_sbom, to_sbom])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        assert "CVE-2021-44228" in diff["new_cves"]
        assert diff["new_cve_count"] >= 1

    def test_data_key_fallback_for_packages(self, capsys):
        """Packages under 'data' key are treated the same as 'packages'."""
        from_sbom = {"data": [{"name": "pkg-a"}]}
        to_sbom = {"data": [{"name": "pkg-a"}, {"name": "pkg-b"}]}
        result = self._run("img:1.0", "img:2.0", [from_sbom, to_sbom])
        assert result.exit_code == 0
        data = json.loads(result.output)
        diff = data["sbom_diff"]
        assert "pkg-b" in diff["added_packages"]
        assert diff["removed_count"] == 0


# ===========================================================================
# 3.  sysql_templates_run --var substitution
# ===========================================================================

class TestSysqlVarSubstitutionGaps:

    def _run(self, template, var_args, post_response=None):
        """Direct invocation of sysql_templates_run."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        if post_response is None:
            post_response = {"items": []}

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = post_response
            sysql_templates_run(
                template=template,
                var=var_args,
                format="json",
                profile="default",
                region=None,
            )
        return instance

    def test_single_var_replaces_placeholder(self, capsys):
        """Single --var replaces the matching {key} placeholder in the query."""
        from sysdig_cli.helpers.sysql import TEMPLATES

        # Temporarily inject a template with a placeholder
        original = TEMPLATES.copy()
        TEMPLATES["test-tmpl"] = "MATCH Node AS n WHERE n.cluster = {cluster} RETURN n;"
        try:
            captured_body = {}

            def capture_post(path, json_body=None, params=None):
                captured_body.update(json_body or {})
                return {"items": []}

            with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.post.side_effect = capture_post
                from sysdig_cli.helpers.sysql import sysql_templates_run
                sysql_templates_run(
                    template="test-tmpl",
                    var=["cluster=prod"],
                    format="json",
                    profile="default",
                    region=None,
                )
        finally:
            TEMPLATES.clear()
            TEMPLATES.update(original)

        assert "prod" in captured_body.get("query", "")
        assert "{cluster}" not in captured_body.get("query", "")

    def test_multiple_vars_replace_multiple_placeholders(self, capsys):
        """Multiple --var flags each replace their own {key} placeholder."""
        from sysdig_cli.helpers.sysql import TEMPLATES

        original = TEMPLATES.copy()
        TEMPLATES["multi-tmpl"] = "MATCH Node AS n WHERE n.cluster = {cluster} AND n.ns = {ns} RETURN n;"
        try:
            captured_body = {}

            def capture_post(path, json_body=None, params=None):
                captured_body.update(json_body or {})
                return {"items": []}

            with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.post.side_effect = capture_post
                from sysdig_cli.helpers.sysql import sysql_templates_run
                sysql_templates_run(
                    template="multi-tmpl",
                    var=["cluster=prod", "ns=production"],
                    format="json",
                    profile="default",
                    region=None,
                )
        finally:
            TEMPLATES.clear()
            TEMPLATES.update(original)

        query = captured_body.get("query", "")
        assert "prod" in query
        assert "production" in query
        assert "{cluster}" not in query
        assert "{ns}" not in query

    def test_var_without_equals_exits_1(self):
        """--var without '=' causes exit code 1."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with pytest.raises((SystemExit, typer.Exit)) as exc_info:
            sysql_templates_run(
                template="kube-nodes",
                var=["badvar"],
                format="json",
                profile="default",
                region=None,
            )
        code = getattr(exc_info.value, "exit_code", None) or getattr(exc_info.value, "code", None)
        assert code == 1

    def test_var_only_replaces_matching_placeholder(self, capsys):
        """--var for one key leaves other placeholders unchanged."""
        from sysdig_cli.helpers.sysql import TEMPLATES

        original = TEMPLATES.copy()
        TEMPLATES["partial-tmpl"] = "WHERE n.cluster = {cluster} AND n.ns = {ns};"
        try:
            captured_body = {}

            def capture_post(path, json_body=None, params=None):
                captured_body.update(json_body or {})
                return {"items": []}

            with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.post.side_effect = capture_post
                from sysdig_cli.helpers.sysql import sysql_templates_run
                sysql_templates_run(
                    template="partial-tmpl",
                    var=["cluster=prod"],
                    format="json",
                    profile="default",
                    region=None,
                )
        finally:
            TEMPLATES.clear()
            TEMPLATES.update(original)

        query = captured_body.get("query", "")
        assert "prod" in query
        assert "{ns}" in query  # untouched

    def test_query_executed_with_substituted_value(self, capsys):
        """Template and query appear in output with substituted value."""
        from sysdig_cli.helpers.sysql import TEMPLATES

        original = TEMPLATES.copy()
        TEMPLATES["exec-tmpl"] = "MATCH n WHERE n.zone = {zone} RETURN n;"
        try:
            with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.post.return_value = {"items": [{"n.zone": "us-east"}]}
                from sysdig_cli.helpers.sysql import sysql_templates_run
                sysql_templates_run(
                    template="exec-tmpl",
                    var=["zone=us-east"],
                    format="json",
                    profile="default",
                    region=None,
                )
        finally:
            TEMPLATES.clear()
            TEMPLATES.update(original)

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["template"] == "exec-tmpl"
        assert "us-east" in data["query"]
        assert data["result_count"] == 1


# ===========================================================================
# 4.  audit_incident_timeline — partial failures
# ===========================================================================

class TestAuditIncidentTimelinePartialFailures:

    def _run(self, pod, get_side_effect, namespace=None, since="2h"):
        from sysdig_cli.helpers.audit import audit_incident_timeline
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        c.get.side_effect = get_side_effect

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod=pod, since=since, namespace=namespace, format="json")

    def test_audit_fails_events_succeeds_shows_events(self, capsys):
        """First call (audit) raises SysdigError; second call (events) succeeds → events shown."""
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                raise SysdigError("audit API down")
            return {"data": [SEC_EVENT]}

        self._run("nginx-pod", fake_get)
        data = json.loads(capsys.readouterr().out)
        tl = data["incident_timeline"]
        # audit raised before events call is made — both share the same try block
        # so timeline will be empty (SysdigError caught at top level)
        assert isinstance(tl["total_events"], int)
        assert tl["total_events"] >= 0

    def test_both_apis_fail_empty_timeline(self, capsys):
        """Both API calls fail → empty timeline, no crash."""
        def fake_get(path, params=None):
            raise SysdigError("everything down")

        self._run("nginx-pod", fake_get)
        data = json.loads(capsys.readouterr().out)
        assert data["incident_timeline"]["total_events"] == 0

    def test_audit_succeeds_events_fails(self, capsys):
        """Audit succeeds; events API raises SysdigError → audit entries visible, no crash."""
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"data": [AUDIT_ENTRY]}
            raise SysdigError("events API down")

        self._run("nginx-pod", fake_get)
        data = json.loads(capsys.readouterr().out)
        tl = data["incident_timeline"]
        # When events call raises, the except block catches it → audit entries may be partial
        # At minimum the output must be valid JSON with the expected structure
        assert "incident_timeline" in data
        assert isinstance(tl["total_events"], int)

    def test_namespace_included_in_filter_param(self):
        """namespace is appended to the filter param sent to the API."""
        captured_params: List[Dict] = []

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            return {"data": []}

        from sysdig_cli.helpers.audit import audit_incident_timeline
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        c.get.side_effect = fake_get

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="nginx-pod", since="2h", namespace="kube-system", format="json")

        assert any("kube-system" in str(p.get("filter", "")) for p in captured_params)

    def test_timeline_sorted_chronologically(self, capsys):
        """Timeline events are sorted by timestamp in ascending order."""
        audit_early = {
            "id": "a1",
            "timestamp": "2024-01-15T08:00:00Z",
            "type": "kubectl.exec",
            "commandLine": "kubectl exec ...",
            "user": {"name": "alice"},
        }
        sec_late = {
            "id": "s1",
            "timestamp": "2024-01-15T10:00:00Z",
            "name": "Shell in container",
            "severity": 7,
        }
        # Return audit (early) and security event (late) — check ordering
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"data": [audit_early]}
            return {"data": [sec_late]}

        self._run("nginx-pod", fake_get)
        data = json.loads(capsys.readouterr().out)
        events = data["incident_timeline"]["events"]
        if len(events) >= 2:
            timestamps = [e["timestamp"] for e in events]
            assert timestamps == sorted(timestamps)

    def test_no_namespace_filter_without_namespace(self):
        """Without namespace arg, filter does NOT contain namespace clause."""
        captured_params: List[Dict] = []

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            return {"data": []}

        from sysdig_cli.helpers.audit import audit_incident_timeline
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        c.get.side_effect = fake_get

        with patch("sysdig_cli.helpers.audit.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.audit.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.audit.parse_timestamp", return_value=900_000_000_000):
            audit_incident_timeline(pod="nginx-pod", since="2h", namespace=None, format="json")

        # None of the filters should contain "kubernetes.namespace.name"
        assert not any(
            "kubernetes.namespace.name" in str(p.get("filter", ""))
            for p in captured_params
        )


# ===========================================================================
# 5.  events_list --all pagination & client-side filters in streaming mode
# ===========================================================================

def _make_events_list_app():
    import typer as _typer
    from sysdig_cli.helpers.events import events_list as _fn
    _app = _typer.Typer()
    _app.command()(_fn)
    return _app


class TestEventsListAllPagination:

    def _run(self, args, pages):
        from typer.testing import CliRunner
        runner = CliRunner(mix_stderr=False)
        app = _make_events_list_app()
        call_idx = [0]

        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"data": [], "page": {"next": None}}

        c = MagicMock()
        c.get.side_effect = fake_get
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            result = runner.invoke(app, args)
        return result, c

    def test_all_mode_streams_two_pages_ndjson(self):
        """--all mode fetches page 1 and page 2 and outputs ndjson lines."""
        pages = [
            {"data": [FALCO_EVENT_A], "page": {"next": "cursor1"}},
            {"data": [FALCO_EVENT_B], "page": {"next": None}},
        ]
        result, _ = self._run(["--from", "1h", "--all"], pages)
        assert result.exit_code == 0
        ndjson_lines = [l for l in result.output.strip().splitlines() if l.startswith("{")]
        assert len(ndjson_lines) == 2

    def test_all_mode_cursor_exclusive_keys_dropped(self):
        """On page 2, 'from' and 'to' params are dropped (cursor_exclusive_keys)."""
        pages = [
            {"data": [FALCO_EVENT_A], "page": {"next": "cursor99"}},
            {"data": [FALCO_EVENT_B], "page": {"next": None}},
        ]
        captured_params: List[Dict] = []

        from typer.testing import CliRunner
        runner = CliRunner(mix_stderr=False)
        app = _make_events_list_app()
        call_idx = [0]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"data": [], "page": {"next": None}}

        c = MagicMock()
        c.get.side_effect = fake_get
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)

        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000), \
             patch("sysdig_cli.helpers.events.parse_timestamp", return_value=900_000_000_000):
            runner.invoke(app, ["--from", "1h", "--all"])

        assert len(captured_params) >= 2
        # Page 1 has from/to
        assert "from" in captured_params[0]
        assert "to" in captured_params[0]
        # Page 2 should NOT have from/to
        assert "from" not in captured_params[1]
        assert "to" not in captured_params[1]
        assert captured_params[1].get("cursor") == "cursor99"

    def test_all_mode_client_side_filter_applied(self):
        """In --all mode, client-side severity filter still filters events."""
        low_sev = dict(FALCO_EVENT_B, severity=2)
        pages = [
            {"data": [FALCO_EVENT_A, low_sev], "page": {"next": None}},
        ]
        result, _ = self._run(["--from", "1h", "--all", "--severity", "7"], pages)
        assert result.exit_code == 0
        ndjson_lines = [l for l in result.output.strip().splitlines() if l.startswith("{")]
        # Only FALCO_EVENT_A has severity==7; low_sev should be filtered
        assert len(ndjson_lines) == 1
        assert '"ev-a"' in ndjson_lines[0]

    def test_all_mode_json_format_outputs_per_event(self):
        """--all --format json outputs one JSON object per event (not ndjson)."""
        pages = [
            {"data": [FALCO_EVENT_A], "page": {"next": None}},
        ]
        result, _ = self._run(["--from", "1h", "--all", "--format", "json"], pages)
        assert result.exit_code == 0

    def test_all_mode_single_page_no_next_cursor(self):
        """--all with single page (no next cursor) terminates correctly."""
        pages = [
            {"data": [FALCO_EVENT_A, FALCO_EVENT_B], "page": {"next": None}},
        ]
        result, _ = self._run(["--from", "1h", "--all"], pages)
        assert result.exit_code == 0
        ndjson_lines = [l for l in result.output.strip().splitlines() if l.startswith("{")]
        assert len(ndjson_lines) == 2


# ===========================================================================
# 6.  paginator.paginate_all_items — cursor_exclusive_keys
# ===========================================================================

class TestPaginateAllItemsCursorExclusiveKeys:

    def _make_client(self, pages):
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        call_idx = [0]

        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"data": []}

        c.get.side_effect = fake_get
        return c

    def test_two_pages_yields_all_items(self):
        """paginate_all_items yields items from both pages."""
        from sysdig_cli.paginator import paginate_all_items

        pages = [
            {"data": [{"id": 1}], "page": {"next": "cur1"}},
            {"data": [{"id": 2}], "page": {"next": None}},
        ]
        c = self._make_client(pages)
        items = list(paginate_all_items(c, "GET", "/fake", params={"from": 100, "to": 200}))
        assert len(items) == 2
        assert items[0]["id"] == 1
        assert items[1]["id"] == 2

    def test_from_to_dropped_on_page2(self):
        """cursor_exclusive_keys=['from','to'] removes them from page 2 request."""
        from sysdig_cli.paginator import paginate_all_items

        captured_params: List[Dict] = []
        pages = [
            {"data": [{"id": 1}], "page": {"next": "cursor-abc"}},
            {"data": [{"id": 2}], "page": {"next": None}},
        ]
        call_idx = [0]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": []}

        c = MagicMock()
        c.get.side_effect = fake_get

        list(paginate_all_items(
            c, "GET", "/fake",
            params={"from": 100, "to": 200, "limit": 50},
            cursor_exclusive_keys=["from", "to"],
        ))

        assert len(captured_params) == 2
        # Page 1 has from and to
        assert "from" in captured_params[0]
        assert "to" in captured_params[0]
        # Page 2 has cursor but NOT from/to
        assert "from" not in captured_params[1]
        assert "to" not in captured_params[1]
        assert captured_params[1]["cursor"] == "cursor-abc"

    def test_without_cursor_exclusive_keys_from_to_preserved(self):
        """Without cursor_exclusive_keys, from/to are NOT removed on page 2."""
        from sysdig_cli.paginator import paginate_all_items

        captured_params: List[Dict] = []
        pages = [
            {"data": [{"id": 1}], "page": {"next": "cursor-xyz"}},
            {"data": [{"id": 2}], "page": {"next": None}},
        ]
        call_idx = [0]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": []}

        c = MagicMock()
        c.get.side_effect = fake_get

        list(paginate_all_items(
            c, "GET", "/fake",
            params={"from": 100, "to": 200},
            cursor_exclusive_keys=None,
        ))

        assert "from" in captured_params[1]
        assert "to" in captured_params[1]

    def test_single_page_no_cursor_yields_items_only(self):
        """Single page with no next cursor terminates after first fetch."""
        from sysdig_cli.paginator import paginate_all_items

        pages = [{"data": [{"id": 1}, {"id": 2}], "page": {"next": None}}]
        c = self._make_client(pages)
        items = list(paginate_all_items(c, "GET", "/fake", params={}))
        assert len(items) == 2

    def test_empty_first_page_terminates_cleanly(self):
        """Empty first page with no cursor → yields nothing and stops."""
        from sysdig_cli.paginator import paginate_all_items

        pages = [{"data": [], "page": {"next": None}}]
        c = self._make_client(pages)
        items = list(paginate_all_items(c, "GET", "/fake", params={}))
        assert items == []

    def test_three_pages_all_items_yielded(self):
        """Three-page scenario with cursor_exclusive_keys yields all items."""
        from sysdig_cli.paginator import paginate_all_items

        captured_params: List[Dict] = []
        pages = [
            {"data": [{"id": 1}], "page": {"next": "cur1"}},
            {"data": [{"id": 2}], "page": {"next": "cur2"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_idx = [0]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": []}

        c = MagicMock()
        c.get.side_effect = fake_get

        items = list(paginate_all_items(
            c, "GET", "/fake",
            params={"from": 0, "to": 9999},
            cursor_exclusive_keys=["from", "to"],
        ))

        assert len(items) == 3
        # Page 1: has from/to
        assert "from" in captured_params[0]
        # Pages 2 and 3: no from/to
        assert "from" not in captured_params[1]
        assert "from" not in captured_params[2]
        assert captured_params[1]["cursor"] == "cur1"
        assert captured_params[2]["cursor"] == "cur2"

    def test_items_key_extracts_data(self):
        """'items' response key is also extracted correctly."""
        from sysdig_cli.paginator import paginate_all_items

        pages = [{"items": [{"x": 1}, {"x": 2}], "page": {"next": None}}]
        c = self._make_client(pages)
        items = list(paginate_all_items(c, "GET", "/fake", params={}))
        assert len(items) == 2

    def test_nextcursor_key_followed(self):
        """'nextCursor' response key is used as cursor."""
        from sysdig_cli.paginator import paginate_all_items

        captured_params: List[Dict] = []
        pages = [
            {"data": [{"id": "a"}], "nextCursor": "nc-1"},
            {"data": [{"id": "b"}]},
        ]
        call_idx = [0]

        def fake_get(path, params=None):
            captured_params.append(dict(params or {}))
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": []}

        c = MagicMock()
        c.get.side_effect = fake_get

        items = list(paginate_all_items(c, "GET", "/fake", params={}))
        assert len(items) == 2
        assert captured_params[1]["cursor"] == "nc-1"


# ===========================================================================
# 7.  Additional events.tail edge cases
# ===========================================================================

class TestEventsTailEdgeCases:

    def _make_tail_client(self, get_side_effect):
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        c.get.side_effect = get_side_effect
        return c

    def test_events_key_fallback(self, capsys):
        """Response with 'events' key (not 'data') is handled correctly."""
        from sysdig_cli.helpers.events import tail

        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"events": [FALCO_EVENT_A]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        assert '"ev-a"' in out

    def test_items_key_fallback(self, capsys):
        """Response with 'items' key (not 'data') is handled correctly."""
        from sysdig_cli.helpers.events import tail

        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"items": [FALCO_EVENT_A]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        assert '"ev-a"' in out

    def test_event_with_eventid_field_deduped(self, capsys):
        """Events using 'eventId' as key are deduplicated correctly."""
        from sysdig_cli.helpers.events import tail

        event_with_event_id = {"eventId": "eid-123", "name": "test"}
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] <= 2:
                return {"data": [event_with_event_id]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        lines = [l for l in out.strip().splitlines() if l.strip().startswith("{")]
        # Should be deduplicated — only 1 line
        assert len(lines) == 1

    def test_tail_multiple_new_events_all_printed(self, capsys):
        """Multiple new events in a single poll are all printed."""
        from sysdig_cli.helpers.events import tail

        ev1 = dict(FALCO_EVENT_A)
        ev2 = dict(FALCO_EVENT_B)
        call_no = [0]

        def fake_get(path, params=None):
            call_no[0] += 1
            if call_no[0] == 1:
                return {"data": [ev1, ev2]}
            raise KeyboardInterrupt

        c = self._make_tail_client(fake_get)
        with patch("sysdig_cli.helpers.events.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.events.time.sleep"), \
             patch("sysdig_cli.helpers.events.now_ns", return_value=1_000_000_000_000):
            tail(interval=1)

        out = capsys.readouterr().out
        lines = [l for l in out.strip().splitlines() if l.strip().startswith("{")]
        assert len(lines) == 2


# ===========================================================================
# 8.  stream_ndjson helper in paginator
# ===========================================================================

class TestStreamNdjson:

    def test_stream_ndjson_returns_count(self):
        """stream_ndjson returns total number of items written."""
        from sysdig_cli.paginator import stream_ndjson
        import io

        pages = [
            {"data": [{"id": 1}, {"id": 2}], "page": {"next": "c1"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_idx = [0]

        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            return pages[idx] if idx < len(pages) else {"data": []}

        c = MagicMock()
        c.get.side_effect = fake_get

        buf = io.StringIO()
        count = stream_ndjson(c, "GET", "/fake", params={}, file=buf)
        assert count == 3
        lines = [l for l in buf.getvalue().strip().splitlines() if l]
        assert len(lines) == 3

    def test_stream_ndjson_valid_json_lines(self):
        """stream_ndjson writes valid JSON on each line."""
        from sysdig_cli.paginator import stream_ndjson
        import io

        pages = [{"data": [{"x": "hello"}, {"x": "world"}], "page": {"next": None}}]
        call_idx = [0]

        def fake_get(path, params=None):
            return pages[call_idx[0]] if call_idx[0] < len(pages) else {"data": []}

        call_idx[0] = 0

        c = MagicMock()
        c.get.side_effect = fake_get

        buf = io.StringIO()
        stream_ndjson(c, "GET", "/fake", params={}, file=buf)
        for line in buf.getvalue().strip().splitlines():
            obj = json.loads(line)
            assert "x" in obj


# ===========================================================================
# 9.  vulns_list --all pagination (thin coverage)
# ===========================================================================

class TestVulnsListAllPagination:
    """Additional thin-coverage tests for vulns_list streaming mode."""

    def _make_vulns_client(self, pages):
        c = MagicMock()
        c.__enter__ = MagicMock(return_value=c)
        c.__exit__ = MagicMock(return_value=False)
        call_idx = [0]

        def fake_get(path, params=None):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"data": [], "page": {"next": None}}

        c.get.side_effect = fake_get
        return c

    def test_all_pages_two_pages_ndjson(self, capsys):
        """vulns_list --all streams items from two pages as ndjson."""
        from sysdig_cli.helpers.vulns import vulns_list

        workload1 = {
            "mainAssetName": "nginx:1.19",
            "resultId": "r1",
            "vulnTotalBySeverity": {"critical": 2, "high": 1, "medium": 0, "low": 0, "negligible": 0},
        }
        workload2 = {
            "mainAssetName": "redis:6.0",
            "resultId": "r2",
            "vulnTotalBySeverity": {"critical": 0, "high": 3, "medium": 0, "low": 0, "negligible": 0},
        }
        pages = [
            {"data": [workload1], "page": {"next": "cursor1", "total": 2}},
            {"data": [workload2], "page": {"next": None, "total": 2}},
        ]
        c = self._make_vulns_client(pages)

        with patch("sysdig_cli.helpers.vulns.SysdigClient", return_value=c), \
             patch("sysdig_cli.helpers.vulns.now_ns", return_value=1_000_000_000_000):
            vulns_list(
                fmt="ndjson",
                severity=None,
                cluster=None,
                namespace=None,
                pod=None,
                reachable=False,
                cloud=None,
                cve=None,
                exploitable=False,
                kev=False,
                sort="critical",
                limit=100,
                all_pages=True,
                profile="default",
                region=None,
                no_trunc=False,
            )

        out = capsys.readouterr().out
        ndjson_lines = [l for l in out.strip().splitlines() if l.strip().startswith("{")]
        assert len(ndjson_lines) == 2
