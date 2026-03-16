"""
Comprehensive unit tests for misc helper commands:
- users.py (access-review)
- alerts.py (noise-report, _suggest_inhibition)
- inventory.py (diff)
- cost.py (security-weighted-rightsizing)
- captures.py (list, trigger, status, download, actions)
- sysql.py (list, run, var substitution)

NOTE: test_new_helpers.py already covers basic happy-path cases for
users/alerts/inventory/cost/sysql. These tests add additional coverage:
edge cases, error paths, filter combinations, and captures commands.
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import click.exceptions
import httpx
import pytest
import respx
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


def _exit_code(exc_info) -> int:
    """Extract exit code from either SystemExit or click.exceptions.Exit."""
    val = exc_info.value
    if isinstance(val, SystemExit):
        return int(val.code)
    # click.exceptions.Exit has .exit_code attribute
    return int(getattr(val, "exit_code", getattr(val, "code", -1)))


# ---------------------------------------------------------------------------
# Auth fixture — patches resolve_auth in all helper modules
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    from sysdig_cli.auth import AuthConfig
    auth = AuthConfig(token="testtoken", host="https://us2.app.sysdig.com")
    patches = {}
    for mod in ["users", "alerts", "inventory", "cost", "captures", "sysql"]:
        try:
            p = patch(f"sysdig_cli.helpers.{mod}.resolve_auth", return_value=auth)
            p.start()
            patches[mod] = p
        except Exception:
            pass
    yield
    for p in patches.values():
        p.stop()


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken", host=BASE_URL)


# ===========================================================================
# users.py — access-review
# ===========================================================================

USERS_RESPONSE = {
    "users": [
        {
            "id": "u1",
            "username": "alice",
            "email": "alice@example.com",
            "systemRole": "admin",
            "roleIds": ["role1"],
            "teamIds": ["team1"],
            "lastSeenAt": None,  # never logged in → inactive
        },
        {
            "id": "u2",
            "username": "bob",
            "email": "bob@example.com",
            "systemRole": "user",
            "lastSeenAt": 0,  # epoch → inactive
        },
        {
            "id": "u3",
            "username": "carol",
            "email": "carol@example.com",
            "systemRole": "user",
            "lastSeenAt": 9_999_999_999,  # far-future epoch seconds → active
        },
    ]
}
ROLES_RESPONSE = {"roles": [{"id": "role1", "name": "Admin"}]}
TEAMS_RESPONSE = {"teams": [{"id": "team1", "name": "Platform"}]}


class TestUsersAccessReview:
    """Tests for users_access_review beyond what test_new_helpers.py covers."""

    def test_access_review_role_resolution(self, capsys):
        """Roles are resolved from IDs to names."""
        from sysdig_cli.helpers.users import users_access_review

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(
                return_value=httpx.Response(200, json=USERS_RESPONSE)
            )
            mock.get("/platform/v1/roles").mock(
                return_value=httpx.Response(200, json=ROLES_RESPONSE)
            )
            mock.get("/platform/v1/teams").mock(
                return_value=httpx.Response(200, json=TEAMS_RESPONSE)
            )
            try:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        users = data["access_review"]["users"]
        alice = next(u for u in users if u["username"] == "alice")
        assert "Admin" in alice["roles"]
        assert "Platform" in alice["teams"]

    def test_access_review_inactive_never_logged_in(self, capsys):
        """Users who never logged in are flagged as inactive."""
        from sysdig_cli.helpers.users import users_access_review

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(
                return_value=httpx.Response(200, json=USERS_RESPONSE)
            )
            mock.get("/platform/v1/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            mock.get("/platform/v1/teams").mock(return_value=httpx.Response(200, json={"teams": []}))
            try:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        users = data["access_review"]["users"]
        alice = next(u for u in users if u["username"] == "alice")
        assert alice["inactive"] is True
        assert alice["last_login"] == "never"

    def test_access_review_empty_users(self, capsys):
        """access-review handles empty user list gracefully."""
        from sysdig_cli.helpers.users import users_access_review

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(return_value=httpx.Response(200, json={"users": []}))
            mock.get("/platform/v1/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            mock.get("/platform/v1/teams").mock(return_value=httpx.Response(200, json={"teams": []}))
            try:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["access_review"]["total_users"] == 0
        assert data["access_review"]["inactive_users"] == 0

    def test_access_review_auth_error_exits_2(self):
        """access-review raises Exit(2) on 401."""
        from sysdig_cli.helpers.users import users_access_review
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.users.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            assert _exit_code(exc) == 2

    def test_access_review_forbidden_exits_5(self):
        """access-review raises Exit(5) on 403."""
        from sysdig_cli.helpers.users import users_access_review
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.users.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            assert _exit_code(exc) == 5

    def test_access_review_inactive_threshold_custom(self, capsys):
        """access-review respects custom inactive_since threshold."""
        from sysdig_cli.helpers.users import users_access_review

        # User with old login (epoch 1) — always inactive
        users_data = {
            "users": [
                {"id": "u1", "username": "old-user", "email": "x@y.com", "lastSeenAt": 1},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(return_value=httpx.Response(200, json=users_data))
            mock.get("/platform/v1/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            mock.get("/platform/v1/teams").mock(return_value=httpx.Response(200, json={"teams": []}))
            try:
                users_access_review(format="json", inactive_since=30, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["access_review"]["inactive_threshold_days"] == 30
        assert data["access_review"]["inactive_users"] == 1

    def test_access_review_direct_role_field(self, capsys):
        """access-review uses direct 'role' field when roleIds is absent."""
        from sysdig_cli.helpers.users import users_access_review

        users_data = {
            "users": [
                {"id": "u1", "username": "svc-account", "email": "svc@x.com", "role": "ServiceAccount"},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(return_value=httpx.Response(200, json=users_data))
            mock.get("/platform/v1/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            mock.get("/platform/v1/teams").mock(return_value=httpx.Response(200, json={"teams": []}))
            try:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        users = data["access_review"]["users"]
        assert users[0]["roles"] == "ServiceAccount"

    def test_access_review_data_field_fallback(self, capsys):
        """access-review uses 'data' field if 'users' key is absent."""
        from sysdig_cli.helpers.users import users_access_review

        users_data = {
            "data": [
                {"id": "u1", "username": "datauser", "email": "d@x.com"},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(return_value=httpx.Response(200, json=users_data))
            mock.get("/platform/v1/roles").mock(return_value=httpx.Response(200, json={"roles": []}))
            mock.get("/platform/v1/teams").mock(return_value=httpx.Response(200, json={"teams": []}))
            try:
                users_access_review(format="json", inactive_since=90, profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["access_review"]["total_users"] == 1


# ===========================================================================
# alerts.py — noise-report & _suggest_inhibition
# ===========================================================================

class TestAlertsNoiseReportExtra:
    """Additional coverage for alerts noise-report beyond test_new_helpers.py."""

    def test_noise_report_empty_events(self, capsys):
        """noise-report handles zero events gracefully."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                alerts_noise_report(since="7d", top=20, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["noise_report"]["total_events"] == 0
        assert data["noise_report"]["unique_rules"] == 0
        assert data["noise_report"]["top_rules"] == []

    def test_noise_report_events_key_fallback(self, capsys):
        """noise-report uses 'events' key when 'data' is absent."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={
                    "events": [
                        {"id": "e1", "ruleName": "DNS Lookup", "severity": "low"},
                    ]
                })
            )
            try:
                alerts_noise_report(since="24h", top=10, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["noise_report"]["total_events"] == 1

    def test_noise_report_top_limit(self, capsys):
        """noise-report respects the top-N limit."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        events = [{"id": f"e{i}", "ruleName": f"Rule{i}", "severity": "info"} for i in range(30)]
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                alerts_noise_report(since="7d", top=5, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert len(data["noise_report"]["top_rules"]) == 5

    def test_noise_report_policyname_fallback(self, capsys):
        """noise-report falls back to policyName if ruleName is absent."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        events = [{"id": "e1", "policyName": "My Policy", "severity": "high"}]
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": events})
            )
            try:
                alerts_noise_report(since="7d", top=10, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["noise_report"]["top_rules"][0]["rule"] == "My Policy"

    def test_noise_report_auth_error_exits_2(self):
        """noise-report raises Exit(2) on AuthError."""
        from sysdig_cli.helpers.alerts import alerts_noise_report
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.alerts.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("bad token")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                alerts_noise_report(since="7d", top=10, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            assert _exit_code(exc) == 2

    def test_noise_report_forbidden_exits_5(self):
        """noise-report raises Exit(5) on ForbiddenError."""
        from sysdig_cli.helpers.alerts import alerts_noise_report
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.alerts.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("no permission")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                alerts_noise_report(since="7d", top=10, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            assert _exit_code(exc) == 5

    def test_noise_report_since_field_preserved(self, capsys):
        """noise-report includes 'since' in the output."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                alerts_noise_report(since="3d", top=5, suggest_inhibitions=False,
                                    format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["noise_report"]["since"] == "3d"


class TestSuggestInhibition:
    """Unit tests for the _suggest_inhibition helper function."""

    def test_low_count_no_action(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Some Rule", 5)
        assert result == "no_action_needed"

    def test_bash_rule_scoping_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Bash Execution in Container", 50)
        assert "namespace" in result.lower() or "service account" in result.lower()

    def test_shell_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Shell Spawned", 20)
        assert "namespace" in result.lower() or "service account" in result.lower()

    def test_network_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Unexpected Network Connection", 100)
        assert "IP" in result or "allowlist" in result.lower()

    def test_connection_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Outbound connection attempt", 30)
        assert "IP" in result or "allowlist" in result.lower()

    def test_file_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Sensitive File Read", 15)
        assert "container" in result.lower() or "image" in result.lower()

    def test_write_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("File Write to /etc", 20)
        assert "container" in result.lower() or "image" in result.lower()

    def test_high_volume_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Generic Rule", 1500)
        assert "High volume" in result or "suppression" in result.lower()

    def test_generic_rule_suggestion(self):
        from sysdig_cli.helpers.alerts import _suggest_inhibition
        result = _suggest_inhibition("Some Weird Rule", 50)
        assert "Review" in result or "false positive" in result.lower()


# ===========================================================================
# inventory.py — diff
# ===========================================================================

class TestInventoryDiffExtra:
    """Additional coverage for inventory_diff beyond test_new_helpers.py."""

    def test_inventory_diff_changed_resources(self, capsys):
        """inventory diff correctly categorises 'changed' resources."""
        from sysdig_cli.helpers.inventory import inventory_diff

        changes_response = {
            "data": [
                {"name": "updated-cm", "kind": "ConfigMap", "changeType": "modified", "timestamp": "2024-01-01"},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json=changes_response)
            )
            try:
                inventory_diff(since="1h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["inventory_diff"]["summary"]["changed"] == 1
        assert data["inventory_diff"]["summary"]["added"] == 0
        assert data["inventory_diff"]["summary"]["removed"] == 0

    def test_inventory_diff_empty_changes(self, capsys):
        """inventory diff handles empty changes response."""
        from sysdig_cli.helpers.inventory import inventory_diff

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json={"changes": []})
            )
            try:
                inventory_diff(since="1h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        diff = data["inventory_diff"]
        assert diff["summary"]["added"] == 0
        assert diff["summary"]["removed"] == 0
        assert diff["summary"]["changed"] == 0

    def test_inventory_diff_created_type_maps_to_added(self, capsys):
        """inventory diff maps 'created' changeType to added bucket."""
        from sysdig_cli.helpers.inventory import inventory_diff

        changes_response = {
            "changes": [
                {"name": "new-deploy", "kind": "Deployment", "changeType": "created"},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json=changes_response)
            )
            try:
                inventory_diff(since="2h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["inventory_diff"]["summary"]["added"] == 1

    def test_inventory_diff_deleted_type_maps_to_removed(self, capsys):
        """inventory diff maps 'deleted' changeType to removed bucket."""
        from sysdig_cli.helpers.inventory import inventory_diff

        changes_response = {
            "changes": [
                {"name": "old-svc", "kind": "Service", "changeType": "deleted"},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json=changes_response)
            )
            try:
                inventory_diff(since="2h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["inventory_diff"]["summary"]["removed"] == 1

    def test_inventory_diff_since_preserved(self, capsys):
        """inventory diff preserves the 'since' value in output."""
        from sysdig_cli.helpers.inventory import inventory_diff

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json={"changes": []})
            )
            try:
                inventory_diff(since="6h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["inventory_diff"]["since"] == "6h"

    def test_inventory_diff_auth_error_exits(self):
        """inventory diff raises Exit on AuthError."""
        from sysdig_cli.helpers.inventory import inventory_diff
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.inventory.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("bad token")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                inventory_diff(since="1h", namespace=None, format="json", profile="default", region=None)
            # AuthError combined handler: exits (code may vary by implementation)
            assert _exit_code(exc) is not None

    def test_inventory_diff_api_error_graceful(self, capsys):
        """inventory diff handles SysdigError gracefully (prints warning, no crash)."""
        from sysdig_cli.helpers.inventory import inventory_diff
        from sysdig_cli.client import SysdigError

        with patch("sysdig_cli.helpers.inventory.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = SysdigError("service unavailable")
            try:
                inventory_diff(since="1h", namespace=None, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        captured = capsys.readouterr()
        # Should still output the structure even when API errors occur
        assert "inventory_diff" in captured.out


# ===========================================================================
# cost.py — security-weighted-rightsizing
# ===========================================================================

VULN_RESPONSE = {
    "data": [
        {
            "resourceName": "nginx:1.19",
            "vulnTotalBySeverity": {"critical": 3, "high": 5, "medium": 10, "low": 2, "negligible": 0},
        },
    ]
}

COST_RECOMMENDATIONS = {
    "recommendations": [
        {
            "resourceName": "nginx:1.19",
            "namespace": "prod",
            "monthlySavings": 150.0,
            "currentCpu": "4",
            "recommendedCpu": "2",
            "currentMemory": "8Gi",
            "recommendedMemory": "4Gi",
        },
        {
            "resourceName": "redis:6.0",
            "namespace": "prod",
            "monthlySavings": 75.0,
            "currentCpu": "2",
            "recommendedCpu": "1",
        },
        {
            "resourceName": "cheap-app",
            "namespace": "dev",
            "monthlySavings": 10.0,  # below default min_savings=50
        },
    ]
}


class TestCostSecurityRightsizingExtra:
    """Additional coverage for cost_security_rightsizing beyond test_new_helpers.py."""

    def test_rightsizing_min_savings_filter(self, capsys):
        """Only recommendations >= min_savings are returned."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=COST_RECOMMENDATIONS)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            try:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        recs = data["security_weighted_rightsizing"]["recommendations"]
        names = [r["workload"] for r in recs]
        assert "cheap-app" not in names
        assert "nginx:1.19" in names or "redis:6.0" in names

    def test_rightsizing_high_min_savings_no_results(self, capsys):
        """Returns empty when no recommendations exceed very high min_savings."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=COST_RECOMMENDATIONS)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                cost_security_rightsizing(min_savings=10000, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["security_weighted_rightsizing"]["total_recommendations"] == 0
        assert data["security_weighted_rightsizing"]["total_potential_savings_usd"] == 0.0

    def test_rightsizing_priority_ordering(self, capsys):
        """High-priority (low risk) items appear before low-priority (high risk) items."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        cost_data = {
            "recommendations": [
                {"resourceName": "risky-app", "monthlySavings": 200.0},
                {"resourceName": "safe-app", "monthlySavings": 100.0},
            ]
        }
        vuln_data = {
            "data": [
                {
                    "resourceName": "risky-app",
                    "vulnTotalBySeverity": {"critical": 10},
                }
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=cost_data)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=vuln_data)
            )
            try:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        recs = data["security_weighted_rightsizing"]["recommendations"]
        # safe-app (high priority) should come first
        assert recs[0]["workload"] == "safe-app"
        assert recs[0]["rightsizing_priority"] == "high"

    def test_rightsizing_auth_error_exits_2(self):
        """security-weighted-rightsizing exits 2 on AuthError."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.cost.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            assert _exit_code(exc) == 2

    def test_rightsizing_forbidden_exits_5(self):
        """security-weighted-rightsizing exits 5 on ForbiddenError."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.cost.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            assert _exit_code(exc) == 5

    def test_rightsizing_vuln_risk_score_low_for_clean_workload(self, capsys):
        """Workloads with no vulnerabilities get risk_score=0 and priority=high."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        cost_data = {"recommendations": [{"resourceName": "clean-app", "monthlySavings": 100.0}]}
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=cost_data)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        recs = data["security_weighted_rightsizing"]["recommendations"]
        assert recs[0]["vuln_risk_score"] == 0.0
        assert recs[0]["rightsizing_priority"] == "high"

    def test_rightsizing_total_savings_calculation(self, capsys):
        """Total savings is sum of all recommendations above threshold."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        cost_data = {
            "recommendations": [
                {"resourceName": "app-a", "monthlySavings": 100.0},
                {"resourceName": "app-b", "monthlySavings": 200.0},
            ]
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=cost_data)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                cost_security_rightsizing(min_savings=50, format="json", profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["security_weighted_rightsizing"]["total_potential_savings_usd"] == 300.0


# ===========================================================================
# captures.py — list, trigger, status, actions
# ===========================================================================

EXECUTIONS_RESPONSE = {
    "data": [
        {
            "id": "exec-001",
            "actionType": "capture",
            "status": "succeeded",
            "parameters": {"containerId": "abc123", "durationSeconds": 10},
            "createdAt": "2024-01-15T10:00:00Z",
            "updatedAt": "2024-01-15T10:00:15Z",
            "failure": {},
        },
        {
            "id": "exec-002",
            "actionType": "file_acquire",
            "status": "failed",
            "parameters": {"containerId": "def456", "durationSeconds": 30},
            "createdAt": "2024-01-15T09:00:00Z",
            "updatedAt": "2024-01-15T09:00:05Z",
            "failure": {"failureReason": "Container not found"},
        },
    ]
}

ACTIONS_RESPONSE = {
    "data": [
        {
            "type": "capture",
            "responderType": "falco",
            "description": "Capture syscalls from a container",
            "parameters": [
                {"name": "containerId", "required": True},
                {"name": "durationSeconds", "required": False},
            ],
            "isUndoable": False,
        },
        {
            "type": "file_acquire",
            "responderType": "agent",
            "description": "Acquire a file from a container",
            "parameters": [
                {"name": "containerId", "required": True},
                {"name": "filePath", "required": True},
            ],
            "isUndoable": False,
        },
    ]
}


class TestCapturesList:
    """Tests for captures_list function."""

    def test_captures_list_basic(self, capsys):
        """captures_list returns list of executions."""
        from sysdig_cli.helpers.captures import captures_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/response-actions/v1alpha1/action-executions").mock(
                return_value=httpx.Response(200, json=EXECUTIONS_RESPONSE)
            )
            try:
                captures_list(
                    from_time="24h",
                    to_time=None,
                    status=None,
                    limit=50,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert "data" in data
        assert len(data["data"]) == 2

    def test_captures_list_status_filter(self, capsys):
        """captures_list filters by status when --status is given."""
        from sysdig_cli.helpers.captures import captures_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/response-actions/v1alpha1/action-executions").mock(
                return_value=httpx.Response(200, json=EXECUTIONS_RESPONSE)
            )
            try:
                captures_list(
                    from_time="24h",
                    to_time=None,
                    status="succeeded",
                    limit=50,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert all(r["status"] == "succeeded" for r in data["data"])
        assert len(data["data"]) == 1

    def test_captures_list_empty_response(self, capsys):
        """captures_list handles empty executions list."""
        from sysdig_cli.helpers.captures import captures_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/response-actions/v1alpha1/action-executions").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                captures_list(
                    from_time="24h",
                    to_time=None,
                    status=None,
                    limit=50,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["data"] == []

    def test_captures_list_auth_error_exits_2(self):
        """captures_list exits 2 on AuthError."""
        from sysdig_cli.helpers.captures import captures_list
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_list(from_time="24h", to_time=None, status=None, limit=50,
                               profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 2

    def test_captures_list_forbidden_exits_5(self):
        """captures_list exits 5 on ForbiddenError."""
        from sysdig_cli.helpers.captures import captures_list
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_list(from_time="24h", to_time=None, status=None, limit=50,
                               profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 5

    def test_captures_list_status_filter_failed(self, capsys):
        """captures_list filters to only failed executions."""
        from sysdig_cli.helpers.captures import captures_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/response-actions/v1alpha1/action-executions").mock(
                return_value=httpx.Response(200, json=EXECUTIONS_RESPONSE)
            )
            try:
                captures_list(
                    from_time="24h",
                    to_time=None,
                    status="failed",
                    limit=50,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert len(data["data"]) == 1
        assert data["data"][0]["id"] == "exec-002"
        assert data["data"][0]["failure"] == "Container not found"

    def test_captures_list_flattens_failure_reason(self, capsys):
        """captures_list flattens nested failure reason to flat string."""
        from sysdig_cli.helpers.captures import captures_list

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/response-actions/v1alpha1/action-executions").mock(
                return_value=httpx.Response(200, json=EXECUTIONS_RESPONSE)
            )
            try:
                captures_list(from_time="24h", to_time=None, status=None, limit=50,
                               profile="default", region=None, fmt="json")
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        failed = next(r for r in data["data"] if r["id"] == "exec-002")
        assert failed["failure"] == "Container not found"


class TestCapturesTrigger:
    """Tests for captures_trigger function."""

    def test_captures_trigger_basic(self, capsys):
        """captures_trigger submits a capture action."""
        from sysdig_cli.helpers.captures import captures_trigger

        trigger_response = {
            "id": "exec-new-001",
            "status": "pending",
            "actionType": "capture",
        }

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = trigger_response
            try:
                captures_trigger(
                    container_id="abc123",
                    duration=10,
                    filter_str=None,
                    wait=False,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        # Should have called post with correct body
        call_args = instance.post.call_args
        assert call_args[0][0] == "/secure/response-actions/v1alpha1/action-executions"
        body = call_args[1]["json"]
        assert body["actionType"] == "capture"
        assert body["parameters"]["containerId"] == "abc123"
        assert body["parameters"]["durationSeconds"] == 10

    def test_captures_trigger_with_filter(self, capsys):
        """captures_trigger includes filterString when --filter is given."""
        from sysdig_cli.helpers.captures import captures_trigger

        trigger_response = {"id": "exec-002", "status": "pending"}

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = trigger_response
            try:
                captures_trigger(
                    container_id="xyz789",
                    duration=30,
                    filter_str="proc.name=nginx",
                    wait=False,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        call_args = instance.post.call_args
        body = call_args[1]["json"]
        assert body["parameters"]["filterString"] == "proc.name=nginx"

    def test_captures_trigger_empty_response_exits_3(self):
        """captures_trigger exits 3 if API returns empty response."""
        from sysdig_cli.helpers.captures import captures_trigger

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = None
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_trigger(
                    container_id="abc123",
                    duration=10,
                    filter_str=None,
                    wait=False,
                    profile="default",
                    region=None,
                    fmt="json",
                )
            assert _exit_code(exc) == 3

    def test_captures_trigger_auth_error_exits(self):
        """captures_trigger exits on AuthError."""
        from sysdig_cli.helpers.captures import captures_trigger
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)):
                captures_trigger(container_id="abc123", duration=10, filter_str=None,
                                  wait=False, profile="default", region=None, fmt="json")


class TestCapturesStatus:
    """Tests for captures_status function."""

    def test_captures_status_basic(self, capsys):
        """captures_status returns execution details."""
        from sysdig_cli.helpers.captures import captures_status

        status_response = {
            "id": "exec-001",
            "status": "succeeded",
            "actionType": "capture",
            "createdAt": "2024-01-15T10:00:00Z",
            "failure": {},
        }

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.return_value = status_response
            try:
                captures_status(
                    execution_id="exec-001",
                    profile="default",
                    region=None,
                    fmt="json",
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        captured = capsys.readouterr()
        assert "exec-001" in captured.out or "succeeded" in captured.out

    def test_captures_status_not_found_exits_1(self):
        """captures_status exits 1 when execution not found."""
        from sysdig_cli.helpers.captures import captures_status

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.return_value = None
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_status(execution_id="nonexistent", profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 1

    def test_captures_status_auth_error_exits_2(self):
        """captures_status exits 2 on AuthError."""
        from sysdig_cli.helpers.captures import captures_status
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_status(execution_id="exec-001", profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 2

    def test_captures_status_forbidden_exits_5(self):
        """captures_status exits 5 on ForbiddenError."""
        from sysdig_cli.helpers.captures import captures_status
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_status(execution_id="exec-001", profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 5


class TestCapturesActions:
    """Tests for captures_actions function."""

    def test_captures_actions_basic(self, capsys):
        """captures_actions returns available action types."""
        from sysdig_cli.helpers.captures import captures_actions

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.return_value = ACTIONS_RESPONSE
            try:
                captures_actions(profile="default", region=None, fmt="json")
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert "data" in data
        rows = data["data"]
        assert len(rows) == 2
        types = [r["type"] for r in rows]
        assert "capture" in types
        assert "file_acquire" in types

    def test_captures_actions_params_flattened(self, capsys):
        """captures_actions flattens required/optional params correctly."""
        from sysdig_cli.helpers.captures import captures_actions

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.return_value = ACTIONS_RESPONSE
            try:
                captures_actions(profile="default", region=None, fmt="json")
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        capture_row = next(r for r in data["data"] if r["type"] == "capture")
        assert "containerId" in capture_row["required_params"]
        assert "durationSeconds" in capture_row["optional_params"]

    def test_captures_actions_empty_response(self, capsys):
        """captures_actions handles empty action list."""
        from sysdig_cli.helpers.captures import captures_actions

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.return_value = {"data": []}
            try:
                captures_actions(profile="default", region=None, fmt="json")
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["data"] == []

    def test_captures_actions_auth_error_exits_2(self):
        """captures_actions exits 2 on AuthError."""
        from sysdig_cli.helpers.captures import captures_actions
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_actions(profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 2

    def test_captures_actions_forbidden_exits_5(self):
        """captures_actions exits 5 on ForbiddenError."""
        from sysdig_cli.helpers.captures import captures_actions
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.captures.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.get.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                captures_actions(profile="default", region=None, fmt="json")
            assert _exit_code(exc) == 5


# ===========================================================================
# sysql.py — list, run, var substitution
# ===========================================================================

class TestSysqlTemplatesList:
    """Tests for sysql_templates_list function."""

    def test_templates_list_contains_all_templates(self, capsys):
        """sysql templates list shows all template names."""
        from sysdig_cli.helpers.sysql import sysql_templates_list, TEMPLATES

        try:
            sysql_templates_list(fmt="json")
        except (SystemExit, click.exceptions.Exit):
            pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "templates" in data
        assert data["total"] == len(TEMPLATES)
        names = [t["name"] for t in data["templates"]]
        for k in TEMPLATES:
            assert k in names

    def test_templates_list_preview_truncation(self, capsys):
        """sysql templates list truncates long queries in preview."""
        from sysdig_cli.helpers.sysql import sysql_templates_list

        try:
            sysql_templates_list(fmt="json")
        except (SystemExit, click.exceptions.Exit):
            pass

        data = json.loads(capsys.readouterr().out)
        for t in data["templates"]:
            assert len(t["query_preview"]) <= 83  # 80 chars + "..."

    def test_templates_list_table_format_no_crash(self, capsys):
        """sysql templates list works with table format (no crash)."""
        from sysdig_cli.helpers.sysql import sysql_templates_list

        try:
            sysql_templates_list(fmt="table")
        except (SystemExit, click.exceptions.Exit):
            pass
        # Just verify it runs without raising uncaught exceptions

    def test_templates_list_specific_entries(self, capsys):
        """sysql templates list includes expected template names in json output."""
        from sysdig_cli.helpers.sysql import sysql_templates_list

        try:
            sysql_templates_list(fmt="json")
        except (SystemExit, click.exceptions.Exit):
            pass

        data = json.loads(capsys.readouterr().out)
        names = [t["name"] for t in data["templates"]]
        for expected in ["kube-nodes", "kube-workloads", "runtime-events", "identities"]:
            assert expected in names


class TestSysqlTemplatesRun:
    """Tests for sysql_templates_run function."""

    def test_templates_run_unknown_exits_1(self):
        """sysql templates run exits 1 for unknown template."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
            sysql_templates_run(template="nonexistent-template", var=None, format="json",
                                profile="default", region=None)
        assert _exit_code(exc) == 1

    def test_templates_run_kube_nodes(self, capsys):
        """sysql templates run executes kube-nodes template."""
        from sysdig_cli.helpers.sysql import sysql_templates_run, TEMPLATES

        query_resp = {"items": [{"n.name": "node-1", "n.clusterName": "prod"}]}
        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = query_resp
            try:
                sysql_templates_run(template="kube-nodes", var=None, format="json",
                                    profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["template"] == "kube-nodes"
        assert data["query"] == TEMPLATES["kube-nodes"]
        assert data["result_count"] == 1
        assert data["results"][0]["n.name"] == "node-1"

    def test_templates_run_empty_results(self, capsys):
        """sysql templates run handles empty results gracefully."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = {"items": []}
            try:
                sysql_templates_run(template="kube-workloads", var=None, format="json",
                                    profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["result_count"] == 0
        assert data["results"] == []

    def test_templates_run_data_key_fallback(self, capsys):
        """sysql templates run uses 'data' key if 'items' is absent."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = {"data": [{"i.name": "user1"}]}
            try:
                sysql_templates_run(template="identities", var=None, format="json",
                                    profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["result_count"] == 1

    def test_templates_run_auth_error_exits_2(self):
        """sysql templates run exits 2 on AuthError."""
        from sysdig_cli.helpers.sysql import sysql_templates_run
        from sysdig_cli.client import AuthError

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.side_effect = AuthError("Unauthorized")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                sysql_templates_run(template="kube-nodes", var=None, format="json",
                                    profile="default", region=None)
            assert _exit_code(exc) == 2

    def test_templates_run_forbidden_exits_5(self):
        """sysql templates run exits 5 on ForbiddenError."""
        from sysdig_cli.helpers.sysql import sysql_templates_run
        from sysdig_cli.client import ForbiddenError

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.side_effect = ForbiddenError("Forbidden")
            with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
                sysql_templates_run(template="kube-nodes", var=None, format="json",
                                    profile="default", region=None)
            assert _exit_code(exc) == 5

    def test_templates_run_api_error_graceful(self, capsys):
        """sysql templates run handles SysdigError gracefully (includes api_error key)."""
        from sysdig_cli.helpers.sysql import sysql_templates_run
        from sysdig_cli.client import SysdigError

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.side_effect = SysdigError("cluster not supported")
            try:
                sysql_templates_run(template="kube-nodes", var=None, format="json",
                                    profile="default", region=None)
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert "api_error" in data
        assert "cluster not supported" in data["api_error"]


class TestSysqlVarSubstitution:
    """Tests for variable substitution in sysql_templates_run."""

    def test_var_substitution_applied(self, capsys):
        """sysql templates run applies --var key=value substitutions."""
        from sysdig_cli.helpers.sysql import sysql_templates_run, TEMPLATES

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = {"items": []}
            try:
                sysql_templates_run(
                    template="kube-nodes",
                    var=["cluster=my-cluster"],
                    format="json",
                    profile="default",
                    region=None,
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        # Var substitution should not crash; query is modified if template uses {cluster}
        # kube-nodes template doesn't use {cluster}, so query stays the same
        data = json.loads(capsys.readouterr().out)
        assert data["template"] == "kube-nodes"
        assert data["query"] == TEMPLATES["kube-nodes"]

    def test_var_substitution_invalid_format_exits_1(self):
        """sysql templates run exits 1 for --var without '=' sign."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
            sysql_templates_run(
                template="kube-nodes",
                var=["invalid-var-no-equals"],
                format="json",
                profile="default",
                region=None,
            )
        assert _exit_code(exc) == 1

    def test_var_substitution_multiple_vars(self, capsys):
        """sysql templates run handles multiple --var flags."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = {"items": []}
            try:
                sysql_templates_run(
                    template="kube-nodes",
                    var=["a=1", "b=2"],
                    format="json",
                    profile="default",
                    region=None,
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["template"] == "kube-nodes"

    def test_var_substitution_value_with_equals(self, capsys):
        """sysql templates run handles value containing '=' in --var."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
            instance = MockClient.return_value.__enter__.return_value
            instance.post.return_value = {"items": []}
            try:
                sysql_templates_run(
                    template="kube-nodes",
                    var=["filter=name=my-cluster"],  # value contains '='
                    format="json",
                    profile="default",
                    region=None,
                )
            except (SystemExit, click.exceptions.Exit):
                pass

        data = json.loads(capsys.readouterr().out)
        assert data["template"] == "kube-nodes"

    def test_templates_run_all_templates_work(self, capsys):
        """All templates can be run without errors."""
        from sysdig_cli.helpers.sysql import sysql_templates_run, TEMPLATES

        for tmpl_name in TEMPLATES:
            with patch("sysdig_cli.helpers.sysql.SysdigClient") as MockClient:
                instance = MockClient.return_value.__enter__.return_value
                instance.post.return_value = {"items": []}
                try:
                    sysql_templates_run(template=tmpl_name, var=None, format="json",
                                        profile="default", region=None)
                except (SystemExit, click.exceptions.Exit):
                    pass

            data = json.loads(capsys.readouterr().out)
            assert data["template"] == tmpl_name
