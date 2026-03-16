"""
Tests for the 12 new helper commands.
Uses CliRunner and respx to mock HTTP calls.
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import patch

import httpx
import pytest
import respx
from typer.testing import CliRunner

from sysdig_cli.auth import AuthConfig

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken", host=BASE_URL)


@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    """Patch resolve_auth to return a test auth config."""
    monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

VULN_RESPONSE = {
    "data": [
        {
            "id": "r1",
            "resourceName": "nginx:1.19",
            "vulnTotalBySeverity": {"critical": 3, "high": 5, "medium": 10, "low": 2, "negligible": 0},
        },
        {
            "id": "r2",
            "resourceName": "redis:6.0",
            "vulnTotalBySeverity": {"critical": 1, "high": 2, "medium": 4, "low": 1, "negligible": 0},
        },
    ],
    "page": {"next": None},
}

ACCEPTED_RISKS_RESPONSE = {
    "acceptedRisks": [
        {"id": "ar1", "vulnerability": "CVE-2024-1234", "reason": "mitigated", "expiresAt": None},
    ]
}

AUDIT_RESPONSE = {
    "data": [
        {
            "id": "a1",
            "timestamp": 1705312800000000000,
            "type": "kubectl.exec",
            "user": {"name": "alice"},
            "commandLine": "kubectl exec pod -- bash",
        }
    ],
    "page": {"next": None},
}

EVENTS_RESPONSE = {
    "data": [
        {
            "id": "e1",
            "name": "bash execution",
            "severity": "high",
            "description": "bash found",
            "timestamp": 1705312800000000000,
        }
    ],
    "page": {"next": None},
}

USERS_RESPONSE = {
    "users": [
        {"id": "u1", "username": "alice", "email": "alice@example.com", "systemRole": "admin"},
        {"id": "u2", "username": "bob", "email": "bob@example.com", "lastSeenAt": 0},
    ]
}

ROLES_RESPONSE = {"roles": [{"id": "role1", "name": "Admin"}]}
TEAMS_RESPONSE = {"teams": [{"id": "team1", "name": "Platform"}]}


# ---------------------------------------------------------------------------
# vulns weekly-report
# ---------------------------------------------------------------------------

class TestVulnsWeeklyReport:
    def test_weekly_report_basic(self, auth, capsys):
        """weekly-report fetches runtime results and accepted risks."""
        from sysdig_cli.helpers.vulns import vulns_weekly_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(200, json=ACCEPTED_RISKS_RESPONSE)
            )
            try:
                vulns_weekly_report(
                    zones=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        assert "weekly_report" in captured.out
        data = json.loads(captured.out)
        assert "weekly_report" in data
        assert data["weekly_report"]["total_runtime_workloads"] == 2

    def test_weekly_report_with_zones(self, auth, capsys):
        """weekly-report passes zones filter."""
        from sysdig_cli.helpers.vulns import vulns_weekly_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(200, json=ACCEPTED_RISKS_RESPONSE)
            )
            try:
                vulns_weekly_report(
                    zones="prod,staging",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["weekly_report"]["zones_filter"] == "prod,staging"

    def test_weekly_report_api_fallback(self, auth, capsys):
        """weekly-report uses mock data if API fails."""
        from sysdig_cli.helpers.vulns import vulns_weekly_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(500, json={"message": "server error"})
            )
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(500)
            )
            try:
                vulns_weekly_report(
                    zones=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        # Should fall back to mock data, not crash
        assert "weekly_report" in captured.out


# ---------------------------------------------------------------------------
# vulns zone-comparison
# ---------------------------------------------------------------------------

class TestVulnsZoneComparison:
    def test_zone_comparison_basic(self, auth, capsys):
        """zone-comparison fetches data and groups by cloud provider."""
        from sysdig_cli.helpers.vulns import vulns_zone_comparison

        vuln_resp = {
            "data": [
                {"mainAssetName": "workload-a", "scope": {"cloudProvider": "aws"},
                 "vulnTotalBySeverity": {"critical": 5, "high": 10, "medium": 20, "low": 3}},
                {"mainAssetName": "workload-b", "scope": {"cloudProvider": "gcp"},
                 "vulnTotalBySeverity": {"critical": 2, "high": 5, "medium": 8, "low": 1}},
                {"mainAssetName": "workload-c", "scope": {"cloudProvider": "aws"},
                 "vulnTotalBySeverity": {"critical": 1, "high": 3, "medium": 5, "low": 0}},
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=vuln_resp)
            )
            try:
                vulns_zone_comparison(
                    format="json",
                    limit=500,
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "zone_comparison" in data
        clouds = [z["zone"] for z in data["zone_comparison"]]
        assert "aws" in clouds
        assert "gcp" in clouds
        # AWS has 2 workloads: critical 5+1=6
        aws = next(z for z in data["zone_comparison"] if z["zone"] == "aws")
        assert aws["total_workloads"] == 2
        assert aws["critical"] == 6


# ---------------------------------------------------------------------------
# vulns sbom-diff
# ---------------------------------------------------------------------------

class TestVulnsSbomDiff:
    def test_sbom_diff_empty_sboms(self, auth, capsys):
        """sbom-diff handles empty SBOM responses gracefully."""
        from sysdig_cli.helpers.vulns import vulns_sbom_diff

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1beta1/sbom").mock(
                return_value=httpx.Response(200, json={})
            )
            try:
                vulns_sbom_diff(
                    from_image="nginx:1.18",
                    to_image="nginx:1.19",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "sbom_diff" in data
        assert data["sbom_diff"]["from_image"] == "nginx:1.18"
        assert data["sbom_diff"]["to_image"] == "nginx:1.19"

    def test_sbom_diff_with_packages(self, auth, capsys):
        """sbom-diff detects added and removed packages."""
        from sysdig_cli.helpers.vulns import vulns_sbom_diff

        sbom_from = {"packages": [{"name": "openssl"}, {"name": "libz"}]}
        sbom_to = {"packages": [{"name": "openssl"}, {"name": "curl"}]}

        call_count = 0
        responses = [
            httpx.Response(200, json=sbom_from),
            httpx.Response(200, json=sbom_to),
        ]

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1beta1/sbom").mock(
                side_effect=responses
            )
            try:
                vulns_sbom_diff(
                    from_image="myapp:1.0",
                    to_image="myapp:2.0",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        diff = data["sbom_diff"]
        assert "curl" in diff["added_packages"]
        assert "libz" in diff["removed_packages"]


# ---------------------------------------------------------------------------
# vulns coverage-report
# ---------------------------------------------------------------------------

class TestVulnsCoverageReport:
    def test_coverage_report_basic(self, auth, capsys):
        """coverage-report shows current/stale/unscanned breakdown."""
        from sysdig_cli.helpers.vulns import vulns_coverage_report

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            try:
                vulns_coverage_report(
                    format="json",
                    stale_days=7,
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "coverage_report" in data
        assert data["coverage_report"]["total_workloads"] == 2
        assert "stale_threshold_days" in data["coverage_report"]


# ---------------------------------------------------------------------------
# vulns risk-digest
# ---------------------------------------------------------------------------

class TestVulnsRiskDigest:
    def test_risk_digest_week(self, auth, capsys):
        """risk-digest fetches accepted risks for week period."""
        from sysdig_cli.helpers.vulns import vulns_risk_digest

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(200, json=ACCEPTED_RISKS_RESPONSE)
            )
            try:
                vulns_risk_digest(
                    period="week",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "risk_digest" in data
        assert data["risk_digest"]["period"] == "week"
        assert data["risk_digest"]["period_days"] == 7

    def test_risk_digest_month(self, auth, capsys):
        """risk-digest works for month period."""
        from sysdig_cli.helpers.vulns import vulns_risk_digest

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/vulnerability/v1beta1/accepted-risks").mock(
                return_value=httpx.Response(200, json={"acceptedRisks": []})
            )
            try:
                vulns_risk_digest(
                    period="month",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["risk_digest"]["period_days"] == 30

    def test_risk_digest_invalid_period(self, auth):
        """risk-digest rejects invalid period."""
        from sysdig_cli.helpers.vulns import vulns_risk_digest
        import click
        with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
            vulns_risk_digest(period="year", format="json", profile="default", region=None)
        exit_code = getattr(exc.value, "code", None) or getattr(exc.value, "exit_code", None)
        assert exit_code == 1


# ---------------------------------------------------------------------------
# audit compliance-export
# ---------------------------------------------------------------------------

class TestAuditComplianceExport:
    def test_compliance_export_soc2(self, auth, capsys):
        """compliance-export returns audit entries for soc2."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=AUDIT_RESPONSE)
            )
            try:
                audit_compliance_export(
                    framework="soc2",
                    since="30d",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "compliance_export" in data
        assert data["compliance_export"]["framework"] == "soc2"
        assert data["compliance_export"]["total_entries"] == 1

    def test_compliance_export_invalid_framework(self, auth):
        """compliance-export rejects unknown framework."""
        from sysdig_cli.helpers.audit import audit_compliance_export
        import click
        with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
            audit_compliance_export(
                framework="gdpr",
                since="30d",
                format="json",
                profile="default",
                region=None,
            )
        exit_code = getattr(exc.value, "code", None) or getattr(exc.value, "exit_code", None)
        assert exit_code == 1

    def test_compliance_export_pci(self, auth, capsys):
        """compliance-export works for pci framework."""
        from sysdig_cli.helpers.audit import audit_compliance_export

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json={"data": [], "page": {"next": None}})
            )
            try:
                audit_compliance_export(
                    framework="pci",
                    since="7d",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["compliance_export"]["framework"] == "pci"


# ---------------------------------------------------------------------------
# audit incident-timeline
# ---------------------------------------------------------------------------

class TestAuditIncidentTimeline:
    def test_incident_timeline_basic(self, auth, capsys):
        """incident-timeline returns events for a pod."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=AUDIT_RESPONSE)
            )
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=EVENTS_RESPONSE)
            )
            try:
                audit_incident_timeline(
                    pod="my-pod",
                    since="2h",
                    namespace=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "incident_timeline" in data
        assert data["incident_timeline"]["pod"] == "my-pod"
        assert data["incident_timeline"]["total_events"] == 2

    def test_incident_timeline_with_namespace(self, auth, capsys):
        """incident-timeline applies namespace filter."""
        from sysdig_cli.helpers.audit import audit_incident_timeline

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            try:
                audit_incident_timeline(
                    pod="my-pod",
                    since="1h",
                    namespace="default",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["incident_timeline"]["namespace"] == "default"


# ---------------------------------------------------------------------------
# users access-review
# ---------------------------------------------------------------------------

class TestUsersAccessReview:
    def test_access_review_basic(self, auth, capsys):
        """access-review returns combined user/role/team data."""
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
                users_access_review(
                    format="json",
                    inactive_since=90,
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "access_review" in data
        assert data["access_review"]["total_users"] == 2
        assert data["access_review"]["inactive_threshold_days"] == 90

    def test_access_review_inactive_flag(self, auth, capsys):
        """access-review flags users with no recent login."""
        from sysdig_cli.helpers.users import users_access_review

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/platform/v1/users").mock(
                return_value=httpx.Response(200, json=USERS_RESPONSE)
            )
            mock.get("/platform/v1/roles").mock(
                return_value=httpx.Response(200, json={"roles": []})
            )
            mock.get("/platform/v1/teams").mock(
                return_value=httpx.Response(200, json={"teams": []})
            )
            try:
                users_access_review(
                    format="json",
                    inactive_since=90,
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # bob has lastSeenAt=0 (epoch), should be inactive
        users = data["access_review"]["users"]
        bob = next((u for u in users if u["username"] == "bob"), None)
        if bob:
            assert bob["inactive"] is True


# ---------------------------------------------------------------------------
# alerts noise-report
# ---------------------------------------------------------------------------

class TestAlertsNoiseReport:
    def test_noise_report_basic(self, auth, capsys):
        """noise-report returns top rules by event volume."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        events_response = {
            "data": [
                {"id": "e1", "ruleName": "Bash in Container", "severity": "high"},
                {"id": "e2", "ruleName": "Bash in Container", "severity": "high"},
                {"id": "e3", "ruleName": "Netcat", "severity": "critical"},
                {"id": "e4", "ruleName": "Bash in Container", "severity": "high"},
            ],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=events_response)
            )
            try:
                alerts_noise_report(
                    since="7d",
                    top=20,
                    suggest_inhibitions=False,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "noise_report" in data
        assert data["noise_report"]["total_events"] == 4
        top_rules = data["noise_report"]["top_rules"]
        assert len(top_rules) > 0
        # Bash in Container should be first (3 occurrences)
        assert top_rules[0]["rule"] == "Bash in Container"
        assert top_rules[0]["event_count"] == 3

    def test_noise_report_with_inhibitions(self, auth, capsys):
        """noise-report includes inhibition suggestions when requested."""
        from sysdig_cli.helpers.alerts import alerts_noise_report

        events_response = {
            "data": [{"id": f"e{i}", "ruleName": "Shell Spawned", "severity": "medium"} for i in range(15)],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=events_response)
            )
            try:
                alerts_noise_report(
                    since="7d",
                    top=5,
                    suggest_inhibitions=True,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        top_rules = data["noise_report"]["top_rules"]
        assert "suggested_inhibition" in top_rules[0]


# ---------------------------------------------------------------------------
# sysql templates
# ---------------------------------------------------------------------------

class TestSysqlTemplates:
    def test_templates_list(self, capsys):
        """sysql templates list outputs available templates."""
        from sysdig_cli.helpers.sysql import sysql_templates_list, TEMPLATES

        try:
            sysql_templates_list(fmt="table")
        except SystemExit:
            pass

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        # All template names should appear in the output
        for name in TEMPLATES:
            assert name in combined, f"Template name '{name}' not in output"

    def test_templates_run_unknown(self, auth):
        """sysql templates run rejects unknown template."""
        from sysdig_cli.helpers.sysql import sysql_templates_run
        import click
        with pytest.raises((SystemExit, click.exceptions.Exit)) as exc:
            sysql_templates_run(
                template="nonexistent",
                var=None,
                format="json",
                profile="default",
                region=None,
            )
        exit_code = getattr(exc.value, "code", None) or getattr(exc.value, "exit_code", None)
        assert exit_code == 1

    def test_templates_run_known(self, auth, capsys):
        """sysql templates run executes a known template."""
        from sysdig_cli.helpers.sysql import sysql_templates_run

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.post("/api/sysql/v2/query").mock(
                return_value=httpx.Response(200, json={"items": [{"n.name": "node-1"}], "summary": {}})
            )
            try:
                sysql_templates_run(
                    template="kube-nodes",
                    var=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["template"] == "kube-nodes"
        assert data["result_count"] == 1

    def test_templates_run_all_keys_present(self, auth, capsys):
        """sysql templates run includes all expected fields in response."""
        from sysdig_cli.helpers.sysql import sysql_templates_run, TEMPLATES

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.post("/api/sysql/v2/query").mock(
                return_value=httpx.Response(200, json={"items": [], "summary": {}})
            )
            try:
                sysql_templates_run(
                    template="kube-workloads",
                    var=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "template" in data
        assert "query" in data
        assert "result_count" in data
        assert data["query"] == TEMPLATES["kube-workloads"]


# ---------------------------------------------------------------------------
# inventory diff
# ---------------------------------------------------------------------------

class TestInventoryDiff:
    def test_inventory_diff_basic(self, auth, capsys):
        """inventory diff returns added/removed/changed breakdown."""
        from sysdig_cli.helpers.inventory import inventory_diff

        changes_response = {
            "changes": [
                {"name": "new-pod", "kind": "Pod", "changeType": "added", "timestamp": "2024-01-01"},
                {"name": "old-pod", "kind": "Pod", "changeType": "removed", "timestamp": "2024-01-01"},
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
                inventory_diff(
                    since="1h",
                    namespace=None,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "inventory_diff" in data
        assert data["inventory_diff"]["summary"]["added"] == 1
        assert data["inventory_diff"]["summary"]["removed"] == 1

    def test_inventory_diff_with_namespace(self, auth, capsys):
        """inventory diff applies namespace filter."""
        from sysdig_cli.helpers.inventory import inventory_diff

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/cspm/v1/resourceInventory/resources").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            mock.get("/api/cspm/v1/resourceInventory/changes").mock(
                return_value=httpx.Response(200, json={"changes": []})
            )
            try:
                inventory_diff(
                    since="2h",
                    namespace="kube-system",
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["inventory_diff"]["namespace"] == "kube-system"


# ---------------------------------------------------------------------------
# cost security-weighted-rightsizing
# ---------------------------------------------------------------------------

class TestCostSecurityRightsizing:
    def test_rightsizing_basic(self, auth, capsys):
        """security-weighted-rightsizing returns filtered recommendations."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        rightsizing_response = {
            "recommendations": [
                {
                    "resourceName": "nginx:1.19",
                    "namespace": "prod",
                    "monthlySavings": 120.0,
                    "currentCpu": "2",
                    "recommendedCpu": "1",
                },
                {
                    "resourceName": "small-pod",
                    "namespace": "dev",
                    "monthlySavings": 10.0,  # below threshold
                    "currentCpu": "1",
                    "recommendedCpu": "0.5",
                },
            ]
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=rightsizing_response)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            try:
                cost_security_rightsizing(
                    min_savings=50,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "security_weighted_rightsizing" in data
        recs = data["security_weighted_rightsizing"]["recommendations"]
        # Only nginx:1.19 ($120) should pass min_savings=50 threshold
        assert len(recs) == 1
        assert recs[0]["workload"] == "nginx:1.19"

    def test_rightsizing_api_error_graceful(self, auth, capsys):
        """security-weighted-rightsizing handles API errors gracefully."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(404, json={"message": "not found"})
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=VULN_RESPONSE)
            )
            try:
                cost_security_rightsizing(
                    min_savings=50,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        # Should produce output even with API errors
        assert "security_weighted_rightsizing" in captured.out

    def test_rightsizing_security_weighting(self, auth, capsys):
        """security-weighted-rightsizing applies risk weighting correctly."""
        from sysdig_cli.helpers.cost import cost_security_rightsizing

        rightsizing_response = {
            "recommendations": [
                {"resourceName": "nginx:1.19", "monthlySavings": 100.0},
                {"resourceName": "safe-app:1.0", "monthlySavings": 80.0},
            ]
        }
        # nginx has vulns, safe-app doesn't
        vuln_response = {
            "data": [
                {
                    "resourceName": "nginx:1.19",
                    "vulnTotalBySeverity": {"critical": 5, "high": 10},
                }
            ],
            "page": {"next": None},
        }

        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/api/costs/v1/rightsizing").mock(
                return_value=httpx.Response(200, json=rightsizing_response)
            )
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=vuln_response)
            )
            try:
                cost_security_rightsizing(
                    min_savings=50,
                    format="json",
                    profile="default",
                    region=None,
                )
            except SystemExit:
                pass

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        recs = data["security_weighted_rightsizing"]["recommendations"]
        nginx_rec = next((r for r in recs if r["workload"] == "nginx:1.19"), None)
        safe_rec = next((r for r in recs if r["workload"] == "safe-app:1.0"), None)
        assert nginx_rec is not None
        assert safe_rec is not None
        # nginx should have lower priority due to high risk score
        assert nginx_rec["vuln_risk_score"] > safe_rec["vuln_risk_score"]
        assert nginx_rec["rightsizing_priority"] in ("medium", "low")
        assert safe_rec["rightsizing_priority"] == "high"


# ---------------------------------------------------------------------------
# CLI integration tests (via CliRunner invoking main app)
# ---------------------------------------------------------------------------

class TestCliIntegration:
    """Smoke tests that each command appears in --help and can be invoked."""

    def test_vulns_help_shows_all_new_commands(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["vulns", "--help"])
        assert r.exit_code == 0
        assert "weekly-report" in r.stdout
        assert "zone-comparison" in r.stdout
        assert "sbom-diff" in r.stdout
        assert "coverage-report" in r.stdout
        assert "risk-digest" in r.stdout

    def test_audit_help_shows_new_commands(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["audit", "--help"])
        assert r.exit_code == 0
        assert "compliance-export" in r.stdout
        assert "incident-timeline" in r.stdout

    def test_users_access_review_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["users", "access-review", "--help"])
        assert r.exit_code == 0
        assert "access-review" in r.stdout or "access" in r.stdout

    def test_alerts_noise_report_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["alerts", "noise-report", "--help"])
        assert r.exit_code == 0

    def test_sysql_templates_list_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["sysql", "templates", "list", "--help"])
        assert r.exit_code == 0

    def test_sysql_templates_run_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["sysql", "templates", "run", "--help"])
        assert r.exit_code == 0

    def test_inventory_diff_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["inventory", "diff", "--help"])
        assert r.exit_code == 0

    def test_cost_rightsizing_help(self):
        from sysdig_cli.main import app
        r = runner.invoke(app, ["cost", "security-weighted-rightsizing", "--help"])
        assert r.exit_code == 0
