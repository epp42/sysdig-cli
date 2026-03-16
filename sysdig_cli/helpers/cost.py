"""
Cost helper commands.
+security-weighted-rightsizing: Cost rightsizing recommendations with vulnerability risk weighting
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning

cost_helpers_app = typer.Typer(
    name="cost-helpers",
    help="Cost helper commands.",
    no_args_is_help=True,
)

# Risk multiplier: higher vulns mean higher risk score, so we deprioritize rightsizing
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
    "negligible": 0.1,
}


@cost_helpers_app.command("security-weighted-rightsizing")
def cost_security_rightsizing(
    min_savings: int = typer.Option(50, "--min-savings", help="Minimum monthly savings USD"),
    format: str = typer.Option("table", "--format"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Cost rightsizing recommendations with vulnerability risk weighting."""
    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    print_info(f"Fetching rightsizing recommendations (min savings: ${min_savings}/mo)...")

    recommendations: List[Dict[str, Any]] = []

    try:
        with SysdigClient(auth=auth) as client:
            # Fetch cost rightsizing recommendations
            cost_resp = client.get(
                "/api/costs/v1/rightsizing",
                params={"limit": 1000},
            )
            raw_recs = (
                (cost_resp or {}).get("data") or
                (cost_resp or {}).get("recommendations") or
                (cost_resp or {}).get("items") or
                []
            )

            # Fetch vulnerability data for risk weighting
            vuln_resp = client.get(
                "/secure/vulnerability/v1/runtime-results",
                params={"limit": 1000},
            )
            vuln_data = (vuln_resp or {}).get("data") or []

            # Build vuln risk index by workload name
            vuln_risk: Dict[str, float] = {}
            for item in vuln_data:
                name = item.get("resourceName") or item.get("name") or ""
                vuln_by_sev = (
                    item.get("vulnTotalBySeverity") or
                    item.get("vulnsBySeverity") or
                    {}
                )
                risk_score = sum(
                    _SEVERITY_WEIGHTS.get(sev, 0) * count
                    for sev, count in vuln_by_sev.items()
                    if isinstance(count, (int, float))
                )
                if name:
                    vuln_risk[name] = risk_score

            # Filter and enrich recommendations
            for rec in raw_recs:
                savings = rec.get("monthlySavings") or rec.get("savings") or 0
                try:
                    savings_val = float(savings)
                except (TypeError, ValueError):
                    savings_val = 0.0

                if savings_val < min_savings:
                    continue

                workload = rec.get("resourceName") or rec.get("workload") or rec.get("name") or ""
                risk_score = vuln_risk.get(workload, 0.0)

                # Security-weighted priority: higher risk = lower priority for rightsizing
                priority = "high" if risk_score < 10 else ("medium" if risk_score < 50 else "low")

                recommendations.append({
                    "workload": workload,
                    "namespace": rec.get("namespace", ""),
                    "monthly_savings_usd": round(savings_val, 2),
                    "current_cpu": rec.get("currentCpu") or rec.get("cpu", ""),
                    "recommended_cpu": rec.get("recommendedCpu") or rec.get("recCpu", ""),
                    "current_memory": rec.get("currentMemory") or rec.get("memory", ""),
                    "recommended_memory": rec.get("recommendedMemory") or rec.get("recMemory", ""),
                    "vuln_risk_score": round(risk_score, 1),
                    "rightsizing_priority": priority,
                    "note": (
                        "High vulnerability risk - review security before rightsizing"
                        if priority == "low"
                        else ""
                    ),
                })

            # Sort by priority (high first) then by savings descending
            priority_order = {"high": 0, "medium": 1, "low": 2}
            recommendations.sort(
                key=lambda x: (
                    priority_order.get(x["rightsizing_priority"], 9),
                    -x["monthly_savings_usd"],
                )
            )

    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_warning(f"API error: {e} - rightsizing data may not be available in this environment")
        recommendations = []

    total_savings = sum(r["monthly_savings_usd"] for r in recommendations)
    result: Dict[str, Any] = {
        "security_weighted_rightsizing": {
            "min_savings_threshold_usd": min_savings,
            "total_recommendations": len(recommendations),
            "total_potential_savings_usd": round(total_savings, 2),
            "recommendations": recommendations,
        }
    }
    output(result, fmt=format)
    print_info(
        f"Rightsizing: {len(recommendations)} recommendations, "
        f"${total_savings:.2f}/mo potential savings."
    )
