"""
Output formatters: JSON, table, YAML, CSV, NDJSON.
Only JSON-compatible data to stdout. All warnings to stderr.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Console for stderr output (human-readable)
_stderr_console = Console(stderr=True, highlight=False)


def print_error(msg: str) -> None:
    """Print error message to stderr."""
    _stderr_console.print(f"[bold red]Error:[/bold red] {msg}")


def print_warning(msg: str) -> None:
    """Print warning to stderr."""
    _stderr_console.print(f"[bold yellow]Warning:[/bold yellow] {msg}")


def print_info(msg: str) -> None:
    """Print info message to stderr."""
    _stderr_console.print(f"[dim]{msg}[/dim]")


def flatten_dict(obj: Any, prefix: str = "", sep: str = ".") -> Dict[str, Any]:
    """Flatten a nested dict using dot notation."""
    result: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, (dict, list)):
                nested = flatten_dict(v, key, sep)
                result.update(nested)
            else:
                result[key] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}{sep}{i}" if prefix else str(i)
            if isinstance(v, (dict, list)):
                nested = flatten_dict(v, key, sep)
                result.update(nested)
            else:
                result[key] = v
    else:
        result[prefix] = obj
    return result


def format_json(data: Any) -> str:
    """Format data as pretty-printed JSON."""
    return json.dumps(data, indent=2, default=str)


def format_yaml(data: Any) -> str:
    """Format data as YAML."""
    return yaml.dump(data, default_flow_style=False, allow_unicode=True)


def format_ndjson(data: Any) -> str:
    """Format data as newline-delimited JSON — one item per line."""
    # Extract the list from a paginated response dict
    rows = _extract_rows(data)
    if len(rows) == 1 and rows[0] is data:
        # _extract_rows wrapped a non-list in a list; output the whole thing
        return json.dumps(data, default=str)
    return "\n".join(json.dumps(item, default=str) for item in rows)


def _extract_rows(data: Any) -> List[Dict[str, Any]]:
    """Extract a list of row dicts from various data shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Common Sysdig response patterns
        for key in ("data", "items", "results", "entries", "resources", "policies",
                    "zones", "teams", "users", "roles", "channels", "integrations",
                    "actions", "schedules", "jobs", "bundles", "sboms",
                    "acceptedRisks", "inhibitionRules", "notificationChannels",
                    "accessKeys", "groupMappings", "ipFilters", "serviceAccounts",
                    "notifications", "templates", "alerts", "rules", "events",
                    "vulnerabilities", "packages", "images", "clusters", "nodes",
                    "zone_comparison", "comparison", "diff", "changes"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Single object
        return [data]
    return [{"value": str(data)}]


# ---------------------------------------------------------------------------
# Named display schemas: (field_path, header, width)
# field_path supports dot notation for nested fields
# ---------------------------------------------------------------------------

DISPLAY_SCHEMAS: Dict[str, List[Tuple[str, str, int]]] = {
    "vulns_runtime": [
        ("resultId", "RESULT-ID", 10),
        ("mainAssetName", "WORKLOAD", 60),
        ("vulnTotalBySeverity.critical", "CRIT", 5),
        ("vulnTotalBySeverity.high", "HIGH", 5),
        ("vulnTotalBySeverity.medium", "MED", 5),
        ("vulnTotalBySeverity.low", "LOW", 5),
        ("policyEvaluationResult", "STATUS", 7),
    ],
    "vulns_reachable": [
        ("resultId", "RESULT-ID", 10),
        ("mainAssetName", "WORKLOAD", 60),
        ("runningVulnTotalBySeverity.critical", "CRIT", 5),
        ("runningVulnTotalBySeverity.high", "HIGH", 5),
        ("runningVulnTotalBySeverity.medium", "MED", 5),
        ("runningVulnTotalBySeverity.low", "LOW", 5),
        ("policyEvaluationResult", "STATUS", 7),
    ],
    "vuln_cves": [
        ("cve", "CVE", 20),
        ("severity", "SEV", 8),
        ("package", "PACKAGE", 28),
        ("version", "VERSION", 14),
        ("fix", "FIX", 14),
        ("epss", "EPSS", 7),
        ("disclosed", "DISCLOSED", 11),
        ("kev", "KEV", 4),
        ("exploitable", "XPLOIT", 7),
        ("workload", "WORKLOAD", 40),
    ],
    "events": [
        ("timestamp", "TIME", 14),
        ("severity", "SEV", 4),
        ("content.ruleName", "RULE", 50),
        ("content.output", "OUTPUT", 72),
        ("content.fields.container.name", "CONTAINER", 36),
    ],
    "audit": [
        ("timestamp", "TIME", 20),
        ("userEmail", "USER", 30),
        ("action", "ACTION", 20),
        ("resourceType", "RESOURCE", 20),
        ("sourceIp", "SOURCE IP", 18),
    ],
    "zones": [
        ("name", "NAME", 40),
        ("id", "ID", 10),
        ("author", "CREATED BY", 25),
        ("lastModifiedBy", "MODIFIED BY", 25),
    ],
    "users": [
        ("email", "EMAIL", 35),
        ("firstName", "FIRST", 15),
        ("lastName", "LAST", 15),
        ("isAdmin", "ADMIN", 6),
        ("isEnabled", "ON", 4),
        ("activationStatus", "STATUS", 12),
        ("dateCreated", "CREATED", 12),
    ],
    "teams": [
        ("name", "NAME", 35),
        ("id", "ID", 10),
        ("description", "DESCRIPTION", 50),
    ],
    "top_workloads": [
        ("name", "WORKLOAD", 60),
        ("critical", "CRIT", 6),
        ("high", "HIGH", 6),
    ],
    "policies": [
        ("name", "NAME", 45),
        ("id", "ID", 10),
        ("type", "TYPE", 12),
        ("enabled", "ENABLED", 8),
        ("description", "DESCRIPTION", 40),
    ],
    "alerts": [
        ("name", "NAME", 40),
        ("id", "ID", 10),
        ("enabled", "ENABLED", 8),
        ("severity", "SEV", 5),
        ("type", "TYPE", 15),
    ],
    "scan_summary": [
        ("workloads", "WORKLOADS", 12),
        ("total_vulns", "TOTAL VULNS", 13),
        ("critical", "CRIT", 10),
        ("high", "HIGH", 10),
        ("medium", "MED", 12),
        ("low", "LOW", 10),
        ("negligible", "NEGLIGIBLE", 12),
    ],
    "zone_comparison": [
        ("zone", "CLOUD", 12),
        ("total_workloads", "WORKLOADS", 10),
        ("critical", "CRIT", 8),
        ("high", "HIGH", 8),
        ("medium", "MED", 8),
        ("low", "LOW", 8),
    ],
    "events_list": [
        ("id", "ID", 10),
        ("timestamp", "TIME", 14),
        ("severity", "SEV", 4),
        ("content.ruleName", "RULE", 50),
        ("content.fields.container.name", "CONTAINER", 36),
        ("content.fields.k8s.pod.name", "POD", 36),
        ("content.output", "OUTPUT", 60),
    ],
    "captures_list": [
        ("id", "ID", 10),
        ("type", "TYPE", 16),
        ("status", "STATUS", 10),
        ("container", "CONTAINER", 36),
        ("duration", "DURATION", 9),
        ("created", "CREATED", 24),
        ("failure", "FAILURE", 40),
    ],
    "captures_actions": [
        ("type", "ACTION TYPE", 22),
        ("responder", "RESPONDER", 14),
        ("required_params", "REQUIRED PARAMS", 30),
        ("optional_params", "OPTIONAL PARAMS", 30),
        ("undoable", "UNDO", 5),
        ("description", "DESCRIPTION", 60),
    ],
    "vulns_list": [
        ("resultId", "RESULT-ID", 10),
        ("mainAssetName", "WORKLOAD", 60),
        ("vulnTotalBySeverity.critical", "CRIT", 5),
        ("vulnTotalBySeverity.high", "HIGH", 5),
        ("vulnTotalBySeverity.medium", "MED", 5),
        ("vulnTotalBySeverity.low", "LOW", 5),
        ("policyEvaluationResult", "STATUS", 7),
    ],
    "vulns_accepted_risks": [
        ("id", "ID", 12),
        ("entityValue", "CVE/ENTITY", 22),
        ("entityType", "TYPE", 14),
        ("context", "CONTEXT", 22),
        ("reason", "REASON", 35),
        ("expirationDate", "EXPIRES", 12),
        ("createdBy", "CREATED-BY", 22),
    ],
    "iam_access_keys": [
        ("id", "ID", 10),
        ("accessKey", "ACCESS-KEY", 40),
        ("isEnabled", "ON", 5),
        ("dateCreated", "CREATED", 12),
        ("dateDisabled", "DISABLED", 12),
        ("teamId", "TEAM-ID", 10),
        ("agentLimit", "AGENT-LIMIT", 12),
    ],
    "iam_roles": [
        ("id", "ID", 8),
        ("name", "NAME", 30),
        ("description", "DESCRIPTION", 50),
    ],
    "iam_group_mappings": [
        ("id", "ID", 8),
        ("groupName", "GROUP", 30),
        ("standardTeamRole", "ROLE", 20),
        ("isAdmin", "ADMIN", 6),
        ("weight", "WEIGHT", 8),
        ("dateCreated", "CREATED", 12),
    ],
    "platform_audit_events": [
        ("id", "ID", 12),
        ("timestamp", "TIME", 14),
        ("content.username", "USER", 30),
        ("content.requestMethod", "METHOD", 8),
        ("content.requestUri", "URI", 60),
        ("content.entityType", "ENTITY-TYPE", 20),
        ("content.userOriginIP", "SOURCE-IP", 18),
    ],
}

# Priority field ordering for smart detection
_PRIORITY_FIELDS = [
    "name", "title", "email", "type", "kind", "status", "state",
    "severity", "count", "critical", "high", "medium", "low",
    "created_at", "updated_at", "createdAt", "updatedAt", "timestamp",
]

# Fields that look like internal IDs - skip unless few fields
_ID_SUFFIXES = ("Id", "UUID", "Ref", "id", "uuid", "ref")

# Headers whose column width should never be scaled below the actual content
# (measured from first 20 rows, capped at 80 chars)
_CONTENT_MIN_HEADERS = {"WORKLOAD", "RULE", "OUTPUT", "CONTAINER", "POD"}


def _get_nested(obj: Dict[str, Any], path: str) -> Any:
    """Get a value using dot notation, with fallback for dot-in-key names.

    Tries progressive splits: for path "scope.asset.type" it tries:
      1. obj["scope"]["asset"]["type"]   (pure nesting)
      2. obj["scope"]["asset.type"]      (dot in sub-key)
      3. obj["scope.asset.type"]         (dot in top-level key)
      4. obj["scope.asset"]["type"]      (dot in prefix)
    Returns the first non-None result.
    """
    parts = path.split(".")

    def _descend(current: Any, remaining: List[str]) -> Any:
        if not remaining:
            return current
        if not isinstance(current, dict):
            return None
        key = remaining[0]
        rest = remaining[1:]
        # Try consuming 1, 2, ... keys joined with dots
        for n in range(1, len(remaining) + 1):
            joined = ".".join(remaining[:n])
            if joined in current:
                result = _descend(current[joined], remaining[n:])
                if result is not None:
                    return result
        return None

    return _descend(obj, parts)


def _ns_to_human(ns: Any) -> str:
    """Convert nanosecond timestamp to human-readable string."""
    if ns is None:
        return ""
    try:
        ns_int = int(ns)
        if ns_int <= 0:
            return str(ns)
        # Sysdig uses nanoseconds (>1e18) or seconds (<1e12)
        if ns_int > int(1e18):
            secs = ns_int / 1e9
        elif ns_int > int(1e12):
            secs = ns_int / 1e3  # milliseconds
        else:
            secs = float(ns_int)
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
        return dt.strftime("%d %b %H:%M")
    except (ValueError, TypeError, OSError):
        return str(ns)


def _format_date(val: Any) -> str:
    """Format a date string to YYYY-MM-DD."""
    if not val:
        return ""
    s = str(val)
    if "T" in s:
        return s[:10]
    return s


def _smart_detect_columns(rows: List[Dict[str, Any]]) -> List[Tuple[str, str, int]]:
    """
    Smart column detection for generic data:
    1. Only top-level scalar fields (no nested dicts/lists)
    2. Skip internal ID fields unless fewer than 4 total
    3. Prefer priority fields
    4. Max 10 columns
    """
    if not rows:
        return []

    # Collect top-level scalar keys from first 20 rows
    scalar_keys: List[str] = []
    seen: set = set()
    for row in rows[:20]:
        if not isinstance(row, dict):
            continue
        for k, v in row.items():
            if k not in seen and not isinstance(v, (dict, list)):
                seen.add(k)
                scalar_keys.append(k)

    # If no scalar keys at all, fall back to flattened
    if not scalar_keys:
        flat = flatten_dict(rows[0]) if rows else {}
        scalar_keys = list(flat.keys())

    # Filter out ID-like fields unless very few remain
    def _is_id_field(k: str) -> bool:
        for suffix in _ID_SUFFIXES:
            if k.endswith(suffix) and len(k) > len(suffix):
                return True
        return False

    filtered = [k for k in scalar_keys if not _is_id_field(k)]
    if len(filtered) < 3:
        filtered = scalar_keys  # not enough after filter, keep all

    # Sort by priority: priority-listed fields first, then others
    def _priority(k: str) -> int:
        k_lower = k.lower()
        for i, pf in enumerate(_PRIORITY_FIELDS):
            if k_lower == pf.lower() or k_lower.startswith(pf.lower()):
                return i
        return len(_PRIORITY_FIELDS) + 1

    filtered.sort(key=_priority)

    # Determine terminal width
    try:
        term_width = os.get_terminal_size(fallback=(120, 24)).columns
    except Exception:
        term_width = 120

    max_cols = 10
    # Fewer cols on narrow terminals
    if term_width < 80:
        max_cols = 5
    elif term_width < 100:
        max_cols = 7

    cols = filtered[:max_cols]

    # Compute reasonable widths
    def _col_width(k: str) -> int:
        max_val_len = max(
            len(str(row.get(k, "") or "")) for row in rows[:50]
        )
        return max(max(len(k), 8), min(max_val_len, 40))

    return [(k, k, _col_width(k)) for k in cols]


def _shorten_workload(name: str) -> str:
    """Shorten container image paths to last 2 path segments.

    Examples:
      us-docker.pkg.dev/org/tools/frontend-runner:1.1.9  →  tools/frontend-runner:1.1.9
      ghcr.io/dandelion-python/dandelion-python:latest   →  dandelion-python/dandelion-python:latest
      nginx:1.20.1                                       →  nginx:1.20.1
      quickstart-rancher-server                          →  quickstart-rancher-server
      arn:aws:ecs:us-east-1:.../task/abc123              →  task/abc123
    """
    # Strip sha256 digest first
    if "@sha256:" in name:
        name = name.split("@sha256:")[0]
    parts = name.split("/")
    if len(parts) > 2:
        return "/".join(parts[-2:])
    return name


def _apply_color(header: str, val: str, raw: Any) -> Text:
    """Apply color rules based on column header and raw value."""
    text = Text(val, overflow="ellipsis")

    if header == "CRIT":
        try:
            if int(raw or 0) > 0:
                text.stylize("bold red")
        except (ValueError, TypeError):
            pass
    elif header == "HIGH":
        try:
            if int(raw or 0) > 0:
                text.stylize("yellow")
        except (ValueError, TypeError):
            pass
    elif header == "SEV":
        # Events use integer severity (higher = worse); vulns use string (critical/high/...)
        try:
            sev = int(raw or 0)
            if sev >= 7:
                text.stylize("bold red")
            elif sev >= 5:
                text.stylize("yellow")
        except (ValueError, TypeError):
            sev_lower = val.lower()
            if sev_lower == "critical":
                text.stylize("bold red")
            elif sev_lower == "high":
                text.stylize("yellow")
    elif header == "STATUS":
        val_lower = val.lower()
        if val_lower == "failed":
            text.stylize("red")
        elif val_lower == "passed":
            text.stylize("green")
    elif header == "ADMIN":
        if raw is True or val.lower() in ("true", "1", "yes"):
            text.stylize("bold yellow")
    elif header == "ON":
        if raw is False or val.lower() in ("false", "0", "no"):
            text.stylize("dim red")
    elif header == "KEV":
        if val == "yes":
            text.stylize("bold red")
    elif header == "XPLOIT":
        if val == "yes":
            text.stylize("yellow")

    return text


def _render_schema_table(
    rows: List[Dict[str, Any]],
    schema: List[Tuple[str, str, int]],
    term_width: int = 120,
    return_rich: bool = False,
    no_trunc: bool = False,
) -> Any:
    """Render a table using a named schema."""
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")

    # Two-pass column sizing:
    # Pass 1: Fixed-width columns (TIME, SEV, CRIT, HIGH, MED, LOW, ADMIN, ON, ID, TYPE, CLOUD)
    #         get their exact desired width — never scaled down.
    # Pass 2: Variable columns (NAME, WORKLOAD, RULE, OUTPUT, DESCRIPTION, etc.)
    #         share remaining terminal space proportionally.
    FIXED_HEADERS = {"TIME", "SEV", "CRIT", "HIGH", "MED", "LOW", "ADMIN", "ON",
                     "ID", "RESULT-ID", "TYPE", "CLOUD", "STATUS", "ENABLED",
                     "CREATED", "MODIFIED", "DISCLOSED", "KEV", "XPLOIT",
                     "DURATION", "UNDO", "METHOD", "SOURCE-IP", "EPSS", "ON",
                     "LAST-USED"}
    col_padding = len(schema) * 3  # rich adds ~3 chars per col for borders/padding
    available = max(term_width - col_padding, 40)

    fixed_total = sum(w for _, h, w in schema if h in FIXED_HEADERS)
    variable_desired = sum(w for _, h, w in schema if h not in FIXED_HEADERS)
    variable_budget = max(available - fixed_total, variable_desired * 0.4)
    var_scale = min(1.0, variable_budget / max(variable_desired, 1))

    # Compute content-based minimums for _CONTENT_MIN_HEADERS from first 20 rows
    content_mins: Dict[str, int] = {}
    if not no_trunc:
        for field_path, header, width in schema:
            if header in _CONTENT_MIN_HEADERS:
                max_len = max(
                    (len(str(_get_nested(r, field_path) or "")) for r in rows[:20]),
                    default=0,
                )
                content_mins[header] = min(max_len, 80)

    if no_trunc:
        for _field, header, width in schema:
            if header in FIXED_HEADERS:
                final_w = max(len(header) + 1, width)
            else:
                final_w = max(len(header) + 1, width)
            table.add_column(header, overflow="fold")
    else:
        for _field, header, width in schema:
            if header in FIXED_HEADERS:
                final_w = max(len(header) + 1, width)
            else:
                scaled = max(len(header) + 1, int(width * var_scale))
                if header in _CONTENT_MIN_HEADERS:
                    content_min = content_mins.get(header, 0)
                    final_w = max(scaled, min(content_min, 80))
                else:
                    final_w = scaled
            table.add_column(header, max_width=final_w, overflow="ellipsis", no_wrap=True)

    for row in rows:
        values = []
        for field_path, header, width in schema:
            raw = _get_nested(row, field_path)
            if raw is None:
                val_str = ""
            elif header == "TIME":
                val_str = _ns_to_human(raw)
            elif header in ("CREATED", "MODIFIED", "DISCLOSED"):
                val_str = _format_date(raw)
            elif header == "WORKLOAD":
                val_str = str(raw) if no_trunc else _shorten_workload(str(raw))
            elif header == "RESULT-ID":
                # Show only first 8 chars of UUID-like IDs
                val_str = str(raw)[:8]
            elif header in ("KEV", "XPLOIT"):
                val_str = "yes" if raw else ""
            else:
                val_str = str(raw)
            # Manual truncation so "..." appears in output (not rich's "…")
            # Skip truncation when no_trunc=True
            if not no_trunc and len(val_str) > width:
                val_str = val_str[:width - 3] + "..."
            values.append(_apply_color(header, val_str, raw))
        table.add_row(*values)

    if return_rich:
        return table

    buf = io.StringIO()
    console = Console(file=buf, highlight=False, width=term_width)
    console.print(table)
    return buf.getvalue().rstrip()


def format_table(
    data: Any,
    max_col_width: int = 50,
    schema: Optional[str] = None,
    return_rich: bool = False,
    no_trunc: bool = False,
) -> Any:
    """Format data as a rich table.

    If schema is a key in DISPLAY_SCHEMAS, use that schema.
    Otherwise use smart column detection.
    """
    rows = _extract_rows(data)
    if not rows:
        if return_rich:
            t = Table(box=box.SIMPLE)
            t.add_column("(empty)")
            return t
        return "(empty)"

    try:
        term_width = os.get_terminal_size(fallback=(120, 24)).columns
    except Exception:
        term_width = 120

    # Named schema
    if schema and schema in DISPLAY_SCHEMAS:
        schema_def = DISPLAY_SCHEMAS[schema]
        return _render_schema_table(
            rows, schema_def, term_width=term_width, return_rich=return_rich,
            no_trunc=no_trunc,
        )

    # Smart detection
    smart_cols = _smart_detect_columns(rows)
    if smart_cols:
        return _render_schema_table(
            rows, smart_cols, term_width=term_width, return_rich=return_rich,
            no_trunc=no_trunc,
        )

    # Fallback: flatten and show first 10 cols
    flat_rows = [flatten_dict(row) if isinstance(row, dict) else {"value": str(row)} for row in rows]
    all_keys: List[str] = []
    seen: set = set()
    for row in flat_rows[:100]:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                all_keys.append(k)
    cols = all_keys[:10]

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    if no_trunc:
        for col in cols:
            table.add_column(col, overflow="fold")
    else:
        for col in cols:
            table.add_column(col, max_width=max_col_width, overflow="ellipsis", no_wrap=False)

    for row in flat_rows:
        vals = []
        for col in cols:
            v = row.get(col, "")
            if v is None:
                v = ""
            v_str = str(v)
            if not no_trunc and len(v_str) > max_col_width:
                v_str = v_str[:max_col_width - 3] + "..."
            vals.append(v_str)
        table.add_row(*vals)

    if return_rich:
        return table

    buf = io.StringIO()
    console = Console(file=buf, highlight=False, width=term_width)
    console.print(table)
    return buf.getvalue().rstrip()


def format_csv(data: Any) -> str:
    """Format data as CSV."""
    rows = _extract_rows(data)
    if not rows:
        return ""
    flat_rows = [flatten_dict(row) if isinstance(row, dict) else {"value": str(row)} for row in rows]

    all_keys: List[str] = []
    seen: set = set()
    for row in flat_rows:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                all_keys.append(k)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=all_keys, extrasaction="ignore")
    writer.writeheader()
    for row in flat_rows:
        writer.writerow({k: row.get(k, "") for k in all_keys})
    return buf.getvalue().rstrip()


def output(
    data: Any,
    fmt: str = "json",
    file: Any = None,
    schema: Optional[str] = None,
    no_trunc: bool = False,
) -> None:
    """
    Output data in the specified format to stdout (or file).
    ONLY goes to stdout - errors/warnings go to stderr separately.

    schema: optional key in DISPLAY_SCHEMAS for named table rendering.
    no_trunc: when True, disable all truncation in table output.
    """
    if file is None:
        file = sys.stdout

    if data is None:
        return

    fmt = fmt.lower()
    if fmt == "json":
        print(format_json(data), file=file)
    elif fmt == "yaml":
        print(format_yaml(data), file=file, end="")
    elif fmt in ("ndjson", "nd-json"):
        print(format_ndjson(data), file=file)
    elif fmt == "table":
        print(format_table(data, schema=schema, no_trunc=no_trunc), file=file)
    elif fmt == "csv":
        print(format_csv(data), file=file)
    else:
        # Default to JSON
        print(format_json(data), file=file)


def format_structured_error(
    error_type: str,
    message: str,
    details: Optional[List[str]] = None,
) -> str:
    """Format a structured error as JSON for stderr."""
    err = {"type": error_type, "message": message}
    if details:
        err["details"] = details
    return json.dumps(err, indent=2)
