"""
OpenAPI spec loader and service registry.
Loads and resolves the bundled Sysdig OpenAPI spec.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Path to bundled spec
_SPEC_PATH = Path(__file__).parent / "assets" / "openapi.json"

_spec_cache: Optional[Dict[str, Any]] = None


def load_spec(spec_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and return the raw OpenAPI spec (with $ref resolution)."""
    global _spec_cache
    if _spec_cache is not None and spec_path is None:
        return _spec_cache

    path = spec_path or _SPEC_PATH
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    resolved = resolve_refs(raw, raw)
    if spec_path is None:
        _spec_cache = resolved
    return resolved


def resolve_refs(obj: Any, root: Dict[str, Any], _depth: int = 0) -> Any:
    """Recursively resolve $ref references in an OpenAPI document."""
    if _depth > 20:
        # Prevent infinite recursion on circular refs
        return obj

    if isinstance(obj, dict):
        if "$ref" in obj:
            ref_path = obj["$ref"]
            resolved = _follow_ref(ref_path, root)
            # Merge remaining keys (allOf-style)
            extra = {k: v for k, v in obj.items() if k != "$ref"}
            result = resolve_refs(resolved, root, _depth + 1)
            if extra and isinstance(result, dict):
                result = {**result, **extra}
            return result
        return {k: resolve_refs(v, root, _depth + 1) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [resolve_refs(item, root, _depth + 1) for item in obj]
    return obj


def _follow_ref(ref: str, root: Dict[str, Any]) -> Any:
    """Follow a JSON $ref like '#/components/schemas/Foo'."""
    if not ref.startswith("#/"):
        # External ref - return as-is
        return {"$ref": ref}
    parts = ref[2:].split("/")
    node = root
    for part in parts:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            node = node.get(part, {})
        else:
            return {}
    return node


def get_paths(spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return the paths dict from the spec."""
    s = spec or load_spec()
    return s.get("paths", {})


def get_components(spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return the components dict from the spec."""
    s = spec or load_spec()
    return s.get("components", {})


# Service grouping: maps CLI group name -> list of path prefixes
SERVICE_MAP = {
    "vulns": ["/secure/vulnerability"],
    "events": ["/secure/events", "/monitor/events"],
    "audit": ["/secure/activity-audit"],
    "inventory": ["/secure/inventory"],
    "actions": ["/secure/response-actions"],
    "platform": ["/platform/v1", "/platform/v2"],
    "zones": ["/platform/v1/zones", "/platform/v2/zones", "/api/cspm/v1/zones"],
    "teams": ["/platform/v1/teams"],
    "users": ["/platform/v1/users"],
    "roles": ["/platform/v1/roles"],
    "alerts": ["/monitor/alerts"],
    "metrics": ["/prometheus/api/v1"],
    "sysql": ["/api/sysql/v2"],
    "fwd": ["/secure/events-forwarder"],
    "cost": ["/monitor/cost-advisor"],
}


def get_operations_for_service(
    service: str, spec: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Return list of operations for a given service group.
    Each dict has: path, method, operation_id, summary, parameters, request_body, responses
    """
    s = spec or load_spec()
    paths = get_paths(s)
    prefixes = SERVICE_MAP.get(service, [])

    operations = []
    for path, path_item in paths.items():
        if not any(path.startswith(p) for p in prefixes):
            continue
        for method, op in path_item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            if not isinstance(op, dict):
                continue
            operations.append(
                {
                    "path": path,
                    "method": method.lower(),
                    "operation_id": op.get("operationId", ""),
                    "summary": op.get("summary", ""),
                    "description": op.get("description", ""),
                    "parameters": op.get("parameters", []),
                    "request_body": op.get("requestBody"),
                    "responses": op.get("responses", {}),
                    "tags": op.get("tags", []),
                }
            )
    return operations


def get_all_operations(spec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Return all operations across all paths."""
    s = spec or load_spec()
    paths = get_paths(s)
    operations = []
    for path, path_item in paths.items():
        for method, op in path_item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            if not isinstance(op, dict):
                continue
            operations.append(
                {
                    "path": path,
                    "method": method.lower(),
                    "operation_id": op.get("operationId", ""),
                    "summary": op.get("summary", ""),
                    "description": op.get("description", ""),
                    "parameters": op.get("parameters", []),
                    "request_body": op.get("requestBody"),
                    "responses": op.get("responses", {}),
                    "tags": op.get("tags", []),
                }
            )
    return operations


def find_operation(
    path: str, method: str, spec: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Find a specific operation by path and method."""
    s = spec or load_spec()
    paths = get_paths(s)
    path_item = paths.get(path, {})
    op = path_item.get(method.lower())
    if not op:
        return None
    return {
        "path": path,
        "method": method.lower(),
        "operation_id": op.get("operationId", ""),
        "summary": op.get("summary", ""),
        "description": op.get("description", ""),
        "parameters": op.get("parameters", []),
        "request_body": op.get("requestBody"),
        "responses": op.get("responses", {}),
        "tags": op.get("tags", []),
    }


def extract_path_params(path: str) -> List[str]:
    """Extract path parameter names from a path like /foo/{id}/bar/{name}."""
    import re
    return re.findall(r"\{(\w+)\}", path)


def path_to_command_name(path: str, service: str) -> Tuple[str, List[str]]:
    """
    Convert an API path to a CLI command name.
    Returns (command_name, path_params).
    """
    # Strip service prefix
    prefixes = SERVICE_MAP.get(service, [])
    stripped = path
    for prefix in sorted(prefixes, key=len, reverse=True):
        if path.startswith(prefix):
            stripped = path[len(prefix):]
            break

    # Remove version segments
    import re
    stripped = re.sub(r"^/v\d+[a-z0-9]*/", "/", stripped)
    stripped = re.sub(r"^/v\d+[a-z0-9]*$", "", stripped)

    # Extract path params
    path_params = extract_path_params(stripped)

    # Remove path params from name
    name_part = re.sub(r"/\{[^}]+\}", "", stripped)
    name_part = name_part.strip("/")

    # Convert to kebab-case
    name_part = name_part.replace("/", "-").replace("_", "-")
    name_part = re.sub(r"-+", "-", name_part).strip("-")

    return name_part or "root", path_params
