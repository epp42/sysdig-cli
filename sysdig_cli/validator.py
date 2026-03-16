"""
Input validation and security checks.
Blocks path traversal, header injection, insecure hosts.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .formatter import print_warning

# Patterns to reject in path parameters
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),        # ../
    re.compile(r"\.\.[/\\]"),    # ..\ or ../
    re.compile(r"^\.\.$"),       # exactly ..
    re.compile(r"\0"),           # null byte
    re.compile(r"%2e%2e", re.IGNORECASE),  # URL-encoded ..
    re.compile(r"%00", re.IGNORECASE),     # URL-encoded null
]

# Header injection patterns
_HEADER_INJECTION_PATTERNS = [
    re.compile(r"\r\n"),   # CRLF
    re.compile(r"\r"),     # CR
    re.compile(r"\n"),     # LF
]

# Prometheus admin endpoints that should warn
_DANGEROUS_PROMETHEUS_PATHS = [
    "/prometheus/api/v1/admin/tsdb/delete_series",
    "/prometheus/api/v1/admin/tsdb/clean_tombstones",
    "/prometheus/api/v1/admin/tsdb/snapshot",
    "/prometheus/api/v1/write",
]

MAX_STRING_LENGTH = 4096
MAX_PARAM_LENGTH = 1024


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_host(host: str) -> None:
    """Ensure host uses HTTPS."""
    if not host.startswith("https://"):
        raise ValidationError(
            f"Host must use HTTPS (got {host!r}). "
            "Plaintext HTTP is not allowed for security reasons."
        )


def validate_path_param(name: str, value: str) -> str:
    """
    Validate a path parameter value.
    Blocks path traversal and null bytes.
    Returns the value if valid.
    """
    if not isinstance(value, str):
        return str(value)

    for pattern in _PATH_TRAVERSAL_PATTERNS:
        if pattern.search(value):
            raise ValidationError(
                f"Path parameter {name!r} contains potentially dangerous "
                f"characters: {value!r}"
            )

    if len(value) > MAX_PARAM_LENGTH:
        raise ValidationError(
            f"Path parameter {name!r} exceeds max length of {MAX_PARAM_LENGTH}."
        )

    return value


def validate_string_param(name: str, value: str) -> str:
    """
    Validate a string query parameter.
    Blocks header injection and overly long values.
    """
    if not isinstance(value, str):
        return str(value)

    for pattern in _HEADER_INJECTION_PATTERNS:
        if pattern.search(value):
            raise ValidationError(
                f"Parameter {name!r} contains header injection characters (CR/LF)."
            )

    if len(value) > MAX_STRING_LENGTH:
        raise ValidationError(
            f"Parameter {name!r} exceeds max length of {MAX_STRING_LENGTH}."
        )

    return value


def validate_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate all parameters in a dict. Returns cleaned dict."""
    validated = {}
    for name, value in params.items():
        if value is None:
            validated[name] = value
            continue
        if isinstance(value, str):
            validated[name] = validate_string_param(name, value)
        else:
            validated[name] = value
    return validated


def validate_api_path(path: str) -> str:
    """
    Validate an API path before use.
    Blocks path traversal attempts.
    """
    for pattern in _PATH_TRAVERSAL_PATTERNS:
        if pattern.search(path):
            raise ValidationError(
                f"API path contains dangerous characters: {path!r}"
            )
    return path


def check_dangerous_endpoint(path: str, method: str) -> None:
    """
    Warn about dangerous/destructive endpoints.
    Prints warning to stderr; does not block.
    """
    method_upper = method.upper()

    # Prometheus admin endpoints
    if any(path.startswith(dp) for dp in _DANGEROUS_PROMETHEUS_PATHS):
        print_warning(
            f"Prometheus admin endpoint detected: {method_upper} {path}. "
            "This may permanently delete or modify monitoring data."
        )
        return

    # DELETE operations on broad paths (no specific ID)
    if method_upper == "DELETE" and not re.search(r"\{[^}]+\}", path):
        print_warning(
            f"Bulk DELETE detected: {path}. "
            "This may delete multiple resources."
        )

    # Write operations
    if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
        # Warn on audit/security-critical paths
        for critical_prefix in ["/platform/v1/sso-settings", "/platform/v1/ip-filters"]:
            if path.startswith(critical_prefix):
                print_warning(
                    f"Security-sensitive endpoint: {method_upper} {path}. "
                    "Verify changes carefully."
                )
                return


def sanitize_for_logging(data: Any, sensitive_keys: Optional[list] = None) -> Any:
    """
    Remove sensitive values from data before logging.
    Masks token, password, secret, key fields.
    """
    if sensitive_keys is None:
        sensitive_keys = ["token", "password", "secret", "api_key", "apikey",
                         "authorization", "bearer", "credential"]

    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if any(s in k.lower() for s in sensitive_keys):
                result[k] = "****"
            else:
                result[k] = sanitize_for_logging(v, sensitive_keys)
        return result
    elif isinstance(data, list):
        return [sanitize_for_logging(item, sensitive_keys) for item in data]
    elif isinstance(data, str):
        # Check if it looks like a token (long base64-ish string)
        if len(data) > 32 and re.match(r"^[A-Za-z0-9+/=_\-\.]+$", data):
            return data[:4] + "****"
    return data
