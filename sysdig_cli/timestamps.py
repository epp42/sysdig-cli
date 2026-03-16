"""
Timestamp utilities for Sysdig API.
Sysdig uses nanoseconds since epoch.
Supports relative time expressions like '1h', '30m', '7d' and ISO8601.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Optional

NANOSECONDS_PER_SECOND = int(1e9)

# Relative time patterns
_RELATIVE_PATTERN = re.compile(r"^(\d+(?:\.\d+)?)\s*(ns|us|ms|s|m|h|d|w)$", re.IGNORECASE)

_UNIT_TO_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 7 * 86400.0,
}


def now_ns() -> int:
    """Return current time in nanoseconds."""
    return int(time.time() * NANOSECONDS_PER_SECOND)


def unix_to_ns(unix_seconds: float) -> int:
    """Convert Unix timestamp (seconds) to nanoseconds."""
    return int(unix_seconds * NANOSECONDS_PER_SECOND)


def ns_to_unix(ns: int) -> float:
    """Convert nanoseconds to Unix timestamp (seconds)."""
    return ns / NANOSECONDS_PER_SECOND


def ns_to_datetime(ns: int) -> datetime:
    """Convert nanoseconds to UTC datetime."""
    return datetime.fromtimestamp(ns_to_unix(ns), tz=timezone.utc)


def parse_timestamp(value: str) -> int:
    """
    Parse a timestamp string to nanoseconds.

    Supported formats:
    - Relative: '30m', '1h', '2h30m', '7d', '24h'
    - ISO8601: '2024-01-15T10:00:00Z'
    - Unix seconds: '1705312800'
    - Unix nanoseconds: '1705312800000000000'
    """
    if not value:
        raise ValueError("Empty timestamp value")

    value = value.strip()

    # Try relative time (e.g., "1h", "30m", "7d")
    match = _RELATIVE_PATTERN.match(value)
    if match:
        amount = float(match.group(1))
        unit = match.group(2).lower()
        seconds_ago = amount * _UNIT_TO_SECONDS[unit]
        return int((time.time() - seconds_ago) * NANOSECONDS_PER_SECOND)

    # Try compound relative time (e.g., "2h30m")
    compound = _parse_compound_relative(value)
    if compound is not None:
        return compound

    # Try ISO8601
    try:
        dt = _parse_iso8601(value)
        return unix_to_ns(dt.timestamp())
    except (ValueError, TypeError):
        pass

    # Try plain integer
    try:
        val = int(value)
        # Heuristic: if > 1e18 it's already nanoseconds, else treat as seconds
        if val > int(1e18):
            return val
        elif val > int(1e12):
            # Milliseconds?
            return val * int(1e6)
        else:
            return unix_to_ns(val)
    except ValueError:
        pass

    raise ValueError(
        f"Cannot parse timestamp: {value!r}. "
        "Supported formats: '30m', '1h', '7d', ISO8601, Unix seconds/nanoseconds"
    )


def _parse_compound_relative(value: str) -> Optional[int]:
    """Parse compound relative time like '2h30m' or '1d12h'."""
    pattern = re.compile(r"(\d+(?:\.\d+)?)(ns|us|ms|s|m|h|d|w)", re.IGNORECASE)
    matches = pattern.findall(value)
    if not matches:
        return None

    # Verify the full string is composed of these patterns
    reconstructed = "".join(f"{m[0]}{m[1]}" for m in matches)
    if reconstructed.lower() != value.lower():
        return None

    total_seconds = sum(
        float(amount) * _UNIT_TO_SECONDS[unit.lower()]
        for amount, unit in matches
    )
    return int((time.time() - total_seconds) * NANOSECONDS_PER_SECOND)


def _parse_iso8601(value: str) -> datetime:
    """Parse ISO8601 datetime string."""
    # Handle Z suffix
    value = value.replace("Z", "+00:00")

    # Try various formats
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Python 3.11+ fromisoformat handles more cases
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    raise ValueError(f"Cannot parse ISO8601: {value!r}")


def format_ns(ns: int) -> str:
    """Format nanoseconds as human-readable ISO8601 UTC string."""
    dt = ns_to_datetime(ns)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
