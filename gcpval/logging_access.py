"""Helpers for validation method #3 — corroborate state from Cloud Audit Logs.

Cloud Audit Logs (Admin Activity + Data Access) record the API mutations that
produced the current configuration. For a given resource we can look for recent
config-change entries and inspect their payload, which is an independent signal
from reading the live resource.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Default look-back window for admin-activity correlation.
DEFAULT_WINDOW_DAYS = 90
MAX_ENTRIES = 20


def query_entries(clients, log_filter: str, max_entries: int = MAX_ENTRIES) -> List[Any]:
    """Run a Cloud Logging advanced filter and return entry objects (newest first)."""
    client = clients.logging_client()
    from google.cloud.logging_v2 import DESCENDING
    entries = client.list_entries(
        filter_=log_filter,
        order_by=DESCENDING,
        max_results=max_entries,
    )
    return list(entries)


def since_timestamp(window_days: int = DEFAULT_WINDOW_DAYS) -> str:
    """RFC3339 timestamp `window_days` ago (UTC), for use in log filters."""
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def audit_filter_for_resource(
    method_names: List[str],
    resource_name_substr: str = "",
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> str:
    """Build an advanced log filter for admin-activity method calls on a resource."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    methods = " OR ".join(f'protoPayload.methodName="{m}"' for m in method_names)
    parts = [
        'logName:"cloudaudit.googleapis.com"',
        f"timestamp>=\"{since}\"",
        f"({methods})",
    ]
    if resource_name_substr:
        parts.append(f'protoPayload.resourceName:"{resource_name_substr}"')
    return " AND ".join(parts)


def audit_filter_by_resource(
    resource_name_substr: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> str:
    """Any Cloud Audit Log entry mentioning a resource in the window.

    Service-agnostic corroboration: proves the resource has an audit trail and
    surfaces its most recent changes without needing per-service method names.
    """
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    parts = ['logName:"cloudaudit.googleapis.com"', f"timestamp>=\"{since}\""]
    if resource_name_substr:
        parts.append(f'protoPayload.resourceName:"{resource_name_substr}"')
    return " AND ".join(parts)


def entry_to_dict(entry: Any) -> Dict[str, Any]:
    """Normalise a log entry to a plain dict for evidence."""
    payload = getattr(entry, "payload", None)
    proto = payload if isinstance(payload, dict) else {}
    return {
        "timestamp": str(getattr(entry, "timestamp", "")),
        "method": proto.get("methodName", ""),
        "principal": (proto.get("authenticationInfo", {}) or {}).get("principalEmail", ""),
        "resource": proto.get("resourceName", ""),
    }
