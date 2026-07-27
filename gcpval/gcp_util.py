"""Small cross-service helpers."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def public_bindings(iam_policy: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return (role, member) pairs that grant access to allUsers/allAuthenticatedUsers."""
    out: List[Tuple[str, str]] = []
    for b in (iam_policy or {}).get("bindings", []) or []:
        role = b.get("role", "")
        for m in b.get("members", []) or []:
            if m in PUBLIC_MEMBERS:
                out.append((role, m))
    return out


def is_public(iam_policy: Dict[str, Any]) -> bool:
    return bool(public_bindings(iam_policy))


def parse_rfc3339(ts: str):
    """Parse an RFC3339 / ISO timestamp to an aware datetime, or None."""
    if not ts:
        return None
    from datetime import datetime, timezone
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Fallback for nanosecond precision Google sometimes emits.
        try:
            base = s.split(".")[0]
            dt = datetime.fromisoformat(base)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def age_days(ts: str, now=None) -> Optional[float]:
    """Age in days of an RFC3339 timestamp; None if unparseable."""
    dt = parse_rfc3339(ts)
    if dt is None:
        return None
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    return (now - dt).total_seconds() / 86400.0


def duration_seconds(dur: str) -> Optional[float]:
    """Parse a GCP duration string like '7776000s' to seconds."""
    if not dur:
        return None
    d = dur.strip()
    if d.endswith("s"):
        d = d[:-1]
    try:
        return float(d)
    except ValueError:
        return None
