"""ResourceCheck — a declarative base for property-style checks.

Most controls reduce to: enumerate resources, then decide compliant/not from a
property. Subclasses implement `discover_resources()` and `evaluate()`; this
base derives methods 1 (API) and 2 (Prowler replica) from `evaluate`, and
provides a generic method-3 (Cloud Audit Log corroboration by resource name).
Methods 4 (alternate) and 5 (exposure) stay N/A unless the subclass overrides
them.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from .base_check import BaseCheck
from .context import ValidationContext
from .models import Method, MethodResult, Verdict
from . import logging_access as logs


class ResourceCheck(BaseCheck):
    #: set True to attempt the generic audit-log corroboration for method 3
    audit_log_corroboration: bool = True

    def evaluate(self, ctx: ValidationContext, res: Dict[str, Any]) -> Tuple[bool, str, dict]:
        """Return (compliant, human_detail, evidence_dict)."""
        raise NotImplementedError

    def api_check(self, ctx, res) -> MethodResult:
        compliant, detail, ev = self.evaluate(ctx, res)
        return MethodResult.ok(Method.API, compliant, detail, **ev)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        compliant, detail, ev = self.evaluate(ctx, res)
        return MethodResult.ok(
            Method.PROWLER_REPLICA, compliant,
            f"Prowler rule ({self.hub_link}): {detail}", **ev)

    def logs_check(self, ctx, res) -> MethodResult:
        if not self.audit_log_corroboration:
            return MethodResult.na(Method.LOGS, "no log-based signal for this check")
        name = str(res.get("name", "")) or str(res.get("id", ""))
        if not name:
            return MethodResult.na(Method.LOGS, "no resource name to correlate logs")
        flt = logs.audit_filter_by_resource(name, window_days=ctx.log_window_days)
        entries = logs.query_entries(ctx.clients, flt)
        if not entries:
            return MethodResult.na(
                Method.LOGS,
                f"no Cloud Audit Log entries mentioning '{name}' in last "
                f"{ctx.log_window_days}d")
        recent = [logs.entry_to_dict(e) for e in entries[:5]]
        return MethodResult(
            Method.LOGS, Verdict.MANUAL,
            f"{len(entries)} audit entr(y/ies) found for '{name}'; current-state "
            f"check is authoritative",
            {"recent_events": recent})
