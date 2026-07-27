"""Base for the CIS "log metric filter AND alert" logging controls.

Each such control requires (a) a log-based metric whose filter matches a
specific audit pattern, and (b) a Monitoring alert policy watching that metric.
Subclasses declare the pattern via `required_all` / `required_any` substrings.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext
from gcpval.models import Method, MethodResult


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


class LoggingMetricAlertCheck(ResourceCheck):
    service = "logging"
    audit_log_corroboration = False

    #: all of these substrings must appear in a candidate metric filter
    required_all: List[str] = []
    #: at least one of these must appear (empty = no constraint)
    required_any: List[str] = []
    pattern_desc: str = ""

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project}]

    def _matching_metrics(self, ctx) -> List[Dict[str, Any]]:
        log = ctx.clients.discovery("logging", "v2")
        metrics: List[Dict[str, Any]] = []
        req = log.projects().metrics().list(parent=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            metrics.extend(resp.get("metrics", []) or [])
            req = log.projects().metrics().list_next(req, resp)
        out = []
        need_all = [_norm(s) for s in self.required_all]
        need_any = [_norm(s) for s in self.required_any]
        for m in metrics:
            f = _norm(m.get("filter", ""))
            if all(s in f for s in need_all) and (not need_any or any(s in f for s in need_any)):
                out.append(m)
        return out

    def _alerts_for_metric(self, ctx, metric_name: str) -> List[Dict[str, Any]]:
        mon = ctx.clients.discovery("monitoring", "v3")
        metric_type = f"logging.googleapis.com/user/{metric_name}"
        policies: List[Dict[str, Any]] = []
        req = mon.projects().alertPolicies().list(name=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            for p in resp.get("alertPolicies", []) or []:
                blob = _norm(str(p.get("conditions", [])))
                if _norm(metric_type) in blob:
                    policies.append(p)
            req = mon.projects().alertPolicies().list_next(req, resp)
        return policies

    def evaluate(self, ctx, res):
        metrics = self._matching_metrics(ctx)
        if not metrics:
            return False, (f"no log-based metric matches the required filter "
                           f"({self.pattern_desc}); need one metric + an alert"), {"metric": None}
        names = [m.get("name") for m in metrics]
        alerted = []
        for m in metrics:
            if self._alerts_for_metric(ctx, m.get("name", "")):
                alerted.append(m.get("name"))
        ok = bool(alerted)
        return ok, (f"matching metric(s)={names}; with alert policy={alerted or 'none'}"), \
            {"metrics": names, "alerted": alerted}

    def alternate_check(self, ctx, res) -> MethodResult:
        """Break the requirement into its two halves so a partial setup is visible."""
        metrics = self._matching_metrics(ctx)
        if not metrics:
            return MethodResult.ok(Method.ALTERNATE, False,
                                   "no matching log-based metric exists (so no alert can fire)")
        names = [m.get("name") for m in metrics]
        alerted = [m.get("name") for m in metrics if self._alerts_for_metric(ctx, m.get("name", ""))]
        return MethodResult.ok(
            Method.ALTERNATE, bool(alerted),
            f"metric present={names}; alert present for={alerted or 'none'}")
