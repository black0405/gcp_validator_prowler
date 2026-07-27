"""BaseCheck — the contract every per-control script implements.

A check discovers the resources it cares about from live GCP, then runs each of
the five validation methods against every resource. Methods that do not apply
return N/A (with a reason) instead of a fake verdict. Each Prowler finding for
the check is matched to a live resource so the report can compare verdicts and
flag likely false positives / negatives.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import hub
from .context import ValidationContext
from .models import CheckResult, Method, MethodResult, ResourceResult, Verdict
from .prowler import ProwlerFinding


class BaseCheck:
    # Subclasses MUST set these.
    check_id: str = ""
    service: str = ""

    def __init__(self) -> None:
        if not self.check_id:
            raise ValueError(f"{type(self).__name__} must set check_id")
        m = hub.meta(self.check_id)
        self.service = self.service or m["service"]
        self.severity = m["severity"]
        self.title = m["title"]
        self.hub_link = m["hub_link"]

    # ---- resource discovery (override) ---------------------------------
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        """Return the list of resources to evaluate.

        Each resource is a dict; the framework only requires 'id' and 'name'
        (and optionally 'project', 'region'). Subclasses add whatever fields
        their methods need.
        """
        raise NotImplementedError

    # ---- the five validation methods (override the ones that apply) ----
    def api_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        return MethodResult.na(Method.API, "no direct-API validation defined")

    def prowler_replica_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        return MethodResult.na(Method.PROWLER_REPLICA, "no Prowler-replica logic defined")

    def logs_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        return MethodResult.na(Method.LOGS, "no log-based signal for this check")

    def alternate_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        return MethodResult.na(Method.ALTERNATE, "no alternate check for this check")

    def exposure_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        return MethodResult.na(Method.EXPOSURE, "not an exposure check")

    # ---- resource<->finding matching (override if needed) --------------
    def resource_matches(self, res: Dict[str, Any], finding: ProwlerFinding) -> bool:
        rid = str(res.get("id", ""))
        rname = str(res.get("name", ""))
        keys = {k for k in (rid, rname) if k}
        cand = {finding.resource_name, finding.resource_uid}
        # exact, or name is a suffix/substring of the resource uid path
        if keys & cand:
            return True
        for k in keys:
            for c in cand:
                if k and c and (k == c or k in c or c in k):
                    return True
        return False

    # ---- orchestration -------------------------------------------------
    _METHOD_FNS = (
        (Method.API, "api_check"),
        (Method.PROWLER_REPLICA, "prowler_replica_check"),
        (Method.LOGS, "logs_check"),
        (Method.ALTERNATE, "alternate_check"),
        (Method.EXPOSURE, "exposure_check"),
    )

    def _run_methods(self, ctx: ValidationContext, res: Dict[str, Any], rr: ResourceResult) -> None:
        for method, fn_name in self._METHOD_FNS:
            fn = getattr(self, fn_name)
            try:
                rr.add(fn(ctx, res))
            except Exception as exc:  # noqa: BLE001 - report, never crash the run
                rr.add(MethodResult.error(method, exc))

    def run(self, ctx: ValidationContext) -> CheckResult:
        result = CheckResult(
            check_id=self.check_id, service=self.service, severity=self.severity,
            title=self.title, hub_link=self.hub_link,
        )
        findings = list(ctx.prowler.for_check(self.check_id))
        matched: List[bool] = [False] * len(findings)

        try:
            resources = self.discover_resources(ctx)
        except Exception as exc:  # noqa: BLE001
            result.error = f"discovery failed: {type(exc).__name__}: {exc}"
            resources = []

        for res in resources:
            rr = ResourceResult(
                resource_id=str(res.get("id", res.get("name", ""))),
                resource_name=str(res.get("name", "")),
                project=str(res.get("project", ctx.project)),
                region=str(res.get("region", "")),
            )
            self._run_methods(ctx, res, rr)
            for i, f in enumerate(findings):
                if not matched[i] and self.resource_matches(res, f):
                    rr.prowler_status = f.status
                    rr.prowler_detail = f.status_detail
                    matched[i] = True
                    break
            result.add(rr)

        # Prowler flagged resources we could not enumerate live (deleted, other
        # project, permissions): surface them so nothing is silently dropped.
        for i, f in enumerate(findings):
            if matched[i]:
                continue
            rr = ResourceResult(
                resource_id=f.resource_uid or f.resource_name,
                resource_name=f.resource_name,
                project=f.project or ctx.project,
                region=f.region,
                prowler_status=f.status,
                prowler_detail=f.status_detail,
            )
            reason = "resource not found in live discovery (deleted, different project, or insufficient permissions)"
            for method, _ in self._METHOD_FNS:
                rr.add(MethodResult.na(method, reason))
            result.add(rr)

        return result
