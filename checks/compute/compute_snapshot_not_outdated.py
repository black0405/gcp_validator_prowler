"""compute_snapshot_not_outdated — disk snapshots should be recent (<= 30 days).

Prowler Hub: https://hub.prowler.com/check/compute_snapshot_not_outdated
"""
from typing import Any, Dict, List

from checks.compute._base import ComputeCheck
from gcpval.context import ValidationContext
from gcpval.gcp_util import age_days

_MAX_AGE_DAYS = 30


class Check(ComputeCheck):
    check_id = "compute_snapshot_not_outdated"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        req = ctx.clients.compute().snapshots().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            for s in resp.get("items", []) or []:
                out.append({"id": s.get("id") or s.get("name"), "name": s.get("name"),
                            "region": "global", "project": ctx.project, "snapshot": s})
            req = ctx.clients.compute().snapshots().list_next(req, resp)
        return out

    def evaluate(self, ctx, res):
        created = res["snapshot"].get("creationTimestamp", "")
        age = age_days(created)
        ok = age is not None and age <= _MAX_AGE_DAYS
        detail = (f"creationTimestamp={created} (age={age:.0f}d, max={_MAX_AGE_DAYS}d)"
                  if age is not None else f"unparseable creationTimestamp: {created}")
        return ok, detail, {"age_days": age}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
