"""iam_account_access_approval_enabled — Access Approval must be enrolled.

Prowler Hub: https://hub.prowler.com/check/iam_account_access_approval_enabled
"""
from typing import Any, Dict, List

from checks.iam._base import IamCheck
from gcpval.context import ValidationContext


class Check(IamCheck):
    check_id = "iam_account_access_approval_enabled"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        aa = ctx.clients.discovery("accessapproval", "v1")
        settings = aa.projects().getAccessApprovalSettings(
            name=f"projects/{ctx.project}/accessApprovalSettings").execute()
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project, "settings": settings}]

    def evaluate(self, ctx, res):
        enrolled = res["settings"].get("enrolledServices", []) or []
        ok = bool(enrolled)
        return ok, f"accessApprovalSettings.enrolledServices={len(enrolled)}", {"enrolled": enrolled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
