"""compute_image_not_publicly_shared — custom images must not be shared publicly.

Prowler Hub: https://hub.prowler.com/check/compute_image_not_publicly_shared
"""
from typing import Any, Dict, List

from checks.compute._base import ComputeCheck
from gcpval.context import ValidationContext
from gcpval.models import Method, MethodResult
from gcpval.gcp_util import public_bindings


class Check(ComputeCheck):
    check_id = "compute_image_not_publicly_shared"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        req = ctx.clients.compute().images().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            for img in resp.get("items", []) or []:
                out.append({"id": img.get("id") or img.get("name"), "name": img.get("name"),
                            "region": "global", "project": ctx.project, "image": img})
            req = ctx.clients.compute().images().list_next(req, resp)
        return out

    def _iam(self, ctx, res):
        return ctx.clients.compute().images().getIamPolicy(
            project=ctx.project, resource=res["name"]).execute()

    def api_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self._iam(ctx, res))
        return MethodResult.ok(Method.API, not pub,
                               "getIamPolicy(): public bindings=" + (str(pub) if pub else "none"),
                               public_bindings=pub)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self._iam(ctx, res))
        return MethodResult.ok(Method.PROWLER_REPLICA, not pub,
                               f"Prowler rule ({self.hub_link}): FAIL when the image IAM policy "
                               f"binds allUsers/allAuthenticatedUsers -> " + ("found" if pub else "none"))


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
