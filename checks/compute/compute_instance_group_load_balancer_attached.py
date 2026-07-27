"""compute_instance_group_load_balancer_attached — MIGs should sit behind a load balancer.

Prowler Hub: https://hub.prowler.com/check/compute_instance_group_load_balancer_attached
"""
from checks.compute._groups_base import ComputeMigCheck
from checks.compute._base import aggregated
from gcpval.models import Method, MethodResult


class Check(ComputeMigCheck):
    check_id = "compute_instance_group_load_balancer_attached"

    def evaluate(self, ctx, res):
        mig = res["mig"]
        target_pools = mig.get("targetPools", []) or []
        ok = bool(target_pools)
        return ok, f"targetPools attached: {len(target_pools)}", {"target_pools": len(target_pools)}

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate: scan backend services for this group's instance group URL."""
        group_url = res["mig"].get("instanceGroup", "")
        if not group_url:
            return MethodResult.na(Method.ALTERNATE, "MIG has no instanceGroup URL yet")
        attached = []
        for bs in aggregated(ctx.clients.compute().backendServices(), ctx.project, "backendServices"):
            for b in bs.get("backends", []) or []:
                if b.get("group", "") == group_url:
                    attached.append(bs.get("name"))
        ok = bool(res["mig"].get("targetPools")) or bool(attached)
        return MethodResult.ok(Method.ALTERNATE, ok,
                               "backend services referencing this group: " + (str(attached) if attached else "none"),
                               backend_services=attached)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
