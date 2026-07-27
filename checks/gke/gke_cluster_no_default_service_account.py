"""gke_cluster_no_default_service_account — node pools must not use the default compute SA.

Prowler Hub: https://hub.prowler.com/check/gke_cluster_no_default_service_account
"""
from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class Check(ResourceCheck):
    check_id = "gke_cluster_no_default_service_account"
    service = "gke"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        gke = ctx.clients.container()
        resp = gke.projects().locations().clusters().list(
            parent=f"projects/{ctx.project}/locations/-").execute()
        out: List[Dict[str, Any]] = []
        for c in resp.get("clusters", []) or []:
            out.append({
                "id": c.get("id") or c.get("name"), "name": c.get("name"),
                "region": c.get("location", ""), "project": ctx.project, "cluster": c,
            })
        return out

    def evaluate(self, ctx, res):
        cluster = res["cluster"]
        offending = []
        pools = cluster.get("nodePools") or []
        # Also consider the cluster-level default nodeConfig.
        configs = [("<cluster-default>", (cluster.get("nodeConfig") or {}))] if cluster.get("nodeConfig") else []
        configs += [(p.get("name", "?"), (p.get("config") or {})) for p in pools]
        for pool_name, cfg in configs:
            sa = cfg.get("serviceAccount", "default")
            if sa == "default" or sa == "":
                offending.append(pool_name)
        ok = not offending
        return ok, (f"node pools using the default service account: "
                    + (str(offending) if offending else "none")), {"offending_pools": offending}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
