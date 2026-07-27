"""compute_loadbalancer_logging_enabled — backend services must have logging enabled.

Prowler Hub: https://hub.prowler.com/check/compute_loadbalancer_logging_enabled
"""
from typing import Any, Dict, List

from checks.compute._base import ComputeCheck, aggregated
from gcpval.context import ValidationContext


class Check(ComputeCheck):
    check_id = "compute_loadbalancer_logging_enabled"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for bs in aggregated(ctx.clients.compute().backendServices(), ctx.project, "backendServices"):
            loc = str(bs.get("region", "global")).split("/")[-1] or "global"
            out.append({"id": bs.get("id") or bs.get("name"), "name": bs.get("name"),
                        "region": loc, "project": ctx.project, "backend": bs})
        return out

    def evaluate(self, ctx, res):
        log_cfg = res["backend"].get("logConfig") or {}
        enabled = bool(log_cfg.get("enable"))
        return enabled, f"logConfig.enable={enabled}", {"log_config": log_cfg}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
