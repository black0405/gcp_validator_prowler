"""Discovery base for managed instance groups (aggregated)."""
from __future__ import annotations

from typing import Any, Dict, List

from checks.compute._base import ComputeCheck, aggregated
from gcpval.context import ValidationContext


class ComputeMigCheck(ComputeCheck):
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in aggregated(ctx.clients.compute().instanceGroupManagers(),
                            ctx.project, "instanceGroupManagers"):
            loc = str(m.get("region") or m.get("zone", "")).split("/")[-1]
            out.append({"id": m.get("id") or m.get("name"), "name": m.get("name"),
                        "region": loc, "project": ctx.project, "mig": m})
        return out
