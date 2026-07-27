"""Shared base for Secret Manager checks (secret discovery + IAM helper)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class SecretCheck(ResourceCheck):
    service = "secretmanager"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        sm = ctx.clients.secretmanager()
        out: List[Dict[str, Any]] = []
        req = sm.projects().secrets().list(parent=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            for s in resp.get("secrets", []) or []:
                out.append({
                    "id": s.get("name"), "name": str(s.get("name", "")).split("/")[-1],
                    "full_name": s.get("name"), "region": "", "project": ctx.project,
                    "secret": s,
                })
            req = sm.projects().secrets().list_next(req, resp)
        return out

    @staticmethod
    def secret_iam(ctx: ValidationContext, full_name: str) -> Dict[str, Any]:
        return ctx.clients.secretmanager().projects().secrets().getIamPolicy(
            resource=full_name).execute()
