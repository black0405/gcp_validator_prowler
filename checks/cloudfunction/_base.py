"""Shared base for Cloud Functions (v2) checks."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class CloudFunctionCheck(ResourceCheck):
    service = "cloudfunction"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        cf = ctx.clients.cloudfunctions()
        out: List[Dict[str, Any]] = []
        req = cf.projects().locations().functions().list(
            parent=f"projects/{ctx.project}/locations/-")
        while req is not None:
            resp = req.execute()
            for f in resp.get("functions", []) or []:
                name = f.get("name", "")
                out.append({
                    "id": name, "name": name.split("/")[-1], "full_name": name,
                    "region": name.split("/locations/")[-1].split("/")[0] if "/locations/" in name else "",
                    "project": ctx.project, "function": f,
                })
            req = cf.projects().locations().functions().list_next(req, resp)
        return out

    @staticmethod
    def function_iam(ctx: ValidationContext, full_name: str) -> Dict[str, Any]:
        return ctx.clients.cloudfunctions().projects().locations().functions().getIamPolicy(
            resource=full_name).execute()
