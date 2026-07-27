"""Shared base for Cloud Storage checks (bucket discovery + IAM helper)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class CloudStorageCheck(ResourceCheck):
    service = "cloudstorage"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        svc = ctx.clients.storage()
        out: List[Dict[str, Any]] = []
        req = svc.buckets().list(project=ctx.project, projection="full")
        while req is not None:
            resp = req.execute()
            for b in resp.get("items", []) or []:
                out.append({
                    "id": b.get("id") or b.get("name"),
                    "name": b.get("name"),
                    "region": b.get("location", ""),
                    "project": ctx.project,
                    "bucket": b,
                })
            req = svc.buckets().list_next(req, resp)
        return out

    @staticmethod
    def bucket_iam(ctx: ValidationContext, name: str) -> Dict[str, Any]:
        return ctx.clients.storage().buckets().getIamPolicy(bucket=name).execute()


class ProjectScopedCheck(ResourceCheck):
    """For controls evaluated once at the project level rather than per resource."""
    service = ""
    audit_log_corroboration = False

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project}]

    @staticmethod
    def project_iam(ctx: ValidationContext) -> Dict[str, Any]:
        crm = ctx.clients.cloudresourcemanager("v3")
        return crm.projects().getIamPolicy(
            resource=f"projects/{ctx.project}",
            body={"options": {"requestedPolicyVersion": 3}},
        ).execute()
