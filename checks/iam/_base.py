"""Shared bases + helpers for IAM checks."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class IamCheck(ResourceCheck):
    service = "iam"
    audit_log_corroboration = False

    def project_iam(self, ctx: ValidationContext) -> Dict[str, Any]:
        crm = ctx.clients.cloudresourcemanager("v3")
        return crm.projects().getIamPolicy(
            resource=f"projects/{ctx.project}",
            body={"options": {"requestedPolicyVersion": 3}},
        ).execute()

    def list_service_accounts(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        iam = ctx.clients.iam()
        out: List[Dict[str, Any]] = []
        req = iam.projects().serviceAccounts().list(name=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            out.extend(resp.get("accounts", []) or [])
            req = iam.projects().serviceAccounts().list_next(req, resp)
        return out

    def list_sa_keys(self, ctx: ValidationContext, sa_email: str) -> List[Dict[str, Any]]:
        iam = ctx.clients.iam()
        resp = iam.projects().serviceAccounts().keys().list(
            name=f"projects/{ctx.project}/serviceAccounts/{sa_email}").execute()
        return resp.get("keys", []) or []

    @staticmethod
    def member_roles(policy: Dict[str, Any]) -> Dict[str, set]:
        """member -> set(roles)."""
        out: Dict[str, set] = {}
        for b in policy.get("bindings", []) or []:
            role = b.get("role", "")
            for m in b.get("members", []) or []:
                out.setdefault(m, set()).add(role)
        return out


class IamProjectCheck(IamCheck):
    """Evaluated once against the project IAM policy."""
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project,
                 "policy": self.project_iam(ctx)}]


class IamServiceAccountCheck(IamCheck):
    """One row per service account."""
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for sa in self.list_service_accounts(ctx):
            out.append({
                "id": sa.get("uniqueId") or sa.get("email"),
                "name": sa.get("email"), "email": sa.get("email"),
                "project": ctx.project, "sa": sa,
            })
        return out
