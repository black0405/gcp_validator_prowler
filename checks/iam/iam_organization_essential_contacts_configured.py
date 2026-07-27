"""iam_organization_essential_contacts_configured — Essential Contacts must be set.

Prowler Hub: https://hub.prowler.com/check/iam_organization_essential_contacts_configured

Prowler evaluates this at the *organization* level. With project-scoped
credentials we check project-level Essential Contacts as a best-effort proxy and
note that org-level review is authoritative.
"""
from typing import Any, Dict, List

from checks.iam._base import IamCheck
from gcpval.context import ValidationContext


class Check(IamCheck):
    check_id = "iam_organization_essential_contacts_configured"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        ec = ctx.clients.discovery("essentialcontacts", "v1")
        contacts: List[dict] = []
        req = ec.projects().contacts().list(parent=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            contacts.extend(resp.get("contacts", []) or [])
            req = ec.projects().contacts().list_next(req, resp)
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project, "contacts": contacts}]

    def evaluate(self, ctx, res):
        contacts = res["contacts"]
        ok = bool(contacts)
        return ok, (f"project-level Essential Contacts: {len(contacts)} "
                    f"(org-level configuration is authoritative for this control)"), {"count": len(contacts)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
