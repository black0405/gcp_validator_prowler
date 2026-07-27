"""iam_sa_no_administrative_privileges — service accounts must not hold admin/primitive roles.

Prowler Hub: https://hub.prowler.com/check/iam_sa_no_administrative_privileges
"""
from checks.iam._base import IamServiceAccountCheck

_PRIMITIVE = {"roles/owner", "roles/editor"}


def _is_admin_role(role: str) -> bool:
    r = role.lower()
    return role in _PRIMITIVE or r.endswith("admin") or ".admin" in r


class Check(IamServiceAccountCheck):
    check_id = "iam_sa_no_administrative_privileges"

    def evaluate(self, ctx, res):
        policy = self.project_iam(ctx)
        member = f"serviceAccount:{res['email']}"
        roles = self.member_roles(policy).get(member, set())
        admin_roles = sorted(r for r in roles if _is_admin_role(r))
        ok = not admin_roles
        return ok, (f"{res['email']} project roles={sorted(roles) or 'none'}; "
                    f"admin/primitive: {admin_roles or 'none'}"), {"admin_roles": admin_roles}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
