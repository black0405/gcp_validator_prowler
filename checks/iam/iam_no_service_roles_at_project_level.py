"""iam_no_service_roles_at_project_level — no service-account-usage roles at project level.

Prowler Hub: https://hub.prowler.com/check/iam_no_service_roles_at_project_level
"""
from checks.iam._base import IamProjectCheck

_ROLES = {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}


class Check(IamProjectCheck):
    check_id = "iam_no_service_roles_at_project_level"

    def evaluate(self, ctx, res):
        offending = [b.get("role") for b in res["policy"].get("bindings", []) or []
                     if b.get("role") in _ROLES]
        ok = not offending
        return ok, ("project-level bindings of "
                    + str(sorted(_ROLES)) + ": " + (str(offending) if offending else "none")), {"offending": offending}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
