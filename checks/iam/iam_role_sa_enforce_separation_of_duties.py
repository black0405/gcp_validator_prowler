"""iam_role_sa_enforce_separation_of_duties — no principal is both SA admin and SA user.

Prowler Hub: https://hub.prowler.com/check/iam_role_sa_enforce_separation_of_duties
"""
from checks.iam._base import IamProjectCheck

_ADMIN = {"roles/iam.serviceAccountAdmin"}
_USAGE = {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}


class Check(IamProjectCheck):
    check_id = "iam_role_sa_enforce_separation_of_duties"

    def evaluate(self, ctx, res):
        roles_by_member = self.member_roles(res["policy"])
        violators = [m for m, roles in roles_by_member.items()
                     if (roles & _ADMIN) and (roles & _USAGE)]
        ok = not violators
        return ok, ("principals holding both an SA admin and an SA usage role: "
                    + (str(violators) if violators else "none")), {"violators": violators}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
