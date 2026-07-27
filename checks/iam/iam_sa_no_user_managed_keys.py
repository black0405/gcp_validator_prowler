"""iam_sa_no_user_managed_keys — service accounts must not have user-managed keys.

Prowler Hub: https://hub.prowler.com/check/iam_sa_no_user_managed_keys
"""
from checks.iam._base import IamServiceAccountCheck


class Check(IamServiceAccountCheck):
    check_id = "iam_sa_no_user_managed_keys"

    def evaluate(self, ctx, res):
        keys = self.list_sa_keys(ctx, res["email"])
        user_managed = [k for k in keys if k.get("keyType") == "USER_MANAGED"]
        ok = not user_managed
        return ok, f"{res['email']}: {len(user_managed)} user-managed key(s)", {"user_managed": len(user_managed)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
