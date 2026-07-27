"""iam_sa_user_managed_key_rotate_90_days — user-managed SA keys must be < 90 days old.

Prowler Hub: https://hub.prowler.com/check/iam_sa_user_managed_key_rotate_90_days
"""
from checks.iam._base import IamServiceAccountCheck
from gcpval.gcp_util import age_days


class Check(IamServiceAccountCheck):
    check_id = "iam_sa_user_managed_key_rotate_90_days"

    def evaluate(self, ctx, res):
        keys = [k for k in self.list_sa_keys(ctx, res["email"]) if k.get("keyType") == "USER_MANAGED"]
        if not keys:
            return True, f"{res['email']}: no user-managed keys to rotate", {"keys": 0}
        stale = []
        for k in keys:
            age = age_days(k.get("validAfterTime", ""))
            if age is None or age > 90:
                stale.append({"key": str(k.get("name", "")).split("/")[-1], "age_days": age})
        ok = not stale
        return ok, f"{res['email']}: {len(keys)} user-managed key(s), stale(>90d)={len(stale)}", {"stale": stale}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
