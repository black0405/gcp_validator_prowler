"""apikeys_key_rotated_in_90_days — API keys should be recreated at least every 90 days.

Prowler Hub: https://hub.prowler.com/check/apikeys_key_rotated_in_90_days
"""
from checks.apikeys._base import ApiKeysCheck
from gcpval.gcp_util import age_days


class Check(ApiKeysCheck):
    check_id = "apikeys_key_rotated_in_90_days"

    def evaluate(self, ctx, res):
        created = res["key"].get("createTime", "")
        age = age_days(created)
        ok = age is not None and age <= 90
        return ok, f"createTime={created or 'unknown'} (age={age:.0f}d)" if age is not None \
            else f"createTime unparseable: {created}", {"age_days": age}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
