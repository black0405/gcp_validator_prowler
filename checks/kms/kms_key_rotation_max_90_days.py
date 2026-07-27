"""kms_key_rotation_max_90_days — rotation period must be <= 90 days.

Prowler Hub: https://hub.prowler.com/check/kms_key_rotation_max_90_days
"""
from checks.kms._base import KmsCheck
from gcpval.models import Method, MethodResult
from gcpval.gcp_util import duration_seconds

_MAX = 90 * 86400


class Check(KmsCheck):
    check_id = "kms_key_rotation_max_90_days"

    def evaluate(self, ctx, res):
        key = res["key"]
        rp = key.get("rotationPeriod", "")
        secs = duration_seconds(rp)
        ok = secs is not None and secs <= _MAX
        return ok, f"rotationPeriod={rp or 'not set'} ({'<=90d' if ok else '>90d or unset'})", {"seconds": secs}

    def api_check(self, ctx, res) -> MethodResult:
        if res["key"].get("purpose") != "ENCRYPT_DECRYPT":
            return MethodResult.na(Method.API, f"purpose={res['key'].get('purpose')}, rotation N/A")
        return super().api_check(ctx, res)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        if res["key"].get("purpose") != "ENCRYPT_DECRYPT":
            return MethodResult.na(Method.PROWLER_REPLICA, "rotation only applies to ENCRYPT_DECRYPT keys")
        return super().prowler_replica_check(ctx, res)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
