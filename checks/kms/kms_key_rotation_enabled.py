"""kms_key_rotation_enabled — symmetric keys must have automatic rotation set.

Prowler Hub: https://hub.prowler.com/check/kms_key_rotation_enabled
"""
from checks.kms._base import KmsCheck
from gcpval.models import Method, MethodResult


def _is_symmetric(key) -> bool:
    return key.get("purpose") == "ENCRYPT_DECRYPT"


class Check(KmsCheck):
    check_id = "kms_key_rotation_enabled"

    def evaluate(self, ctx, res):
        key = res["key"]
        if not _is_symmetric(key):
            # handled via N/A in api/prowler overrides
            return True, "not a symmetric ENCRYPT_DECRYPT key", {}
        rp = key.get("rotationPeriod", "")
        return bool(rp), f"rotationPeriod={rp or 'not set'}", {"rotation_period": rp}

    def _na_if_asym(self, method, key):
        if not _is_symmetric(key):
            return MethodResult.na(method, f"purpose={key.get('purpose')}, rotation only applies to ENCRYPT_DECRYPT")
        return None

    def api_check(self, ctx, res) -> MethodResult:
        na = self._na_if_asym(Method.API, res["key"])
        return na or super().api_check(ctx, res)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        na = self._na_if_asym(Method.PROWLER_REPLICA, res["key"])
        return na or super().prowler_replica_check(ctx, res)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
