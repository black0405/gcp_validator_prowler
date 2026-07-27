"""cloudstorage_bucket_log_retention_policy_lock — retention policy must be locked.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_log_retention_policy_lock
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_log_retention_policy_lock"

    def evaluate(self, ctx, res):
        rp = res["bucket"].get("retentionPolicy") or {}
        locked = bool(rp.get("isLocked"))
        return locked, f"retentionPolicy.isLocked={locked} (period={rp.get('retentionPeriod','unset')})", {"retention_policy": rp}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
