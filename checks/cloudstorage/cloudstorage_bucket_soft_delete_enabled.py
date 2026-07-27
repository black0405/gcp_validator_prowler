"""cloudstorage_bucket_soft_delete_enabled — soft delete retention must be > 0.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_soft_delete_enabled
"""
from checks.cloudstorage._base import CloudStorageCheck
from gcpval.gcp_util import duration_seconds


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_soft_delete_enabled"

    def evaluate(self, ctx, res):
        policy = res["bucket"].get("softDeletePolicy") or {}
        raw = str(policy.get("retentionDurationSeconds", "") or "")
        secs = duration_seconds(raw) if raw else None
        enabled = bool(secs and secs > 0)
        return enabled, f"softDeletePolicy.retentionDurationSeconds={raw or 'unset'}", {"seconds": secs}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
