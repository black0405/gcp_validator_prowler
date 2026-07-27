"""cloudstorage_bucket_sufficient_retention_period — a retention period must be set.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_sufficient_retention_period
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_sufficient_retention_period"

    def evaluate(self, ctx, res):
        rp = res["bucket"].get("retentionPolicy") or {}
        raw = rp.get("retentionPeriod")
        try:
            secs = int(raw)
        except (TypeError, ValueError):
            secs = 0
        ok = secs > 0
        return ok, f"retentionPolicy.retentionPeriod={raw or 'unset'} ({secs}s)", {"seconds": secs}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
