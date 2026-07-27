"""cloudstorage_bucket_versioning_enabled — object versioning must be enabled.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_versioning_enabled
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_versioning_enabled"

    def evaluate(self, ctx, res):
        enabled = bool((res["bucket"].get("versioning") or {}).get("enabled"))
        return enabled, f"versioning.enabled={enabled}", {"versioning": enabled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
