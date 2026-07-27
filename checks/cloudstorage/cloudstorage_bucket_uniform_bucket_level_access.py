"""cloudstorage_bucket_uniform_bucket_level_access — UBLA must be enabled.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_uniform_bucket_level_access
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_uniform_bucket_level_access"

    def evaluate(self, ctx, res):
        ubla = ((res["bucket"].get("iamConfiguration") or {})
                .get("uniformBucketLevelAccess") or {})
        enabled = bool(ubla.get("enabled"))
        return enabled, f"iamConfiguration.uniformBucketLevelAccess.enabled={enabled}", {"ubla": enabled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
