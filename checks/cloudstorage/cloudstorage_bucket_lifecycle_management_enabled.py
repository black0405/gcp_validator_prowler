"""cloudstorage_bucket_lifecycle_management_enabled — a lifecycle rule must exist.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_lifecycle_management_enabled
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_lifecycle_management_enabled"

    def evaluate(self, ctx, res):
        rules = (res["bucket"].get("lifecycle") or {}).get("rule", []) or []
        return bool(rules), f"lifecycle rules configured: {len(rules)}", {"rule_count": len(rules)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
