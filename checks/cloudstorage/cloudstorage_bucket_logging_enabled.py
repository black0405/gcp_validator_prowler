"""cloudstorage_bucket_logging_enabled — access/usage logging must be configured.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_logging_enabled
"""
from checks.cloudstorage._base import CloudStorageCheck


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_logging_enabled"

    def evaluate(self, ctx, res):
        logging = res["bucket"].get("logging") or {}
        target = logging.get("logBucket", "")
        return bool(target), f"logging.logBucket={target or 'not set'}", {"log_bucket": target}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
