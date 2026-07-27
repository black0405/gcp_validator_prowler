"""bigquery_dataset_cmk_encryption — dataset should use a customer-managed key by default.

Prowler Hub: https://hub.prowler.com/check/bigquery_dataset_cmk_encryption
"""
from checks.bigquery._base import BigQueryDatasetCheck


class Check(BigQueryDatasetCheck):
    check_id = "bigquery_dataset_cmk_encryption"

    def evaluate(self, ctx, res):
        key = (res["dataset"].get("defaultEncryptionConfiguration") or {}).get("kmsKeyName", "")
        return bool(key), f"defaultEncryptionConfiguration.kmsKeyName={key or 'not set (Google-managed)'}", {"kms_key": key}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
