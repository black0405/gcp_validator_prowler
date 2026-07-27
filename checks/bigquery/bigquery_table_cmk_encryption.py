"""bigquery_table_cmk_encryption — table should be encrypted with a customer-managed key.

Prowler Hub: https://hub.prowler.com/check/bigquery_table_cmk_encryption
"""
from checks.bigquery._base import BigQueryTableCheck


class Check(BigQueryTableCheck):
    check_id = "bigquery_table_cmk_encryption"

    def evaluate(self, ctx, res):
        key = (res["table"].get("encryptionConfiguration") or {}).get("kmsKeyName", "")
        return bool(key), f"encryptionConfiguration.kmsKeyName={key or 'not set (Google-managed)'}", {"kms_key": key}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
