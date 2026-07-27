"""cloudsql_instance_cmek_encryption_enabled — instance should use a customer-managed key.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_cmek_encryption_enabled
"""
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_cmek_encryption_enabled"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        key = (inst.get("diskEncryptionConfiguration", {}) or {}).get("kmsKeyName", "")
        return MethodResult.ok(
            Method.API, bool(key),
            f"instances.get(): diskEncryptionConfiguration.kmsKeyName={key or 'not set (Google-managed)'}",
            kms_key=key)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        key = (res["instance"].get("diskEncryptionConfiguration", {}) or {}).get("kmsKeyName", "")
        return MethodResult.ok(
            Method.PROWLER_REPLICA, bool(key),
            f"Prowler rule ({self.hub_link}): PASS when a CMEK (kmsKeyName) is configured -> "
            + (key or "none"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: diskEncryptionStatus reports the key version
        actually in effect (runtime status vs configured intent)."""
        inst = res["instance"]
        status_key = (inst.get("diskEncryptionStatus", {}) or {}).get("kmsKeyVersionName", "")
        return MethodResult.ok(
            Method.ALTERNATE, bool(status_key),
            f"diskEncryptionStatus.kmsKeyVersionName={status_key or 'none'}",
            kms_key_version=status_key)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
