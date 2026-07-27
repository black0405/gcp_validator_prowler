"""cloudstorage_audit_logs_enabled — Data Access audit logs for GCS must be on.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_audit_logs_enabled
"""
from checks.cloudstorage._base import ProjectScopedCheck

_TARGET_SERVICES = {"allServices", "storage.googleapis.com"}
_REQUIRED = {"DATA_READ", "DATA_WRITE"}


class Check(ProjectScopedCheck):
    check_id = "cloudstorage_audit_logs_enabled"
    service = "cloudstorage"

    def evaluate(self, ctx, res):
        policy = self.project_iam(ctx)
        enabled_types = set()
        for ac in policy.get("auditConfigs", []) or []:
            if ac.get("service") in _TARGET_SERVICES:
                for cfg in ac.get("auditLogConfigs", []) or []:
                    if not cfg.get("exemptedMembers"):
                        enabled_types.add(cfg.get("logType"))
        ok = _REQUIRED.issubset(enabled_types)
        return ok, (f"project auditConfigs for GCS enable {sorted(enabled_types) or 'none'}; "
                    f"require {sorted(_REQUIRED)}"), {"enabled": sorted(enabled_types)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
