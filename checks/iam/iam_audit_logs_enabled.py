"""iam_audit_logs_enabled — default project audit logging must capture Data Access.

Prowler Hub: https://hub.prowler.com/check/iam_audit_logs_enabled
"""
from checks.iam._base import IamProjectCheck

_REQUIRED = {"DATA_READ", "DATA_WRITE"}


class Check(IamProjectCheck):
    check_id = "iam_audit_logs_enabled"

    def evaluate(self, ctx, res):
        enabled = set()
        for ac in res["policy"].get("auditConfigs", []) or []:
            if ac.get("service") == "allServices":
                for cfg in ac.get("auditLogConfigs", []) or []:
                    if not cfg.get("exemptedMembers"):
                        enabled.add(cfg.get("logType"))
        ok = _REQUIRED.issubset(enabled)
        return ok, (f"allServices auditConfig enables {sorted(enabled) or 'none'}; "
                    f"require {sorted(_REQUIRED)}"), {"enabled": sorted(enabled)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
