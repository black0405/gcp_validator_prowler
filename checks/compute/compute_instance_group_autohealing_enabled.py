"""compute_instance_group_autohealing_enabled — MIGs should define an autohealing policy.

Prowler Hub: https://hub.prowler.com/check/compute_instance_group_autohealing_enabled
"""
from checks.compute._groups_base import ComputeMigCheck


class Check(ComputeMigCheck):
    check_id = "compute_instance_group_autohealing_enabled"

    def evaluate(self, ctx, res):
        policies = res["mig"].get("autoHealingPolicies", []) or []
        ok = bool(policies)
        return ok, f"autoHealingPolicies configured: {len(policies)}", {"count": len(policies)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
