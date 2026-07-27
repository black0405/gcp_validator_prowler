"""compute_instance_deletion_protection_enabled — deletion protection must be on.

Prowler Hub: https://hub.prowler.com/check/compute_instance_deletion_protection_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_deletion_protection_enabled"

    def evaluate(self, ctx, res):
        enabled = bool(res["instance"].get("deletionProtection"))
        return enabled, f"deletionProtection={enabled}", {"enabled": enabled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
