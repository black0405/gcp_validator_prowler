"""compute_instance_confidential_computing_enabled — Confidential Computing must be on.

Prowler Hub: https://hub.prowler.com/check/compute_instance_confidential_computing_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_confidential_computing_enabled"

    def evaluate(self, ctx, res):
        enabled = bool((res["instance"].get("confidentialInstanceConfig") or {}).get("enableConfidentialCompute"))
        return enabled, f"confidentialInstanceConfig.enableConfidentialCompute={enabled}", {"enabled": enabled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
