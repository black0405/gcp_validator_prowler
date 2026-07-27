"""compute_instance_preemptible_vm_disabled — instances should not be preemptible.

Prowler Hub: https://hub.prowler.com/check/compute_instance_preemptible_vm_disabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_preemptible_vm_disabled"

    def evaluate(self, ctx, res):
        preempt = bool((res["instance"].get("scheduling") or {}).get("preemptible"))
        return (not preempt), f"scheduling.preemptible={preempt}", {"preemptible": preempt}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
