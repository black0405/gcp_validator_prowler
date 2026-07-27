"""compute_instance_automatic_restart_enabled — automatic restart must be enabled.

Prowler Hub: https://hub.prowler.com/check/compute_instance_automatic_restart_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_automatic_restart_enabled"

    def evaluate(self, ctx, res):
        sched = res["instance"].get("scheduling") or {}
        enabled = bool(sched.get("automaticRestart"))
        return enabled, f"scheduling.automaticRestart={enabled}", {"enabled": enabled}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
