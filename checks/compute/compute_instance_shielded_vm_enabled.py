"""compute_instance_shielded_vm_enabled — vTPM and integrity monitoring must be on.

Prowler Hub: https://hub.prowler.com/check/compute_instance_shielded_vm_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_shielded_vm_enabled"

    def evaluate(self, ctx, res):
        cfg = res["instance"].get("shieldedInstanceConfig") or {}
        vtpm = bool(cfg.get("enableVtpm"))
        integrity = bool(cfg.get("enableIntegrityMonitoring"))
        ok = vtpm and integrity
        return ok, f"enableVtpm={vtpm}, enableIntegrityMonitoring={integrity}", {"config": cfg}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
