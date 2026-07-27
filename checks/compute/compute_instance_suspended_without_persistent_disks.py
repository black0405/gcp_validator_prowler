"""compute_instance_suspended_without_persistent_disks — suspended VMs should keep persistent disks.

Prowler Hub: https://hub.prowler.com/check/compute_instance_suspended_without_persistent_disks
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_suspended_without_persistent_disks"

    def evaluate(self, ctx, res):
        inst = res["instance"]
        status = str(inst.get("status", "")).upper()
        disks = inst.get("disks", []) or []
        has_persistent = any(str(d.get("type", "")).upper() == "PERSISTENT" for d in disks)
        if status != "SUSPENDED":
            return True, f"status={status} (check applies to SUSPENDED instances)", {"status": status}
        return has_persistent, f"status=SUSPENDED, has persistent disk={has_persistent}", {"has_persistent": has_persistent}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
