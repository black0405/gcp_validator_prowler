"""compute_instance_disk_auto_delete_disabled — attached disks must not auto-delete.

Prowler Hub: https://hub.prowler.com/check/compute_instance_disk_auto_delete_disabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_disk_auto_delete_disabled"

    def evaluate(self, ctx, res):
        auto = [d.get("deviceName") or d.get("source", "") for d in res["instance"].get("disks", []) or []
                if d.get("autoDelete")]
        return (not auto, "disks with autoDelete=true: " + (str(auto) if auto else "none"), {"auto_delete": auto})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
