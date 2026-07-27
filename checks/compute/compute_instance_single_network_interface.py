"""compute_instance_single_network_interface — instances should have one NIC.

Prowler Hub: https://hub.prowler.com/check/compute_instance_single_network_interface
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_single_network_interface"

    def evaluate(self, ctx, res):
        nics = res["instance"].get("networkInterfaces", []) or []
        ok = len(nics) <= 1
        return ok, f"networkInterfaces count={len(nics)}", {"nic_count": len(nics)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
