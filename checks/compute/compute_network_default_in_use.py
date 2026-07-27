"""compute_network_default_in_use — the auto-created 'default' network should be removed.

Prowler Hub: https://hub.prowler.com/check/compute_network_default_in_use
"""
from checks.compute._base import ComputeNetworkCheck


class Check(ComputeNetworkCheck):
    check_id = "compute_network_default_in_use"

    def evaluate(self, ctx, res):
        name = res["network"].get("name", "")
        ok = name != "default"
        return ok, f"network name='{name}'", {"name": name}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
