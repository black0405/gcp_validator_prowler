"""compute_network_not_legacy — legacy (non-subnet) networks must not be used.

Prowler Hub: https://hub.prowler.com/check/compute_network_not_legacy
"""
from checks.compute._base import ComputeNetworkCheck


class Check(ComputeNetworkCheck):
    check_id = "compute_network_not_legacy"

    def evaluate(self, ctx, res):
        legacy = bool(res["network"].get("IPv4Range"))
        return (not legacy), f"legacy IPv4Range present={legacy}", {"legacy": legacy}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
