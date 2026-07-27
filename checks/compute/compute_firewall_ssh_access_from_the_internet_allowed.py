"""compute_firewall_ssh_access_from_the_internet_allowed — no 0.0.0.0/0 -> tcp/22.

Prowler Hub: https://hub.prowler.com/check/compute_firewall_ssh_access_from_the_internet_allowed
"""
from checks.compute._base import ComputeFirewallCheck, firewall_allows_port


class Check(ComputeFirewallCheck):
    check_id = "compute_firewall_ssh_access_from_the_internet_allowed"
    PORT = 22

    def evaluate(self, ctx, res):
        allows = firewall_allows_port(res["firewall"], self.PORT)
        return (not allows,
                f"INGRESS from 0.0.0.0/0 to tcp/{self.PORT}: {'ALLOWED' if allows else 'not allowed'}",
                {"open": allows})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
