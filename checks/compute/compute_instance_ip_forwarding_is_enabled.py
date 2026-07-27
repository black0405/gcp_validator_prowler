"""compute_instance_ip_forwarding_is_enabled — IP forwarding should be disabled.

Prowler Hub: https://hub.prowler.com/check/compute_instance_ip_forwarding_is_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_ip_forwarding_is_enabled"

    def evaluate(self, ctx, res):
        can = bool(res["instance"].get("canIpForward"))
        # Finding is raised when IP forwarding IS enabled -> compliant when disabled.
        return (not can), f"canIpForward={can}", {"can_ip_forward": can}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
