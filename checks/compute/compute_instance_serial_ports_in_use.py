"""compute_instance_serial_ports_in_use — serial-port access should be disabled.

Prowler Hub: https://hub.prowler.com/check/compute_instance_serial_ports_in_use
"""
from checks.compute._base import ComputeInstanceCheck, metadata_items


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_serial_ports_in_use"

    def evaluate(self, ctx, res):
        val = metadata_items(res["instance"].get("metadata", {})).get("serial-port-enable", "")
        enabled = str(val).lower() in ("true", "1")
        # Finding raised when serial ports ARE in use -> compliant when disabled.
        return (not enabled), f"metadata serial-port-enable={val or 'not set'}", {"value": val}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
