"""compute_instance_on_host_maintenance_migrate — onHostMaintenance should be MIGRATE.

Prowler Hub: https://hub.prowler.com/check/compute_instance_on_host_maintenance_migrate
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_on_host_maintenance_migrate"

    def evaluate(self, ctx, res):
        val = str((res["instance"].get("scheduling") or {}).get("onHostMaintenance", ""))
        ok = val.upper() == "MIGRATE"
        return ok, f"scheduling.onHostMaintenance={val or 'unset'}", {"value": val}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
