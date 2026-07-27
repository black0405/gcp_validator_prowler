"""compute_instance_group_multiple_zones — MIGs should be regional (span >1 zone).

Prowler Hub: https://hub.prowler.com/check/compute_instance_group_multiple_zones
"""
from checks.compute._groups_base import ComputeMigCheck


class Check(ComputeMigCheck):
    check_id = "compute_instance_group_multiple_zones"

    def evaluate(self, ctx, res):
        mig = res["mig"]
        zones = (mig.get("distributionPolicy") or {}).get("zones", []) or []
        regional = bool(mig.get("region"))
        ok = regional and len(zones) > 1
        return ok, (f"{'regional' if regional else 'zonal'} MIG, distributionPolicy zones={len(zones)}"), \
            {"regional": regional, "zone_count": len(zones)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
