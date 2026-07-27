"""cloudsql_instance_high_availability_enabled — instance should be REGIONAL (HA).

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_high_availability_enabled
"""
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult


def _availability(inst) -> str:
    return str((inst.get("settings", {}) or {}).get("availabilityType", "")).upper()


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_high_availability_enabled"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        avail = _availability(inst)
        return MethodResult.ok(
            Method.API, avail == "REGIONAL",
            f"instances.get(): settings.availabilityType={avail or 'ZONAL'}",
            availability_type=avail)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        avail = _availability(res["instance"])
        return MethodResult.ok(
            Method.PROWLER_REPLICA, avail == "REGIONAL",
            f"Prowler rule ({self.hub_link}): PASS when availabilityType == REGIONAL -> "
            + (avail or "ZONAL"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: a REGIONAL (HA) instance has a secondary zone
        assigned; ZONAL instances do not."""
        inst = res["instance"]
        secondary = inst.get("secondaryGceZone", "")
        return MethodResult.ok(
            Method.ALTERNATE, bool(secondary),
            f"secondaryGceZone={secondary or 'none'} (present implies HA failover replica)",
            secondary_zone=secondary)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
