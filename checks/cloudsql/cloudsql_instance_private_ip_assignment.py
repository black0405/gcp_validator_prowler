"""cloudsql_instance_private_ip_assignment — instance should have a private IP configured.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_private_ip_assignment
"""
from checks.cloudsql import _base
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_private_ip_assignment"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        net = _base.ip_config(inst).get("privateNetwork", "")
        return MethodResult.ok(
            Method.API, bool(net),
            f"instances.get(): ipConfiguration.privateNetwork={net or 'not set'}",
            private_network=net)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        inst = res["instance"]
        net = _base.ip_config(inst).get("privateNetwork", "")
        return MethodResult.ok(
            Method.PROWLER_REPLICA, bool(net),
            f"Prowler rule ({self.hub_link}): PASS when a private network is assigned -> "
            + (net or "not set"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: look for an actually-assigned PRIVATE address."""
        inst = res["instance"]
        privates = [e.get("ipAddress", "") for e in inst.get("ipAddresses", []) or []
                    if str(e.get("type", "")).upper() == "PRIVATE"]
        return MethodResult.ok(
            Method.ALTERNATE, bool(privates),
            "assigned PRIVATE addresses: " + (str(privates) if privates else "none"),
            private_addresses=privates)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
