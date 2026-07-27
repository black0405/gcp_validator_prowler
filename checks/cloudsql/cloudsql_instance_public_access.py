"""cloudsql_instance_public_access — instance must not allow 0.0.0.0/0 (whole internet).

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_public_access
"""
from checks.cloudsql import _base
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval import exposure


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_public_access"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        nets = _base.authorized_networks(inst)
        open_ = _base.has_open_authorized_network(inst)
        return MethodResult.ok(
            Method.API, not open_,
            "instances.get(): authorizedNetworks=" + (str(nets) or "[]")
            + (" includes 0.0.0.0/0 (public)" if open_ else " (no whole-internet rule)"),
            authorized_networks=nets)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        inst = res["instance"]
        open_ = _base.has_open_authorized_network(inst)
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not open_,
            f"Prowler rule ({self.hub_link}): FAIL when an authorized network is 0.0.0.0/0"
            + (" -> found" if open_ else " -> not found"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: a rule is only actually reachable if the instance
        also has a public IP. Combine assigned public IP + open rule."""
        inst = res["instance"]
        pub_ip = _base.primary_public_ip(inst)
        open_ = _base.has_open_authorized_network(inst)
        reachable_config = bool(pub_ip) and open_
        return MethodResult.ok(
            Method.ALTERNATE, not reachable_config,
            f"public IP={pub_ip or 'none'}, open-rule={open_} -> "
            + ("internet-reachable by config" if reachable_config else "not internet-reachable by config"),
            public_ip=pub_ip)

    def exposure_check(self, ctx, res) -> MethodResult:
        inst = res["instance"]
        pub_ip = _base.primary_public_ip(inst)
        if not pub_ip:
            return MethodResult.na(Method.EXPOSURE, "instance has no public IP to probe")
        if not ctx.enable_exposure_probe:
            return MethodResult.na(Method.EXPOSURE,
                                   "exposure probe disabled (pass --enable-exposure-probe)")
        port = _base.db_port(inst)
        reachable, detail = exposure.tcp_probe(pub_ip, port, ctx.probe_timeout)
        if reachable:
            return MethodResult(Method.EXPOSURE, Verdict.FAIL,
                                "CONFIRMED internet-reachable: " + detail, {"ip": pub_ip, "port": port})
        return MethodResult(Method.EXPOSURE, Verdict.MANUAL,
                            detail + " (does not by itself disprove a public config; "
                            "this host may be filtered)", {"ip": pub_ip, "port": port})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
