"""cloudsql_instance_public_ip — instance should not have a public IP.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_public_ip
"""
from checks.cloudsql import _base
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval import exposure


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_public_ip"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        ipv4 = bool(_base.ip_config(inst).get("ipv4Enabled"))
        pub_ip = _base.primary_public_ip(inst)
        has_pub = ipv4 or pub_ip is not None
        return MethodResult.ok(
            Method.API, not has_pub,
            f"instances.get(): ipv4Enabled={ipv4}, primary public IP={pub_ip or 'none'}",
            ipv4_enabled=ipv4, public_ip=pub_ip)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        inst = res["instance"]
        has_pub = _base.has_public_ip(inst)
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not has_pub,
            f"Prowler rule ({self.hub_link}): FAIL when the instance has a public IP -> "
            + ("has one" if has_pub else "none"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: inspect the actually-assigned addresses and test
        whether any is globally routable (independent of the ipv4Enabled flag)."""
        inst = res["instance"]
        publics = []
        for entry in inst.get("ipAddresses", []) or []:
            ip = entry.get("ipAddress", "")
            if exposure.is_public_ip(ip):
                publics.append(ip)
        return MethodResult.ok(
            Method.ALTERNATE, not publics,
            "assigned globally-routable addresses: " + (str(publics) if publics else "none"),
            public_addresses=publics)

    def exposure_check(self, ctx, res) -> MethodResult:
        inst = res["instance"]
        pub_ip = _base.primary_public_ip(inst)
        if not pub_ip:
            return MethodResult.na(Method.EXPOSURE, "no public IP assigned")
        if not ctx.enable_exposure_probe:
            return MethodResult.na(Method.EXPOSURE,
                                   "exposure probe disabled (pass --enable-exposure-probe)")
        port = _base.db_port(inst)
        reachable, detail = exposure.tcp_probe(pub_ip, port, ctx.probe_timeout)
        verdict = Verdict.FAIL if reachable else Verdict.MANUAL
        note = "" if reachable else " (unreachable from this host does not prove no public IP)"
        return MethodResult(Method.EXPOSURE, verdict, detail + note, {"ip": pub_ip, "port": port})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
