"""dns_dnssec_disabled — DNSSEC must be enabled on public managed zones.

Prowler Hub: https://hub.prowler.com/check/dns_dnssec_disabled
"""
from checks.dns._base import DnsZoneCheck
from gcpval.models import Method, MethodResult


class Check(DnsZoneCheck):
    check_id = "dns_dnssec_disabled"

    def _skip(self, method, zone):
        if not self.is_public(zone):
            return MethodResult.na(method, f"zone visibility={zone.get('visibility')}, DNSSEC applies to public zones")
        return None

    def evaluate(self, ctx, res):
        state = (res["zone"].get("dnssecConfig") or {}).get("state", "off")
        on = str(state).lower() == "on"
        return on, f"dnssecConfig.state={state}", {"state": state}

    def api_check(self, ctx, res) -> MethodResult:
        return self._skip(Method.API, res["zone"]) or super().api_check(ctx, res)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return self._skip(Method.PROWLER_REPLICA, res["zone"]) or super().prowler_replica_check(ctx, res)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
