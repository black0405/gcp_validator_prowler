"""dns_rsasha1_in_use_to_zone_sign_in_dnssec — zone-signing must not use RSASHA1.

Prowler Hub: https://hub.prowler.com/check/dns_rsasha1_in_use_to_zone_sign_in_dnssec
"""
from checks.dns._base import DnsZoneCheck


class Check(DnsZoneCheck):
    check_id = "dns_rsasha1_in_use_to_zone_sign_in_dnssec"

    def evaluate(self, ctx, res):
        specs = (res["zone"].get("dnssecConfig") or {}).get("defaultKeySpecs", []) or []
        bad = [s for s in specs
               if s.get("keyType") == "zoneSigning" and str(s.get("algorithm", "")).lower() == "rsasha1"]
        return (not bad,
                "zone-signing algorithms: " + str([s.get("algorithm") for s in specs if s.get("keyType") == "zoneSigning"]),
                {"rsasha1_zone_signing": bool(bad)})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
