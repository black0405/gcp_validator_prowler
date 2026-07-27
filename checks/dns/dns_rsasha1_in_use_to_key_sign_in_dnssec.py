"""dns_rsasha1_in_use_to_key_sign_in_dnssec — key-signing must not use RSASHA1.

Prowler Hub: https://hub.prowler.com/check/dns_rsasha1_in_use_to_key_sign_in_dnssec
"""
from checks.dns._base import DnsZoneCheck


class Check(DnsZoneCheck):
    check_id = "dns_rsasha1_in_use_to_key_sign_in_dnssec"

    def evaluate(self, ctx, res):
        specs = (res["zone"].get("dnssecConfig") or {}).get("defaultKeySpecs", []) or []
        bad = [s for s in specs
               if s.get("keyType") == "keySigning" and str(s.get("algorithm", "")).lower() == "rsasha1"]
        return (not bad,
                "key-signing algorithms: " + str([s.get("algorithm") for s in specs if s.get("keyType") == "keySigning"]),
                {"rsasha1_key_signing": bool(bad)})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
