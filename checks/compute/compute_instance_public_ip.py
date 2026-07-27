"""compute_instance_public_ip — VM instances should not have external IPs.

Prowler Hub: https://hub.prowler.com/check/compute_instance_public_ip
"""
from checks.compute._base import ComputeInstanceCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval import exposure


def _public_ips(instance):
    ips = []
    for nic in instance.get("networkInterfaces", []) or []:
        for ac in nic.get("accessConfigs", []) or []:
            if ac.get("natIP"):
                ips.append(ac["natIP"])
    return ips


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_public_ip"

    def evaluate(self, ctx, res):
        ips = _public_ips(res["instance"])
        return (not ips, "external IPs: " + (str(ips) if ips else "none"), {"public_ips": ips})

    def alternate_check(self, ctx, res) -> MethodResult:
        # Alternate signal: only globally-routable natIPs really count as public.
        publics = [ip for ip in _public_ips(res["instance"]) if exposure.is_public_ip(ip)]
        return MethodResult.ok(Method.ALTERNATE, not publics,
                               "globally-routable external IPs: " + (str(publics) if publics else "none"),
                               public_addresses=publics)

    def exposure_check(self, ctx, res) -> MethodResult:
        ips = [ip for ip in _public_ips(res["instance"]) if exposure.is_public_ip(ip)]
        if not ips:
            return MethodResult.na(Method.EXPOSURE, "no external IP to probe")
        if not ctx.enable_exposure_probe:
            return MethodResult.na(Method.EXPOSURE, "exposure probe disabled (pass --enable-exposure-probe)")
        reachable, detail = exposure.tcp_probe(ips[0], 22, ctx.probe_timeout)
        verdict = Verdict.FAIL if reachable else Verdict.MANUAL
        return MethodResult(Method.EXPOSURE, verdict, detail, {"ip": ips[0]})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
