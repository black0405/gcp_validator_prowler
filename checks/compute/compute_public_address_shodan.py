"""compute_public_address_shodan — external IPs should not be exposed/known to Shodan.

Prowler Hub: https://hub.prowler.com/check/compute_public_address_shodan

Prowler queries the Shodan API. Set SHODAN_API_KEY to enable method 1/2 here;
otherwise they report MANUAL. Method 5 independently probes common ports.
"""
import json
import os
from typing import Any, Dict, List

from checks.compute._base import ComputeCheck, aggregated
from gcpval.context import ValidationContext
from gcpval.models import Method, MethodResult, Verdict
from gcpval import exposure


class Check(ComputeCheck):
    check_id = "compute_public_address_shodan"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for a in aggregated(ctx.clients.compute().addresses(), ctx.project, "addresses"):
            if str(a.get("addressType", "")).upper() != "EXTERNAL":
                continue
            loc = str(a.get("region", "global")).split("/")[-1] or "global"
            out.append({"id": a.get("id") or a.get("address"), "name": a.get("name"),
                        "region": loc, "project": ctx.project,
                        "address": a.get("address", ""), "status": a.get("status", "")})
        return out

    def _shodan(self, ip: str):
        key = os.environ.get("SHODAN_API_KEY", "")
        if not key:
            return None, "SHODAN_API_KEY not set"
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(
                    f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=8) as resp:
                data = json.loads(resp.read().decode())
                ports = data.get("ports", []) or []
                return ports, f"Shodan lists {ip} with open ports {ports}"
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return [], f"{ip} not found in Shodan"
            return None, f"Shodan HTTP {exc.code}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return None, f"Shodan query failed: {exc}"

    def api_check(self, ctx, res) -> MethodResult:
        ip = res["address"]
        if not exposure.is_public_ip(ip):
            return MethodResult.na(Method.API, f"{ip} is not a public address")
        ports, detail = self._shodan(ip)
        if ports is None:
            return MethodResult(Method.API, Verdict.MANUAL, detail)
        return MethodResult.ok(Method.API, not ports, detail, ports=ports)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return MethodResult(
            Method.PROWLER_REPLICA, Verdict.MANUAL,
            f"Prowler rule ({self.hub_link}): FAIL when Shodan reports the external IP "
            f"as exposed (requires SHODAN_API_KEY)")

    def exposure_check(self, ctx, res) -> MethodResult:
        ip = res["address"]
        if not exposure.is_public_ip(ip):
            return MethodResult.na(Method.EXPOSURE, "not a public address")
        if not ctx.enable_exposure_probe:
            return MethodResult.na(Method.EXPOSURE, "exposure probe disabled (pass --enable-exposure-probe)")
        for port in (22, 80, 443, 3389):
            reachable, detail = exposure.tcp_probe(ip, port, ctx.probe_timeout)
            if reachable:
                return MethodResult(Method.EXPOSURE, Verdict.FAIL,
                                    "CONFIRMED reachable: " + detail, {"ip": ip, "port": port})
        return MethodResult(Method.EXPOSURE, Verdict.MANUAL,
                            f"{ip}: no common port (22/80/443/3389) reachable from this host")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
