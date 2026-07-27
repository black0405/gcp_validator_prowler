"""compute_network_dns_logging_enabled — a DNS policy with logging must cover the network.

Prowler Hub: https://hub.prowler.com/check/compute_network_dns_logging_enabled
"""
from checks.compute._base import ComputeNetworkCheck


class Check(ComputeNetworkCheck):
    check_id = "compute_network_dns_logging_enabled"

    def _logging_policies(self, ctx):
        dns = ctx.clients.dns()
        pols = []
        req = dns.policies().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            pols.extend(resp.get("policies", []) or [])
            req = dns.policies().list_next(req, resp)
        return pols

    def evaluate(self, ctx, res):
        net = res["network"]
        net_url = net.get("selfLink", "")
        net_name = net.get("name", "")
        covering = []
        for p in self._logging_policies(ctx):
            if not p.get("enableLogging"):
                continue
            for n in p.get("networks", []) or []:
                url = n.get("networkUrl", "")
                if url and (url == net_url or url.endswith("/" + net_name)):
                    covering.append(p.get("name"))
        ok = bool(covering)
        return ok, f"DNS policies with logging covering '{net_name}': {covering or 'none'}", {"policies": covering}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
