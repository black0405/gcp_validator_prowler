"""Shared bases + helpers for Compute Engine checks."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext

DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def metadata_items(meta: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in (meta or {}).get("items", []) or []:
        out[str(it.get("key", ""))] = str(it.get("value", ""))
    return out


def aggregated(collection, project: str, key: str = "instances") -> List[dict]:
    """Iterate a Compute aggregatedList endpoint and flatten items."""
    items: List[dict] = []
    req = collection.aggregatedList(project=project)
    while req is not None:
        resp = req.execute()
        for _scope, block in (resp.get("items", {}) or {}).items():
            items.extend(block.get(key, []) or [])
        req = collection.aggregatedList_next(req, resp)
    return items


class ComputeCheck(ResourceCheck):
    service = "compute"


class ComputeInstanceCheck(ComputeCheck):
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for inst in aggregated(ctx.clients.compute().instances(), ctx.project, "instances"):
            zone = str(inst.get("zone", "")).split("/")[-1]
            out.append({
                "id": inst.get("id") or inst.get("name"), "name": inst.get("name"),
                "region": zone, "project": ctx.project, "instance": inst,
            })
        return out


class ComputeFirewallCheck(ComputeCheck):
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        req = ctx.clients.compute().firewalls().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            for fw in resp.get("items", []) or []:
                out.append({"id": fw.get("id") or fw.get("name"), "name": fw.get("name"),
                            "region": "global", "project": ctx.project, "firewall": fw})
            req = ctx.clients.compute().firewalls().list_next(req, resp)
        return out


class ComputeNetworkCheck(ComputeCheck):
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        req = ctx.clients.compute().networks().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            for n in resp.get("items", []) or []:
                out.append({"id": n.get("id") or n.get("name"), "name": n.get("name"),
                            "region": "global", "project": ctx.project, "network": n})
            req = ctx.clients.compute().networks().list_next(req, resp)
        return out


class ComputeSubnetCheck(ComputeCheck):
    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for s in aggregated(ctx.clients.compute().subnetworks(), ctx.project, "subnetworks"):
            region = str(s.get("region", "")).split("/")[-1]
            out.append({"id": s.get("id") or s.get("name"), "name": s.get("name"),
                        "region": region, "project": ctx.project, "subnet": s})
        return out


class ComputeProjectCheck(ComputeCheck):
    audit_log_corroboration = False

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        proj = ctx.clients.compute().projects().get(project=ctx.project).execute()
        return [{"id": ctx.project, "name": ctx.project, "region": "global",
                 "project": ctx.project, "project_obj": proj}]


def firewall_allows_port(fw: Dict[str, Any], port: int) -> bool:
    """True if an INGRESS firewall from 0.0.0.0/0 allows tcp `port` (or all)."""
    if fw.get("direction", "INGRESS") != "INGRESS" or fw.get("disabled"):
        return False
    if "0.0.0.0/0" not in (fw.get("sourceRanges", []) or []):
        return False
    for a in fw.get("allowed", []) or []:
        proto = str(a.get("IPProtocol", "")).lower()
        if proto in ("all",):
            return True
        if proto not in ("tcp", "6"):
            continue
        ports = a.get("ports")
        if not ports:  # tcp with no port list == all tcp ports
            return True
        for spec in ports:
            spec = str(spec)
            if "-" in spec:
                lo, hi = spec.split("-", 1)
                if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                    return True
            elif spec.isdigit() and int(spec) == port:
                return True
    return False
