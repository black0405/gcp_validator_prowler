"""Shared base for Cloud DNS checks (managed-zone discovery)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class DnsZoneCheck(ResourceCheck):
    service = "dns"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        dns = ctx.clients.dns()
        out: List[Dict[str, Any]] = []
        req = dns.managedZones().list(project=ctx.project)
        while req is not None:
            resp = req.execute()
            for z in resp.get("managedZones", []) or []:
                out.append({
                    "id": z.get("id") or z.get("name"), "name": z.get("name"),
                    "region": z.get("visibility", ""), "project": ctx.project,
                    "zone": z,
                })
            req = dns.managedZones().list_next(req, resp)
        return out

    @staticmethod
    def is_public(zone) -> bool:
        return str(zone.get("visibility", "public")).lower() == "public"
