"""Shared base for Cloud KMS checks (crypto-key discovery + IAM helper)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class KmsCheck(ResourceCheck):
    service = "kms"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        kms = ctx.clients.cloudkms()
        out: List[Dict[str, Any]] = []
        locs = kms.projects().locations().list(
            name=f"projects/{ctx.project}").execute().get("locations", []) or []
        for loc in locs:
            loc_name = loc["name"]
            rreq = kms.projects().locations().keyRings().list(parent=loc_name)
            while rreq is not None:
                rresp = rreq.execute()
                for ring in rresp.get("keyRings", []) or []:
                    kreq = kms.projects().locations().keyRings().cryptoKeys().list(
                        parent=ring["name"])
                    while kreq is not None:
                        kresp = kreq.execute()
                        for k in kresp.get("cryptoKeys", []) or []:
                            out.append({
                                "id": k["name"],
                                "name": k["name"].split("/")[-1],
                                "full_name": k["name"],
                                "region": loc.get("locationId", ""),
                                "project": ctx.project,
                                "key": k,
                            })
                        kreq = kms.projects().locations().keyRings().cryptoKeys().list_next(kreq, kresp)
                rreq = kms.projects().locations().keyRings().list_next(rreq, rresp)
        return out

    @staticmethod
    def key_iam(ctx: ValidationContext, full_name: str) -> Dict[str, Any]:
        return (ctx.clients.cloudkms().projects().locations().keyRings()
                .cryptoKeys().getIamPolicy(resource=full_name).execute())
