"""Shared base for API Keys checks (key discovery via the apikeys API)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class ApiKeysCheck(ResourceCheck):
    service = "apikeys"
    audit_log_corroboration = False

    def _list_keys(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        ak = ctx.clients.discovery("apikeys", "v2")
        number = ctx.clients.project_number()
        keys: List[Dict[str, Any]] = []
        req = ak.projects().locations().keys().list(
            parent=f"projects/{number}/locations/global")
        while req is not None:
            resp = req.execute()
            keys.extend(resp.get("keys", []) or [])
            req = ak.projects().locations().keys().list_next(req, resp)
        return keys

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for k in self._list_keys(ctx):
            out.append({
                "id": k.get("uid") or k.get("name"),
                "name": k.get("displayName") or str(k.get("name", "")).split("/")[-1],
                "region": "global", "project": ctx.project, "key": k,
            })
        return out
