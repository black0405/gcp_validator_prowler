"""Base for checks that assert whether a specific GCP API is enabled/disabled."""
from __future__ import annotations

from typing import Any, Dict, List

from .resource_check import ResourceCheck
from .context import ValidationContext
from .models import Method, MethodResult


class ServiceEnabledCheck(ResourceCheck):
    """Subclasses set `api_host` and `want_enabled`."""
    api_host: str = ""
    want_enabled: bool = True
    audit_log_corroboration = False

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        return [{"id": self.api_host, "name": self.api_host, "project": ctx.project}]

    def evaluate(self, ctx, res):
        state = ctx.clients.service_state(self.api_host)
        enabled = state == "ENABLED"
        compliant = (enabled == self.want_enabled)
        want = "ENABLED" if self.want_enabled else "DISABLED"
        return compliant, f"serviceusage state of {self.api_host} = {state or 'UNKNOWN'} (want {want})", {"state": state}

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate signal: presence in the enabled-services listing."""
        su = ctx.clients.serviceusage()
        listed = False
        req = su.services().list(parent=f"projects/{ctx.project}", filter="state:ENABLED")
        while req is not None:
            resp = req.execute()
            for s in resp.get("services", []) or []:
                if str(s.get("name", "")).endswith(self.api_host):
                    listed = True
                    break
            req = su.services().list_next(req, resp) if not listed else None
        compliant = (listed == self.want_enabled)
        return MethodResult.ok(
            Method.ALTERNATE, compliant,
            f"services.list(state:ENABLED) {'contains' if listed else 'does not contain'} {self.api_host}",
            listed_enabled=listed)
