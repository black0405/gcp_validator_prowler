"""logging_sink_created — a sink exporting all log entries must exist.

Prowler Hub: https://hub.prowler.com/check/logging_sink_created
"""
from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class Check(ResourceCheck):
    check_id = "logging_sink_created"
    service = "logging"
    audit_log_corroboration = False

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project}]

    def _sinks(self, ctx):
        log = ctx.clients.discovery("logging", "v2")
        sinks: List[dict] = []
        req = log.projects().sinks().list(parent=f"projects/{ctx.project}")
        while req is not None:
            resp = req.execute()
            sinks.extend(resp.get("sinks", []) or [])
            req = log.projects().sinks().list_next(req, resp)
        return sinks

    def evaluate(self, ctx, res):
        sinks = self._sinks(ctx)
        # A sink with no filter exports every log entry (CIS requirement).
        export_all = [s.get("name") for s in sinks if not (s.get("filter") or "").strip()]
        ok = bool(export_all)
        return ok, (f"{len(sinks)} sink(s); exporting-all (empty filter): "
                    f"{export_all or 'none'}"), {"sink_count": len(sinks), "export_all": export_all}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
