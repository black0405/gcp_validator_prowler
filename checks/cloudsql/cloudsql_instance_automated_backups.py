"""cloudsql_instance_automated_backups — automated backups must be enabled.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_automated_backups
"""
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult


def _backup_enabled(inst) -> bool:
    return bool((inst.get("settings", {}) or {}).get("backupConfiguration", {}).get("enabled"))


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_automated_backups"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        enabled = _backup_enabled(inst)
        return MethodResult.ok(
            Method.API, enabled,
            f"instances.get(): backupConfiguration.enabled={enabled}",
            backup_enabled=enabled)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        enabled = _backup_enabled(res["instance"])
        return MethodResult.ok(
            Method.PROWLER_REPLICA, enabled,
            f"Prowler rule ({self.hub_link}): PASS when backupConfiguration.enabled is true -> "
            + ("enabled" if enabled else "disabled"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate API path: query backupRuns.list() — proof that successful
        backups actually exist, not just that the setting is on."""
        svc = ctx.clients.sqladmin()
        resp = svc.backupRuns().list(project=ctx.project, instance=res["name"]).execute()
        runs = resp.get("items", []) or []
        successful = [r for r in runs if str(r.get("status", "")).upper() == "SUCCESSFUL"]
        return MethodResult.ok(
            Method.ALTERNATE, bool(successful),
            f"backupRuns.list(): {len(runs)} run(s), {len(successful)} successful",
            total_runs=len(runs), successful_runs=len(successful))


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
