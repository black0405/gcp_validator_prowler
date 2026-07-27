"""Shared base classes for Cloud SQL checks.

Cloud SQL Admin API (sqladmin v1) is the single source for instance
configuration. `CloudSqlCheck` handles instance discovery, database-flag
extraction, Cloud Audit Log correlation, and an alternate-API vantage;
`CloudSqlFlagCheck` turns almost every database-flag control into a few lines.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from gcpval.base_check import BaseCheck
from gcpval.context import ValidationContext
from gcpval.models import Method, MethodResult, Verdict
from gcpval import logging_access as logs


def db_family(instance: Dict[str, Any]) -> str:
    """MYSQL / POSTGRES / SQLSERVER derived from databaseVersion."""
    ver = (instance.get("databaseVersion") or "").upper()
    if ver.startswith("MYSQL"):
        return "MYSQL"
    if ver.startswith("POSTGRES"):
        return "POSTGRES"
    if ver.startswith("SQLSERVER"):
        return "SQLSERVER"
    return "UNKNOWN"


def flags_map(instance: Dict[str, Any]) -> Dict[str, str]:
    settings = instance.get("settings", {}) or {}
    out: Dict[str, str] = {}
    for f in settings.get("databaseFlags", []) or []:
        out[str(f.get("name", "")).lower()] = str(f.get("value", ""))
    return out


def ip_config(instance: Dict[str, Any]) -> Dict[str, Any]:
    return (instance.get("settings", {}) or {}).get("ipConfiguration", {}) or {}


def authorized_networks(instance: Dict[str, Any]) -> List[str]:
    return [str(n.get("value", "")) for n in ip_config(instance).get("authorizedNetworks", []) or []]


def has_open_authorized_network(instance: Dict[str, Any]) -> bool:
    return any(v in ("0.0.0.0/0", "0.0.0.0", "::/0") for v in authorized_networks(instance))


def primary_public_ip(instance: Dict[str, Any]) -> Optional[str]:
    """The assigned public (PRIMARY) IP address, if the instance has one."""
    for entry in instance.get("ipAddresses", []) or []:
        if str(entry.get("type", "")).upper() == "PRIMARY":
            return entry.get("ipAddress")
    return None


def has_public_ip(instance: Dict[str, Any]) -> bool:
    return bool(ip_config(instance).get("ipv4Enabled")) or primary_public_ip(instance) is not None


def db_port(instance: Dict[str, Any]) -> int:
    from gcpval.exposure import DB_PORTS
    return DB_PORTS.get(db_family(instance), 3306)


class CloudSqlCheck(BaseCheck):
    service = "cloudsql"

    # Audit-log method names that mutate a Cloud SQL instance.
    _MUTATION_METHODS = [
        "cloudsql.instances.update",
        "cloudsql.instances.patch",
        "cloudsql.instances.create",
    ]

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        svc = ctx.clients.sqladmin()
        resp = svc.instances().list(project=ctx.project).execute()
        out: List[Dict[str, Any]] = []
        for inst in resp.get("items", []) or []:
            out.append({
                "id": inst.get("selfLink") or inst.get("name"),
                "name": inst.get("name"),
                "region": inst.get("region", ""),
                "project": ctx.project,
                "instance": inst,          # object from the bulk list() call
            })
        return out

    def _fresh_get(self, ctx: ValidationContext, res: Dict[str, Any]) -> Dict[str, Any]:
        """Authoritative single-instance read via instances.get() (distinct call
        from the bulk list() used for discovery)."""
        svc = ctx.clients.sqladmin()
        return svc.instances().get(project=ctx.project, instance=res["name"]).execute()

    # ---- method 3: correlate from Cloud Audit Logs ---------------------
    def logs_check(self, ctx: ValidationContext, res: Dict[str, Any]) -> MethodResult:
        log_filter = logs.audit_filter_for_resource(
            self._MUTATION_METHODS, resource_name_substr=res["name"],
            window_days=ctx.log_window_days,
        )
        entries = logs.query_entries(ctx.clients, log_filter)
        if not entries:
            return MethodResult.na(
                Method.LOGS,
                f"no Cloud SQL config-change audit entries for '{res['name']}' in last "
                f"{ctx.log_window_days}d to corroborate from",
            )
        recent = [logs.entry_to_dict(e) for e in entries[:5]]
        return self._logs_verdict(ctx, res, entries, recent)

    def _logs_verdict(self, ctx, res, entries, recent) -> MethodResult:
        """Default: report the change history as corroboration (MANUAL —
        current-state read is authoritative). Flag checks override to extract
        the value that was last set."""
        return MethodResult(
            Method.LOGS, Verdict.MANUAL,
            f"{len(entries)} config-change event(s) found; current-state check is authoritative",
            {"recent_changes": recent},
        )


class CloudSqlFlagCheck(CloudSqlCheck):
    """Base for database-flag controls.

    Subclasses set:
      flag_name         : the databaseFlags name (lowercased match)
      db_family_filter  : 'MYSQL' | 'POSTGRES' | 'SQLSERVER' | None (all)
      secure            : callable(value:str|None) -> bool  (value is None if absent)
      absent_is_secure  : how a *missing* flag is treated by the direct read
      prowler_absent_is_secure : how Prowler treats a missing flag (often stricter)
      requirement_desc  : human summary of the secure setting
    """
    flag_name: str = ""
    db_family_filter: Optional[str] = None
    absent_is_secure: bool = False
    prowler_absent_is_secure: bool = False
    requirement_desc: str = ""

    def secure(self, value: Optional[str]) -> bool:  # override
        raise NotImplementedError

    def _applies(self, instance: Dict[str, Any]) -> Optional[str]:
        if self.db_family_filter and db_family(instance) != self.db_family_filter:
            return (f"instance is {db_family(instance)}, flag only applies to "
                    f"{self.db_family_filter}")
        return None

    def _evaluate(self, instance: Dict[str, Any], absent_is_secure: bool):
        fmap = flags_map(instance)
        raw = fmap.get(self.flag_name.lower())
        if raw is None:
            compliant = absent_is_secure
            detail = (f"flag '{self.flag_name}' not set -> "
                      f"{'compliant (secure default)' if compliant else 'non-compliant (must be set)'}; "
                      f"required: {self.requirement_desc}")
        else:
            compliant = self.secure(raw)
            detail = (f"flag '{self.flag_name}' = '{raw}' -> "
                      f"{'compliant' if compliant else 'non-compliant'}; "
                      f"required: {self.requirement_desc}")
        return compliant, detail, raw

    def api_check(self, ctx, res) -> MethodResult:
        instance = self._fresh_get(ctx, res)
        skip = self._applies(instance)
        if skip:
            return MethodResult.na(Method.API, skip)
        compliant, detail, raw = self._evaluate(instance, self.absent_is_secure)
        return MethodResult.ok(Method.API, compliant, "instances.get(): " + detail,
                               flag=self.flag_name, value=raw)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        instance = res["instance"]
        skip = self._applies(instance)
        if skip:
            return MethodResult.na(Method.PROWLER_REPLICA, skip)
        compliant, detail, raw = self._evaluate(instance, self.prowler_absent_is_secure)
        return MethodResult.ok(
            Method.PROWLER_REPLICA, compliant,
            f"Prowler rule ({self.hub_link}): " + detail,
            flag=self.flag_name, value=raw)

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: evaluate the object returned by the bulk list()
        call rather than a per-instance get(). Divergence between the two API
        paths is itself a signal worth surfacing."""
        instance = res["instance"]
        skip = self._applies(instance)
        if skip:
            return MethodResult.na(Method.ALTERNATE, skip)
        compliant, detail, raw = self._evaluate(instance, self.absent_is_secure)
        return MethodResult.ok(Method.ALTERNATE, compliant,
                               "instances.list() vantage: " + detail,
                               flag=self.flag_name, value=raw)

    def _logs_verdict(self, ctx, res, entries, recent) -> MethodResult:
        # Extract the flag value from the most recent mutation payload, if present.
        for e in entries:
            payload = getattr(e, "payload", None)
            if not isinstance(payload, dict):
                continue
            req = payload.get("request", {}) or {}
            body = req.get("body", req)
            settings = ((body.get("settings") if isinstance(body, dict) else {}) or {})
            for f in settings.get("databaseFlags", []) or []:
                if str(f.get("name", "")).lower() == self.flag_name.lower():
                    val = str(f.get("value", ""))
                    compliant = self.secure(val)
                    return MethodResult.ok(
                        Method.LOGS, compliant,
                        f"last config-change set '{self.flag_name}'='{val}' -> "
                        f"{'compliant' if compliant else 'non-compliant'}",
                        recent_changes=recent)
        return MethodResult(
            Method.LOGS, Verdict.MANUAL,
            f"{len(entries)} config-change event(s) found but none carried flag "
            f"'{self.flag_name}' in payload; current-state check is authoritative",
            {"recent_changes": recent})
