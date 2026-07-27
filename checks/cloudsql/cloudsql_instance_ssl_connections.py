"""cloudsql_instance_ssl_connections — instance must require SSL/TLS for connections.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_ssl_connections
"""
from checks.cloudsql import _base
from checks.cloudsql._base import CloudSqlCheck
from gcpval.models import Method, MethodResult

_SECURE_SSL_MODES = {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}


def _requires_ssl(inst) -> tuple:
    cfg = _base.ip_config(inst)
    ssl_mode = str(cfg.get("sslMode", "")).upper()
    require_ssl = bool(cfg.get("requireSsl"))
    secure = require_ssl or ssl_mode in _SECURE_SSL_MODES
    return secure, ssl_mode, require_ssl


class Check(CloudSqlCheck):
    check_id = "cloudsql_instance_ssl_connections"

    def api_check(self, ctx, res) -> MethodResult:
        inst = self._fresh_get(ctx, res)
        secure, ssl_mode, require_ssl = _requires_ssl(inst)
        return MethodResult.ok(
            Method.API, secure,
            f"instances.get(): sslMode={ssl_mode or 'unset'}, requireSsl={require_ssl}",
            ssl_mode=ssl_mode, require_ssl=require_ssl)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        secure, ssl_mode, require_ssl = _requires_ssl(res["instance"])
        return MethodResult.ok(
            Method.PROWLER_REPLICA, secure,
            f"Prowler rule ({self.hub_link}): PASS when SSL is enforced "
            f"(requireSsl or sslMode in {sorted(_SECURE_SSL_MODES)}) -> "
            + ("enforced" if secure else "not enforced"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate vantage: presence of a server CA cert / serverCaCert config
        indicates TLS material provisioned (corroborating signal)."""
        inst = res["instance"]
        has_ca = bool(inst.get("serverCaCert"))
        secure, ssl_mode, _ = _requires_ssl(inst)
        # SSL truly enforced requires the mode; CA presence alone is not enough.
        return MethodResult.ok(
            Method.ALTERNATE, secure,
            f"serverCaCert present={has_ca}; enforced sslMode={ssl_mode or 'unset'}",
            has_server_ca=has_ca)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
