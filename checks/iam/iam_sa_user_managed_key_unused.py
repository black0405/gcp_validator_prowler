"""iam_sa_user_managed_key_unused — flag user-managed SA keys that are not being used.

Prowler Hub: https://hub.prowler.com/check/iam_sa_user_managed_key_unused

Key *usage* is not exposed by the IAM API; it needs the key's last-authentication
time (Policy Intelligence / data-access logs). Method 3 (logs) is the real
signal here; the direct API can only enumerate keys, so it reports MANUAL.
"""
from checks.iam._base import IamServiceAccountCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval import logging_access as logs


class Check(IamServiceAccountCheck):
    check_id = "iam_sa_user_managed_key_unused"
    audit_log_corroboration = False

    def _keys(self, ctx, res):
        return [k for k in self.list_sa_keys(ctx, res["email"]) if k.get("keyType") == "USER_MANAGED"]

    def api_check(self, ctx, res) -> MethodResult:
        keys = self._keys(ctx, res)
        if not keys:
            return MethodResult(Method.API, Verdict.PASS, f"{res['email']}: no user-managed keys")
        return MethodResult(
            Method.API, Verdict.MANUAL,
            f"{res['email']}: {len(keys)} user-managed key(s); key-usage/last-auth is not "
            f"available from the IAM API — see method 3")

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return MethodResult(
            Method.PROWLER_REPLICA, Verdict.MANUAL,
            f"Prowler rule ({self.hub_link}): flags user-managed keys with no recent "
            f"authentication (requires key last-usage data)")

    def logs_check(self, ctx, res) -> MethodResult:
        keys = self._keys(ctx, res)
        if not keys:
            return MethodResult.na(Method.LOGS, "no user-managed keys")
        since = logs.since_timestamp(ctx.log_window_days)
        flt = (f'protoPayload.authenticationInfo.serviceAccountKeyName:"{res["email"]}" '
               f'AND timestamp>="{since}"')
        try:
            entries = logs.query_entries(ctx.clients, flt)
        except Exception as exc:  # noqa: BLE001
            return MethodResult.error(Method.LOGS, exc)
        if entries:
            return MethodResult(Method.LOGS, Verdict.FAIL,
                                f"{len(entries)} authentication event(s) in {ctx.log_window_days}d "
                                f"-> key(s) IS in use")
        return MethodResult(Method.LOGS, Verdict.PASS,
                            f"no key authentication events in {ctx.log_window_days}d "
                            f"-> key(s) appear unused")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
