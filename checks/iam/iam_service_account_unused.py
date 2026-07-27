"""iam_service_account_unused — flag service accounts with no recent activity.

Prowler Hub: https://hub.prowler.com/check/iam_service_account_unused

"Unused" needs last-authentication data (Policy Intelligence / activity
analyzer). The direct API can only tell us the SA is enabled/disabled, so
method 1 reports MANUAL and method 3 provides the real signal from audit logs.
"""
from checks.iam._base import IamServiceAccountCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval import logging_access as logs


class Check(IamServiceAccountCheck):
    check_id = "iam_service_account_unused"
    audit_log_corroboration = False

    def api_check(self, ctx, res) -> MethodResult:
        sa = res["sa"]
        if sa.get("disabled"):
            return MethodResult(Method.API, Verdict.PASS,
                                f"{res['email']} is disabled (not in active use)")
        return MethodResult(
            Method.API, Verdict.MANUAL,
            f"{res['email']} is enabled; usage/last-auth not available from the IAM API "
            f"— see method 3")

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return MethodResult(
            Method.PROWLER_REPLICA, Verdict.MANUAL,
            f"Prowler rule ({self.hub_link}): flags service accounts with no recent "
            f"authentication activity")

    def logs_check(self, ctx, res) -> MethodResult:
        since = logs.since_timestamp(ctx.log_window_days)
        flt = (f'protoPayload.authenticationInfo.principalEmail="{res["email"]}" '
               f'AND timestamp>="{since}"')
        try:
            entries = logs.query_entries(ctx.clients, flt)
        except Exception as exc:  # noqa: BLE001
            return MethodResult.error(Method.LOGS, exc)
        if entries:
            return MethodResult(Method.LOGS, Verdict.FAIL,
                                f"{len(entries)} activity event(s) in {ctx.log_window_days}d "
                                f"-> service account IS in use")
        return MethodResult(Method.LOGS, Verdict.PASS,
                            f"no activity for {res['email']} in {ctx.log_window_days}d "
                            f"-> appears unused")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
