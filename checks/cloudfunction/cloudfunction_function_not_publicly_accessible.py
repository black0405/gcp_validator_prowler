"""cloudfunction_function_not_publicly_accessible — function IAM must not allow allUsers.

Prowler Hub: https://hub.prowler.com/check/cloudfunction_function_not_publicly_accessible
"""
from checks.cloudfunction._base import CloudFunctionCheck
from gcpval.models import Method, MethodResult
from gcpval.gcp_util import public_bindings


class Check(CloudFunctionCheck):
    check_id = "cloudfunction_function_not_publicly_accessible"

    def api_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.function_iam(ctx, res["full_name"]))
        return MethodResult.ok(Method.API, not pub,
                               "getIamPolicy(): public bindings=" + (str(pub) if pub else "none"),
                               public_bindings=pub)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.function_iam(ctx, res["full_name"]))
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not pub,
            f"Prowler rule ({self.hub_link}): FAIL when allUsers/allAuthenticatedUsers "
            f"can invoke the function -> " + ("found" if pub else "none"))


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
