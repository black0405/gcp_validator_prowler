"""secretmanager_secret_not_publicly_accessible — secret IAM must not be public.

Prowler Hub: https://hub.prowler.com/check/secretmanager_secret_not_publicly_accessible
"""
from checks.secretmanager._base import SecretCheck
from gcpval.models import Method, MethodResult
from gcpval.gcp_util import public_bindings


class Check(SecretCheck):
    check_id = "secretmanager_secret_not_publicly_accessible"

    def api_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.secret_iam(ctx, res["full_name"]))
        return MethodResult.ok(Method.API, not pub,
                               "getIamPolicy(): public bindings=" + (str(pub) if pub else "none"),
                               public_bindings=pub)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.secret_iam(ctx, res["full_name"]))
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not pub,
            f"Prowler rule ({self.hub_link}): FAIL when allUsers/allAuthenticatedUsers "
            f"are bound -> " + ("found" if pub else "none"))


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
