"""kms_key_not_publicly_accessible — crypto key IAM must not grant allUsers/allAuthenticatedUsers.

Prowler Hub: https://hub.prowler.com/check/kms_key_not_publicly_accessible
"""
from checks.kms._base import KmsCheck
from gcpval.models import Method, MethodResult
from gcpval.gcp_util import public_bindings


class Check(KmsCheck):
    check_id = "kms_key_not_publicly_accessible"

    def api_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.key_iam(ctx, res["full_name"]))
        return MethodResult.ok(
            Method.API, not pub,
            "getIamPolicy(): public bindings=" + (str(pub) if pub else "none"),
            public_bindings=pub)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        pub = public_bindings(self.key_iam(ctx, res["full_name"]))
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not pub,
            f"Prowler rule ({self.hub_link}): FAIL when the key policy binds "
            f"allUsers/allAuthenticatedUsers -> " + ("found" if pub else "none"))


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
