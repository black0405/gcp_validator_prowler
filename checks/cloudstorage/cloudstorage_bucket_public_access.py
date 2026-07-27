"""cloudstorage_bucket_public_access — bucket must not be public.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_bucket_public_access
"""
from checks.cloudstorage._base import CloudStorageCheck
from gcpval.models import Method, MethodResult, Verdict
from gcpval.gcp_util import public_bindings
from gcpval import exposure


class Check(CloudStorageCheck):
    check_id = "cloudstorage_bucket_public_access"

    def api_check(self, ctx, res) -> MethodResult:
        policy = self.bucket_iam(ctx, res["name"])
        pub = public_bindings(policy)
        return MethodResult.ok(
            Method.API, not pub,
            "getIamPolicy(): public bindings=" + (str(pub) if pub else "none"),
            public_bindings=pub)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        policy = self.bucket_iam(ctx, res["name"])
        pub = public_bindings(policy)
        return MethodResult.ok(
            Method.PROWLER_REPLICA, not pub,
            f"Prowler rule ({self.hub_link}): FAIL when allUsers/allAuthenticatedUsers "
            f"are bound -> " + ("found" if pub else "none"))

    def alternate_check(self, ctx, res) -> MethodResult:
        """Alternate signal: publicAccessPrevention='enforced' blocks public
        grants regardless of IAM bindings."""
        cfg = (res["bucket"].get("iamConfiguration") or {})
        pap = cfg.get("publicAccessPrevention", "inherited")
        enforced = pap == "enforced"
        return MethodResult.ok(
            Method.ALTERNATE, enforced,
            f"iamConfiguration.publicAccessPrevention={pap}",
            public_access_prevention=pap)

    def exposure_check(self, ctx, res) -> MethodResult:
        if not ctx.enable_exposure_probe:
            return MethodResult.na(Method.EXPOSURE,
                                   "exposure probe disabled (pass --enable-exposure-probe)")
        url = f"https://storage.googleapis.com/storage/v1/b/{res['name']}/o?maxResults=1"
        status, detail = exposure.http_status(url, ctx.probe_timeout)
        if status == 200:
            return MethodResult(Method.EXPOSURE, Verdict.FAIL,
                                "CONFIRMED anonymously listable: " + detail, {"status": status})
        if status in (401, 403):
            return MethodResult(Method.EXPOSURE, Verdict.PASS,
                                "anonymous listing denied: " + detail, {"status": status})
        return MethodResult(Method.EXPOSURE, Verdict.MANUAL, detail, {"status": status})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
