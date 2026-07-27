"""compute_instance_default_service_account_in_use_with_full_api_access —
default compute SA + cloud-platform scope is the worst case.

Prowler Hub: https://hub.prowler.com/check/compute_instance_default_service_account_in_use_with_full_api_access
"""
from checks.compute._base import ComputeInstanceCheck, DEFAULT_SA_SUFFIX, CLOUD_PLATFORM_SCOPE


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_default_service_account_in_use_with_full_api_access"

    def evaluate(self, ctx, res):
        offending = []
        for s in res["instance"].get("serviceAccounts", []) or []:
            email = s.get("email", "")
            scopes = s.get("scopes", []) or []
            if email.endswith(DEFAULT_SA_SUFFIX) and CLOUD_PLATFORM_SCOPE in scopes:
                offending.append(email)
        return (not offending,
                "default SA with cloud-platform scope: " + (str(offending) if offending else "none"),
                {"offending": offending})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
