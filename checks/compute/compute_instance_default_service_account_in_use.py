"""compute_instance_default_service_account_in_use — VMs should not use the default compute SA.

Prowler Hub: https://hub.prowler.com/check/compute_instance_default_service_account_in_use
"""
from checks.compute._base import ComputeInstanceCheck, DEFAULT_SA_SUFFIX


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_default_service_account_in_use"

    def evaluate(self, ctx, res):
        sas = [s.get("email", "") for s in res["instance"].get("serviceAccounts", []) or []]
        default_used = any(e.endswith(DEFAULT_SA_SUFFIX) for e in sas)
        return (not default_used, f"attached service accounts={sas or 'none'}", {"service_accounts": sas})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
