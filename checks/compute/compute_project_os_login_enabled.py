"""compute_project_os_login_enabled — project metadata enable-oslogin must be true.

Prowler Hub: https://hub.prowler.com/check/compute_project_os_login_enabled
"""
from checks.compute._base import ComputeProjectCheck, metadata_items


class Check(ComputeProjectCheck):
    check_id = "compute_project_os_login_enabled"

    def evaluate(self, ctx, res):
        meta = metadata_items(res["project_obj"].get("commonInstanceMetadata", {}))
        val = meta.get("enable-oslogin", "")
        ok = str(val).lower() == "true"
        return ok, f"commonInstanceMetadata enable-oslogin={val or 'not set'}", {"value": val}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
