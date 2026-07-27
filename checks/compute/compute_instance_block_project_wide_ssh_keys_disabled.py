"""compute_instance_block_project_wide_ssh_keys_disabled — block-project-ssh-keys must be true.

Prowler Hub: https://hub.prowler.com/check/compute_instance_block_project_wide_ssh_keys_disabled
"""
from checks.compute._base import ComputeInstanceCheck, metadata_items


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_block_project_wide_ssh_keys_disabled"

    def evaluate(self, ctx, res):
        val = metadata_items(res["instance"].get("metadata", {})).get("block-project-ssh-keys", "")
        ok = str(val).lower() == "true"
        return ok, f"metadata block-project-ssh-keys={val or 'not set'}", {"value": val}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
