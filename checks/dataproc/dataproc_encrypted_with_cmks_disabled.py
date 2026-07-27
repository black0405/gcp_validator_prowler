"""dataproc_encrypted_with_cmks_disabled — clusters should use CMEK for disk encryption.

Prowler Hub: https://hub.prowler.com/check/dataproc_encrypted_with_cmks_disabled
"""
from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class Check(ResourceCheck):
    check_id = "dataproc_encrypted_with_cmks_disabled"
    service = "dataproc"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        dp = ctx.clients.dataproc()
        compute = ctx.clients.compute()
        out: List[Dict[str, Any]] = []
        regions = [r["name"] for r in
                   compute.regions().list(project=ctx.project).execute().get("items", []) or []]
        for region in regions:
            try:
                resp = dp.projects().regions().clusters().list(
                    projectId=ctx.project, region=region).execute()
            except Exception:  # noqa: BLE001 - region may not be enabled for Dataproc
                continue
            for c in resp.get("clusters", []) or []:
                out.append({
                    "id": c.get("clusterUuid") or c.get("clusterName"),
                    "name": c.get("clusterName"), "region": region,
                    "project": ctx.project, "cluster": c,
                })
        return out

    def evaluate(self, ctx, res):
        enc = ((res["cluster"].get("config") or {}).get("encryptionConfig") or {})
        key = enc.get("gcePdKmsKeyName", "")
        return bool(key), f"config.encryptionConfig.gcePdKmsKeyName={key or 'not set (Google-managed)'}", {"kms_key": key}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
