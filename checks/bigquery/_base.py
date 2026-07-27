"""Shared bases for BigQuery checks (dataset and table discovery)."""
from __future__ import annotations

from typing import Any, Dict, List

from gcpval.resource_check import ResourceCheck
from gcpval.context import ValidationContext


class BigQueryDatasetCheck(ResourceCheck):
    service = "bigquery"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        bq = ctx.clients.bigquery()
        out: List[Dict[str, Any]] = []
        req = bq.datasets().list(projectId=ctx.project, all=True)
        while req is not None:
            resp = req.execute()
            for d in resp.get("datasets", []) or []:
                ds_id = d.get("datasetReference", {}).get("datasetId") or d.get("id", "").split(":")[-1]
                full = bq.datasets().get(projectId=ctx.project, datasetId=ds_id).execute()
                out.append({
                    "id": full.get("id") or ds_id, "name": ds_id,
                    "region": full.get("location", ""), "project": ctx.project,
                    "dataset": full,
                })
            req = bq.datasets().list_next(req, resp)
        return out


class BigQueryTableCheck(ResourceCheck):
    service = "bigquery"

    def discover_resources(self, ctx: ValidationContext) -> List[Dict[str, Any]]:
        bq = ctx.clients.bigquery()
        out: List[Dict[str, Any]] = []
        dreq = bq.datasets().list(projectId=ctx.project, all=True)
        while dreq is not None:
            dresp = dreq.execute()
            for d in dresp.get("datasets", []) or []:
                ds_id = d.get("datasetReference", {}).get("datasetId") or d.get("id", "").split(":")[-1]
                treq = bq.tables().list(projectId=ctx.project, datasetId=ds_id)
                while treq is not None:
                    tresp = treq.execute()
                    for t in tresp.get("tables", []) or []:
                        tbl_id = t.get("tableReference", {}).get("tableId", "")
                        full = bq.tables().get(
                            projectId=ctx.project, datasetId=ds_id, tableId=tbl_id).execute()
                        out.append({
                            "id": full.get("id") or f"{ds_id}.{tbl_id}",
                            "name": f"{ds_id}.{tbl_id}",
                            "region": full.get("location", ""), "project": ctx.project,
                            "table": full,
                        })
                    treq = bq.tables().list_next(treq, tresp)
            dreq = bq.datasets().list_next(dreq, dresp)
        return out
