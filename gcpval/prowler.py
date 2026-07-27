"""Parse a Prowler output file (OCSF JSON or CSV) into an index of findings.

Supports both OCSF classes Prowler emits (DetectionFinding 2004 and
ComplianceFinding 2003) and the flat CSV export. Findings are indexed by
check id so a check can pull every finding Prowler produced for it.
"""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Verdict


@dataclass
class ProwlerFinding:
    check_id: str
    status: Verdict            # PASS / FAIL (MANUAL kept as MANUAL)
    status_detail: str
    resource_uid: str
    resource_name: str
    region: str
    project: str
    severity: str = ""
    raw_status: str = ""

    @property
    def resource_key(self) -> str:
        """Best-effort stable key to match against a live GCP resource."""
        return self.resource_name or self.resource_uid


def _status(code: str) -> Verdict:
    c = (code or "").strip().upper()
    if c in ("PASS", "PASSED"):
        return Verdict.PASS
    if c in ("FAIL", "FAILED"):
        return Verdict.FAIL
    if c in ("MANUAL",):
        return Verdict.MANUAL
    return Verdict.NA


class ProwlerReport:
    def __init__(self, findings: List[ProwlerFinding]):
        self.findings = findings
        self._by_check: Dict[str, List[ProwlerFinding]] = {}
        for f in findings:
            self._by_check.setdefault(f.check_id, []).append(f)

    def for_check(self, check_id: str) -> List[ProwlerFinding]:
        return self._by_check.get(check_id, [])

    def check_ids(self) -> List[str]:
        return sorted(self._by_check)

    def __len__(self) -> int:
        return len(self.findings)

    # ---- loaders -------------------------------------------------------
    @classmethod
    def load(cls, path: str) -> "ProwlerReport":
        if not path:
            return cls([])
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            return cls(cls._from_ocsf(path))
        if ext == ".csv":
            return cls(cls._from_csv(path))
        # Fall back to sniffing the first non-space char.
        with open(path, "r", encoding="utf-8-sig") as fh:
            head = fh.read(1)
        return cls(cls._from_ocsf(path) if head == "[" else cls._from_csv(path))

    @staticmethod
    def _from_ocsf(path: str) -> List[ProwlerFinding]:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = data.get("findings") or data.get("data") or [data]
        out: List[ProwlerFinding] = []
        for item in data:
            out.append(ProwlerReport._parse_ocsf_item(item))
        return [f for f in out if f.check_id]

    @staticmethod
    def _parse_ocsf_item(item: dict) -> ProwlerFinding:
        meta = item.get("metadata", {}) or {}
        check_id = meta.get("event_code", "")
        # Fallbacks for the check id.
        if not check_id:
            comp = item.get("compliance", {}) or {}
            checks = comp.get("checks") or []
            if checks:
                check_id = checks[0].get("uid", "")
        cloud = (item.get("unmapped", {}) or {}).get("cloud", {}) or {}
        # DetectionFinding puts cloud under "cloud" at top level in some versions.
        if not cloud and isinstance(item.get("cloud"), dict):
            cloud = item["cloud"]
        account = cloud.get("account", {}) or {}
        project = account.get("uid", "") or account.get("name", "")
        region = cloud.get("region", "")

        resources = item.get("resources") or []
        res_uid = res_name = ""
        if resources:
            r0 = resources[0]
            res_uid = r0.get("uid", "") or (r0.get("data", {}) or {}).get("metadata", {}).get("id", "")
            res_name = r0.get("name", "") or (r0.get("data", {}) or {}).get("metadata", {}).get("name", "")
            region = r0.get("region", region)

        return ProwlerFinding(
            check_id=check_id,
            status=_status(item.get("status_code", "")),
            status_detail=item.get("status_detail", "") or item.get("message", ""),
            resource_uid=res_uid,
            resource_name=res_name,
            region=region,
            project=project,
            severity=item.get("severity", ""),
            raw_status=item.get("status_code", ""),
        )

    @staticmethod
    def _from_csv(path: str) -> List[ProwlerFinding]:
        out: List[ProwlerFinding] = []
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            # Prowler CSVs are ';'-delimited; sniff to be safe.
            sample = fh.read(4096)
            fh.seek(0)
            delim = ";" if sample.count(";") >= sample.count(",") else ","
            reader = csv.DictReader(fh, delimiter=delim)
            norm = lambda k: (k or "").strip().upper()
            for row in reader:
                row = {norm(k): (v or "") for k, v in row.items()}
                check_id = row.get("CHECK_ID") or row.get("CHECKID") or ""
                if not check_id:
                    continue
                out.append(ProwlerFinding(
                    check_id=check_id,
                    status=_status(row.get("STATUS") or row.get("STATUS_CODE") or ""),
                    status_detail=row.get("STATUS_EXTENDED") or row.get("STATUSEXTENDED") or "",
                    resource_uid=row.get("RESOURCE_UID") or row.get("RESOURCEID") or "",
                    resource_name=row.get("RESOURCE_NAME") or row.get("RESOURCENAME") or "",
                    region=row.get("REGION") or row.get("LOCATION") or "",
                    project=row.get("PROJECT_ID") or row.get("SUBSCRIPTIONID") or row.get("ACCOUNT_UID") or "",
                    severity=row.get("SEVERITY") or "",
                    raw_status=row.get("STATUS") or "",
                ))
        return out
