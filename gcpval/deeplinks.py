"""Build GCP Cloud Console deep-links per finding (for audit evidence)."""
from __future__ import annotations

from .models import CheckResult, ResourceResult

_BASE = "https://console.cloud.google.com"


def console_link(cr: CheckResult, rr: ResourceResult, project: str = "") -> str:
    project = project or rr.project
    q = f"?project={project}" if project else ""
    name = rr.resource_name
    svc = cr.service
    if svc == "cloudsql" and name:
        return f"{_BASE}/sql/instances/{name}/overview{q}"
    if svc == "cloudstorage" and name:
        return f"{_BASE}/storage/browser/{name}{q}"
    if svc == "compute":
        return f"{_BASE}/compute/instances{q}"
    if svc == "iam":
        return f"{_BASE}/iam-admin/iam{q}"
    if svc == "kms":
        return f"{_BASE}/security/kms/keyrings{q}"
    if svc == "bigquery":
        return f"{_BASE}/bigquery{q}"
    if svc == "dns":
        return f"{_BASE}/net-services/dns/zones{q}"
    if svc == "secretmanager":
        return f"{_BASE}/security/secret-manager{q}"
    if svc == "cloudfunction":
        return f"{_BASE}/functions/list{q}"
    if svc == "gke":
        return f"{_BASE}/kubernetes/list{q}"
    if svc == "gcr" or svc == "artifacts":
        return f"{_BASE}/artifacts{q}"
    if svc == "logging":
        return f"{_BASE}/logs/metrics{q}"
    if svc == "apikeys":
        return f"{_BASE}/apis/credentials{q}"
    if svc == "dataproc":
        return f"{_BASE}/dataproc/clusters{q}"
    return f"{_BASE}/home/dashboard{q}"
