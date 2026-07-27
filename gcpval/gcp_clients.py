"""Lazily-built GCP API clients, shared across checks.

Uses Application Default Credentials (ADC) so it works with either
`gcloud auth application-default login` or a service-account key pointed to by
GOOGLE_APPLICATION_CREDENTIALS. Discovery-based clients (googleapiclient) give
one uniform interface across every GCP service the checks need.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class GcpClients:
    # Read-only scope is enough for validation.
    SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

    def __init__(self, project: str, credentials: Any = None):
        self.project = project
        self._credentials = credentials
        self._discovery: Dict[str, Any] = {}
        self._logging_client = None

    @property
    def credentials(self):
        if self._credentials is None:
            import google.auth
            self._credentials, adc_project = google.auth.default(scopes=self.SCOPES)
            if not self.project:
                self.project = adc_project
        return self._credentials

    def discovery(self, api: str, version: str):
        """Return a cached googleapiclient discovery service (e.g. 'sqladmin','v1')."""
        key = f"{api}:{version}"
        svc = self._discovery.get(key)
        if svc is None:
            from googleapiclient.discovery import build
            svc = build(
                api, version,
                credentials=self.credentials,
                cache_discovery=False,
            )
            self._discovery[key] = svc
        return svc

    # Convenience accessors -------------------------------------------------
    def sqladmin(self):
        return self.discovery("sqladmin", "v1")

    def compute(self):
        return self.discovery("compute", "v1")

    def storage(self):
        return self.discovery("storage", "v1")

    def iam(self):
        return self.discovery("iam", "v1")

    def cloudresourcemanager(self, version: str = "v3"):
        return self.discovery("cloudresourcemanager", version)

    def bigquery(self):
        return self.discovery("bigquery", "v2")

    def cloudkms(self):
        return self.discovery("cloudkms", "v1")

    def dns(self):
        return self.discovery("dns", "v1")

    def secretmanager(self):
        return self.discovery("secretmanager", "v1")

    def cloudfunctions(self):
        return self.discovery("cloudfunctions", "v2")

    def container(self):
        return self.discovery("container", "v1")

    def dataproc(self):
        return self.discovery("dataproc", "v1")

    def serviceusage(self):
        return self.discovery("serviceusage", "v1")

    def project_number(self) -> str:
        """Resolve the numeric project number (needed by some APIs)."""
        crm = self.cloudresourcemanager("v3")
        proj = crm.projects().get(name=f"projects/{self.project}").execute()
        return str(proj.get("name", "")).split("/")[-1] or self.project

    def service_state(self, api_host: str) -> str:
        """Return 'ENABLED' / 'DISABLED' for a service (e.g. 'container.googleapis.com')."""
        su = self.serviceusage()
        name = f"projects/{self.project}/services/{api_host}"
        resp = su.services().get(name=name).execute()
        return str(resp.get("state", "")).upper()

    def logging_client(self):
        """google-cloud-logging client for querying Cloud Audit Logs."""
        if self._logging_client is None:
            from google.cloud import logging as gcloud_logging
            self._logging_client = gcloud_logging.Client(
                project=self.project, credentials=self.credentials
            )
        return self._logging_client


def paginate(request_fn, list_key: str, next_fn) -> List[dict]:
    """Generic pager for googleapiclient list endpoints.

    request_fn() -> initial request; next_fn(prev_request, prev_response) -> next
    request or None; list_key is the response field holding the items.
    """
    items: List[dict] = []
    request = request_fn()
    while request is not None:
        resp = request.execute()
        items.extend(resp.get(list_key, []) or [])
        request = next_fn(request, resp)
    return items
