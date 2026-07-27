"""gcr_container_scanning_enabled — Container Scanning API must be enabled.

Prowler Hub: https://hub.prowler.com/check/gcr_container_scanning_enabled
"""
from gcpval.service_check import ServiceEnabledCheck


class Check(ServiceEnabledCheck):
    check_id = "gcr_container_scanning_enabled"
    service = "gcr"
    api_host = "containerscanning.googleapis.com"
    want_enabled = True


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
