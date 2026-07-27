"""artifacts_container_analysis_enabled — Container Analysis API must be enabled.

Prowler Hub: https://hub.prowler.com/check/artifacts_container_analysis_enabled
"""
from gcpval.service_check import ServiceEnabledCheck


class Check(ServiceEnabledCheck):
    check_id = "artifacts_container_analysis_enabled"
    service = "artifacts"
    api_host = "containeranalysis.googleapis.com"
    want_enabled = True


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
