"""gemini_api_disabled — the Gemini for Google Cloud (Cloud AI Companion) API state.

Prowler Hub: https://hub.prowler.com/check/gemini_api_disabled

The control id asserts the API should be *disabled* when unused; compliant when
the service is DISABLED. Confirm against the hub page for your Prowler version.
"""
from gcpval.service_check import ServiceEnabledCheck


class Check(ServiceEnabledCheck):
    check_id = "gemini_api_disabled"
    service = "gemini"
    api_host = "cloudaicompanion.googleapis.com"
    want_enabled = False   # compliant when the API is DISABLED


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
