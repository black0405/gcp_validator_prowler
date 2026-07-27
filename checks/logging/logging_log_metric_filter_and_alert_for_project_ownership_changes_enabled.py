"""logging ... project ownership changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled"
    required_all = ["cloudresourcemanager.googleapis.com"]
    required_any = ["projectownership", "projectownerinvitee", "roles/owner"]
    pattern_desc = 'cloudresourcemanager AND ProjectOwnership/projectOwnerInvitee/roles/owner'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
