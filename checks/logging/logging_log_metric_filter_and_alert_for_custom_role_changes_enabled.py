"""logging ... custom role changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_custom_role_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_custom_role_changes_enabled"
    required_all = ["iam_role"]
    required_any = ["createrole", "deleterole", "updaterole"]
    pattern_desc = 'resource.type="iam_role" AND Create/Delete/UpdateRole'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
