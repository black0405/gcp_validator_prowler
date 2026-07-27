"""logging ... bucket permission changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled"
    required_all = ["gcs_bucket"]
    required_any = ["setiampermissions", "setiampolicy"]
    pattern_desc = 'resource.type="gcs_bucket" AND storage.setIamPermissions/SetIamPolicy'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
