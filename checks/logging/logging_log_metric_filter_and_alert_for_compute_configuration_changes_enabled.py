"""logging ... compute configuration changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled"
    required_all = ["gce_instance"]
    required_any = ["compute.instances."]
    pattern_desc = 'resource.type="gce_instance" AND compute.instances.*'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
