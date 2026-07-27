"""logging ... VPC network changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled"
    required_all = ["gce_network"]
    required_any = ["compute.networks."]
    pattern_desc = 'resource.type="gce_network" AND compute.networks.*'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
