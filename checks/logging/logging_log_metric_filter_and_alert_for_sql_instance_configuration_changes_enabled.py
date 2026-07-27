"""logging ... SQL instance configuration changes — metric filter + alert must exist.

Prowler Hub: https://hub.prowler.com/check/logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled
"""
from checks.logging._base import LoggingMetricAlertCheck


class Check(LoggingMetricAlertCheck):
    check_id = "logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled"
    required_all = ["cloudsql_database"]
    required_any = ["cloudsql.instances.update", "cloudsql.instances"]
    pattern_desc = 'resource.type="cloudsql_database" AND cloudsql.instances.update'


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
