"""cloudsql_instance_postgres_log_min_duration_statement_flag — must be -1 (disabled).

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_min_duration_statement_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_min_duration_statement_flag"
    flag_name = "log_min_duration_statement"
    db_family_filter = "POSTGRES"
    absent_is_secure = True           # default -1 (logging of statement text disabled)
    prowler_absent_is_secure = True
    requirement_desc = "PostgreSQL flag log_min_duration_statement = -1"

    def secure(self, value):
        return (value or "").strip() == "-1"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
