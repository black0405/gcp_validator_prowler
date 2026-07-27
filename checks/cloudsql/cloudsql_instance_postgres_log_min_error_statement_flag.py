"""cloudsql_instance_postgres_log_min_error_statement_flag — must be 'error'.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_min_error_statement_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_min_error_statement_flag"
    flag_name = "log_min_error_statement"
    db_family_filter = "POSTGRES"
    absent_is_secure = True           # server default is 'error'
    prowler_absent_is_secure = True
    requirement_desc = "PostgreSQL flag log_min_error_statement = error"

    def secure(self, value):
        return (value or "").lower() == "error"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
