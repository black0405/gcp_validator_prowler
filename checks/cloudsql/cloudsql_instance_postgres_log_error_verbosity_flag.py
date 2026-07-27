"""cloudsql_instance_postgres_log_error_verbosity_flag — log_error_verbosity = default/verbose.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_error_verbosity_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_error_verbosity_flag"
    flag_name = "log_error_verbosity"
    db_family_filter = "POSTGRES"
    # Server default is 'default', which already satisfies the requirement.
    absent_is_secure = True
    prowler_absent_is_secure = True
    requirement_desc = "PostgreSQL flag log_error_verbosity in {default, verbose}"

    def secure(self, value):
        return (value or "").lower() in ("default", "verbose")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
