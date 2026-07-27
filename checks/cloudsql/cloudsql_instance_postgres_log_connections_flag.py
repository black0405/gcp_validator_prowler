"""cloudsql_instance_postgres_log_connections_flag — PostgreSQL log_connections must be on.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_connections_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_connections_flag"
    flag_name = "log_connections"
    db_family_filter = "POSTGRES"
    absent_is_secure = False          # default off -> must be enabled
    prowler_absent_is_secure = False
    requirement_desc = "PostgreSQL flag log_connections = on"

    def secure(self, value):
        return (value or "").lower() == "on"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
