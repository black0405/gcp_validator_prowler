"""cloudsql_instance_postgres_log_min_messages_flag — must be a valid severity level.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_min_messages_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck

_VALID = {
    "debug5", "debug4", "debug3", "debug2", "debug1",
    "info", "notice", "warning", "error", "log", "fatal", "panic",
}


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_min_messages_flag"
    flag_name = "log_min_messages"
    db_family_filter = "POSTGRES"
    absent_is_secure = True           # default 'warning' is acceptable
    prowler_absent_is_secure = True
    requirement_desc = "PostgreSQL flag log_min_messages set to a valid level (>= warning recommended)"

    def secure(self, value):
        return (value or "").lower() in _VALID


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
