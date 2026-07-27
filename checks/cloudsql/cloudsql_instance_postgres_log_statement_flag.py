"""cloudsql_instance_postgres_log_statement_flag — statement logging must be enabled (ddl/mod/all).

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_postgres_log_statement_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_postgres_log_statement_flag"
    flag_name = "log_statement"
    db_family_filter = "POSTGRES"
    absent_is_secure = False          # default 'none' -> nothing logged
    prowler_absent_is_secure = False
    requirement_desc = "PostgreSQL flag log_statement in {ddl, mod, all} (CIS recommends 'ddl')"

    def secure(self, value):
        return (value or "").lower() in ("ddl", "mod", "all")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
