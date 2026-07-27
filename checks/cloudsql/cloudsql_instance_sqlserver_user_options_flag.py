"""cloudsql_instance_sqlserver_user_options_flag — the 'user options' flag must NOT be set.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_user_options_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_user_options_flag"
    flag_name = "user options"
    db_family_filter = "SQLSERVER"
    absent_is_secure = True           # compliant precisely when the flag is absent
    prowler_absent_is_secure = True
    requirement_desc = "SQL Server flag 'user options' must not be configured"

    def secure(self, value):
        # Any explicit value is non-compliant.
        return False


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
