"""cloudsql_instance_sqlserver_user_connections_flag — 'user connections' should be 0.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_user_connections_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_user_connections_flag"
    flag_name = "user connections"
    db_family_filter = "SQLSERVER"
    absent_is_secure = True           # default 0 (no limit imposed by the flag)
    prowler_absent_is_secure = True
    requirement_desc = "SQL Server flag 'user connections' = 0"

    def secure(self, value):
        return (value or "").strip() == "0"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
