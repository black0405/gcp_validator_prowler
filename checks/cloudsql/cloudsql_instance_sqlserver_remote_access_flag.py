"""cloudsql_instance_sqlserver_remote_access_flag — must be off.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_remote_access_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_remote_access_flag"
    flag_name = "remote access"
    db_family_filter = "SQLSERVER"
    absent_is_secure = False          # SQL Server 'remote access' defaults to on (1)
    prowler_absent_is_secure = False
    requirement_desc = "SQL Server flag 'remote access' = off"

    def secure(self, value):
        return (value or "").lower() == "off"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
