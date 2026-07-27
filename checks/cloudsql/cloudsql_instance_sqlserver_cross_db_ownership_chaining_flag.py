"""cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag — must be off.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag"
    flag_name = "cross db ownership chaining"
    db_family_filter = "SQLSERVER"
    absent_is_secure = True           # SQL Server default is off
    prowler_absent_is_secure = True
    requirement_desc = "SQL Server flag 'cross db ownership chaining' = off"

    def secure(self, value):
        return (value or "").lower() == "off"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
