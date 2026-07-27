"""cloudsql_instance_sqlserver_contained_database_authentication_flag — must be off.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_contained_database_authentication_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_contained_database_authentication_flag"
    flag_name = "contained database authentication"
    db_family_filter = "SQLSERVER"
    absent_is_secure = True           # default off
    prowler_absent_is_secure = True
    requirement_desc = "SQL Server flag 'contained database authentication' = off"

    def secure(self, value):
        return (value or "").lower() == "off"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
