"""cloudsql_instance_sqlserver_external_scripts_enabled_flag — must be off.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_external_scripts_enabled_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_external_scripts_enabled_flag"
    flag_name = "external scripts enabled"
    db_family_filter = "SQLSERVER"
    absent_is_secure = True           # default off
    prowler_absent_is_secure = True
    requirement_desc = "SQL Server flag 'external scripts enabled' = off"

    def secure(self, value):
        return (value or "").lower() == "off"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
