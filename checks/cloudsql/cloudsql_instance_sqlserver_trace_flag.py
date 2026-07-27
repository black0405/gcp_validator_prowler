"""cloudsql_instance_sqlserver_trace_flag — trace flag 3625 must be on.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_sqlserver_trace_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_sqlserver_trace_flag"
    flag_name = "3625"
    db_family_filter = "SQLSERVER"
    absent_is_secure = False          # 3625 must be explicitly enabled
    prowler_absent_is_secure = False
    requirement_desc = "SQL Server trace flag '3625' = on"

    def secure(self, value):
        return (value or "").lower() == "on"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
