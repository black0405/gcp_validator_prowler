"""cloudsql_instance_mysql_skip_show_database_flag — MySQL skip_show_database must be on.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_mysql_skip_show_database_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_mysql_skip_show_database_flag"
    flag_name = "skip_show_database"
    db_family_filter = "MYSQL"
    absent_is_secure = False          # default off -> insecure
    prowler_absent_is_secure = False
    requirement_desc = "MySQL flag skip_show_database = on"

    def secure(self, value):
        return (value or "").lower() == "on"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
