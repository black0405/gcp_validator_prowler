"""cloudsql_instance_mysql_local_infile_flag — MySQL local_infile must be off.

Prowler Hub: https://hub.prowler.com/check/cloudsql_instance_mysql_local_infile_flag
"""
from checks.cloudsql._base import CloudSqlFlagCheck


class Check(CloudSqlFlagCheck):
    check_id = "cloudsql_instance_mysql_local_infile_flag"
    flag_name = "local_infile"
    db_family_filter = "MYSQL"
    absent_is_secure = False          # server default is on -> insecure
    prowler_absent_is_secure = False
    requirement_desc = "MySQL flag local_infile = off"

    def secure(self, value):
        return (value or "").lower() == "off"


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
