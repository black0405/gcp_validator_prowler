"""cloudfunction_function_inside_vpc — function should route egress through a VPC connector.

Prowler Hub: https://hub.prowler.com/check/cloudfunction_function_inside_vpc
"""
from checks.cloudfunction._base import CloudFunctionCheck


class Check(CloudFunctionCheck):
    check_id = "cloudfunction_function_inside_vpc"

    def evaluate(self, ctx, res):
        svc_cfg = res["function"].get("serviceConfig") or {}
        connector = svc_cfg.get("vpcConnector", "")
        return bool(connector), f"serviceConfig.vpcConnector={connector or 'not set'}", {"vpc_connector": connector}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
