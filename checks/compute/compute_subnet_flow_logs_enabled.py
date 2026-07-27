"""compute_subnet_flow_logs_enabled — VPC subnets must have VPC Flow Logs enabled.

Prowler Hub: https://hub.prowler.com/check/compute_subnet_flow_logs_enabled
"""
from checks.compute._base import ComputeSubnetCheck
from gcpval.models import Method, MethodResult

# Proxy-only / special-purpose subnets cannot have flow logs.
_NO_FLOWLOG_PURPOSES = {
    "INTERNAL_HTTPS_LOAD_BALANCER", "REGIONAL_MANAGED_PROXY",
    "GLOBAL_MANAGED_PROXY", "PRIVATE_SERVICE_CONNECT",
}


class Check(ComputeSubnetCheck):
    check_id = "compute_subnet_flow_logs_enabled"

    def _skip(self, method, subnet):
        purpose = str(subnet.get("purpose", "")).upper()
        if purpose in _NO_FLOWLOG_PURPOSES:
            return MethodResult.na(method, f"subnet purpose={purpose}, flow logs not applicable")
        return None

    def evaluate(self, ctx, res):
        enabled = bool(res["subnet"].get("enableFlowLogs"))
        return enabled, f"enableFlowLogs={enabled}", {"enabled": enabled}

    def api_check(self, ctx, res) -> MethodResult:
        return self._skip(Method.API, res["subnet"]) or super().api_check(ctx, res)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return self._skip(Method.PROWLER_REPLICA, res["subnet"]) or super().prowler_replica_check(ctx, res)


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
