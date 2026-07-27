"""apikeys_api_restrictions_configured — each key must restrict which APIs it can call.

Prowler Hub: https://hub.prowler.com/check/apikeys_api_restrictions_configured
"""
from checks.apikeys._base import ApiKeysCheck


class Check(ApiKeysCheck):
    check_id = "apikeys_api_restrictions_configured"

    def evaluate(self, ctx, res):
        restrictions = res["key"].get("restrictions") or {}
        api_targets = restrictions.get("apiTargets", []) or []
        ok = bool(api_targets)
        return ok, f"restrictions.apiTargets configured: {len(api_targets)}", {"api_targets": len(api_targets)}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
