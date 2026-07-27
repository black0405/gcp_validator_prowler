"""apikeys_key_exists — flags the existence of API keys (prefer service accounts).

Prowler Hub: https://hub.prowler.com/check/apikeys_key_exists
"""
from checks.apikeys._base import ApiKeysCheck
from gcpval.context import ValidationContext
from gcpval.models import Method, MethodResult


class Check(ApiKeysCheck):
    check_id = "apikeys_key_exists"

    def discover_resources(self, ctx: ValidationContext):
        # Project-scoped: a single row summarising key existence.
        keys = self._list_keys(ctx)
        return [{"id": ctx.project, "name": ctx.project, "project": ctx.project,
                 "region": "global", "keys": keys}]

    def evaluate(self, ctx, res):
        keys = res["keys"]
        names = [k.get("displayName") or str(k.get("name", "")).split("/")[-1] for k in keys]
        ok = len(keys) == 0
        return ok, f"{len(keys)} API key(s) present: {names or 'none'}", {"count": len(keys), "keys": names}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
