"""apikeys_api_restricted_with_gemini_api — keys must be API-restricted (an
unrestricted key can reach the Gemini / Generative Language API).

Prowler Hub: https://hub.prowler.com/check/apikeys_api_restricted_with_gemini_api
"""
from checks.apikeys._base import ApiKeysCheck

# APIs that expose Gemini / generative models.
_GEMINI_APIS = {"generativelanguage.googleapis.com", "aiplatform.googleapis.com",
                "cloudaicompanion.googleapis.com"}


class Check(ApiKeysCheck):
    check_id = "apikeys_api_restricted_with_gemini_api"

    def evaluate(self, ctx, res):
        restrictions = res["key"].get("restrictions") or {}
        targets = [t.get("service", "") for t in restrictions.get("apiTargets", []) or []]
        if not targets:
            # Unrestricted key can call any enabled API, including Gemini.
            return False, "key is unrestricted (can call the Gemini API)", {"api_targets": []}
        # Restricted: compliant unless it explicitly allows a Gemini API.
        allows_gemini = any(t in _GEMINI_APIS for t in targets)
        return (not allows_gemini,
                f"restricted apiTargets={targets}; grants Gemini API access: {allows_gemini}",
                {"api_targets": targets, "allows_gemini": allows_gemini})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
