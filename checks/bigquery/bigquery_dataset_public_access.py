"""bigquery_dataset_public_access — dataset must not be shared with allUsers/allAuthenticatedUsers.

Prowler Hub: https://hub.prowler.com/check/bigquery_dataset_public_access
"""
from checks.bigquery._base import BigQueryDatasetCheck

_PUBLIC = {"allUsers", "allAuthenticatedUsers"}


class Check(BigQueryDatasetCheck):
    check_id = "bigquery_dataset_public_access"

    def evaluate(self, ctx, res):
        public = []
        for entry in res["dataset"].get("access", []) or []:
            if entry.get("specialGroup") in _PUBLIC:
                public.append(("specialGroup", entry.get("specialGroup"), entry.get("role")))
            if entry.get("iamMember") in _PUBLIC:
                public.append(("iamMember", entry.get("iamMember"), entry.get("role")))
        return (not public,
                "public access entries: " + (str(public) if public else "none"),
                {"public": public})


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
