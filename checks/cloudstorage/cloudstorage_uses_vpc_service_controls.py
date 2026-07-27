"""cloudstorage_uses_vpc_service_controls — GCS protected by a VPC-SC perimeter.

Prowler Hub: https://hub.prowler.com/check/cloudstorage_uses_vpc_service_controls

VPC Service Controls perimeters live at the *organization* level in Access
Context Manager and require org-level read access that project-scoped
credentials usually lack, so this is reported for manual review with a best-
effort automated attempt.
"""
from checks.cloudstorage._base import ProjectScopedCheck
from gcpval.models import Method, MethodResult, Verdict


class Check(ProjectScopedCheck):
    check_id = "cloudstorage_uses_vpc_service_controls"
    service = "cloudstorage"

    def _perimeter_signal(self, ctx):
        """Best-effort: try Access Context Manager, requires org access."""
        try:
            acm = ctx.clients.discovery("accesscontextmanager", "v1")
            # Need the org's access policy; without org id we cannot enumerate.
            return None, "org access policy id unknown for project-scoped creds"
        except Exception as exc:  # noqa: BLE001
            return None, f"Access Context Manager unavailable: {exc}"

    def api_check(self, ctx, res) -> MethodResult:
        _, why = self._perimeter_signal(ctx)
        return MethodResult(
            Method.API, Verdict.MANUAL,
            "VPC-SC perimeters are org-level; verify in Access Context Manager. " + why)

    def prowler_replica_check(self, ctx, res) -> MethodResult:
        return MethodResult(
            Method.PROWLER_REPLICA, Verdict.MANUAL,
            f"Prowler rule ({self.hub_link}): PASS when the project sits inside a "
            f"VPC-SC perimeter protecting storage.googleapis.com — requires org read access")


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
