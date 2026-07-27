"""iam_cloud_asset_inventory_enabled — Cloud Asset Inventory API must be enabled.

Prowler Hub: https://hub.prowler.com/check/iam_cloud_asset_inventory_enabled
"""
from gcpval.service_check import ServiceEnabledCheck


class Check(ServiceEnabledCheck):
    check_id = "iam_cloud_asset_inventory_enabled"
    service = "iam"
    api_host = "cloudasset.googleapis.com"
    want_enabled = True


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
