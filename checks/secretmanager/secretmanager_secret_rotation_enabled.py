"""secretmanager_secret_rotation_enabled — secret must have rotation configured.

Prowler Hub: https://hub.prowler.com/check/secretmanager_secret_rotation_enabled
"""
from checks.secretmanager._base import SecretCheck


class Check(SecretCheck):
    check_id = "secretmanager_secret_rotation_enabled"

    def evaluate(self, ctx, res):
        rotation = res["secret"].get("rotation") or {}
        period = rotation.get("rotationPeriod", "")
        nxt = rotation.get("nextRotationTime", "")
        ok = bool(period or nxt)
        return ok, f"rotation.rotationPeriod={period or 'unset'}, nextRotationTime={nxt or 'unset'}", {"rotation": rotation}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
