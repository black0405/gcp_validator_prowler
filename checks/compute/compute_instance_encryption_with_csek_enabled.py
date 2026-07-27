"""compute_instance_encryption_with_csek_enabled — attached disks use customer-supplied keys.

Prowler Hub: https://hub.prowler.com/check/compute_instance_encryption_with_csek_enabled
"""
from checks.compute._base import ComputeInstanceCheck


class Check(ComputeInstanceCheck):
    check_id = "compute_instance_encryption_with_csek_enabled"

    def evaluate(self, ctx, res):
        disks = res["instance"].get("disks", []) or []
        if not disks:
            return False, "instance has no attached disks", {"disks": 0}
        without = [d.get("deviceName") or d.get("source", "")
                   for d in disks if not (d.get("diskEncryptionKey") or {}).get("sha256")
                   and not (d.get("diskEncryptionKey") or {}).get("kmsKeyName")]
        ok = not without
        return ok, "disks without a customer-supplied encryption key: " + (str(without) if without else "none"), {"unencrypted": without}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
