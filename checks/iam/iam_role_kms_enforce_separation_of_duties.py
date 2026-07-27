"""iam_role_kms_enforce_separation_of_duties — no principal is both KMS admin and a KMS user.

Prowler Hub: https://hub.prowler.com/check/iam_role_kms_enforce_separation_of_duties
"""
from checks.iam._base import IamProjectCheck

_ADMIN = {"roles/cloudkms.admin"}
_USAGE = {
    "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    "roles/cloudkms.cryptoKeyEncrypter",
    "roles/cloudkms.cryptoKeyDecrypter",
    "roles/cloudkms.signerVerifier",
    "roles/cloudkms.signer",
}


class Check(IamProjectCheck):
    check_id = "iam_role_kms_enforce_separation_of_duties"

    def evaluate(self, ctx, res):
        roles_by_member = self.member_roles(res["policy"])
        violators = [m for m, roles in roles_by_member.items()
                     if (roles & _ADMIN) and (roles & _USAGE)]
        ok = not violators
        return ok, ("principals holding both a KMS admin and a KMS usage role: "
                    + (str(violators) if violators else "none")), {"violators": violators}


if __name__ == "__main__":
    from gcpval.cli import run_single
    run_single(Check)
