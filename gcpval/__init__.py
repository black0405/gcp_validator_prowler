"""gcpval — a validation framework that cross-checks Prowler GCP findings.

For every Prowler finding it runs up to five independent validation methods
(direct API, Prowler-logic replica, Cloud Audit Logs, an alternate signal, and
an internet-exposure probe) and reports each verdict side-by-side plus a
consensus, so real issues can be separated from false positives.
"""

__version__ = "0.1.0"
