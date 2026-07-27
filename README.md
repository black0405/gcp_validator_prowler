# gcp_validator — cross-validate Prowler GCP findings

A validation harness that re-checks Prowler's GCP findings with **independent
evidence** so you can separate real issues from false positives. For every
Prowler check it runs up to five methods and reports each verdict side-by-side
plus a consensus and a false-positive / false-negative flag.

## The five validation methods

| # | Method | What it does |
|---|--------|--------------|
| 1 | **API** | A direct, single-resource read of the exact property (`instances.get()`), the authoritative live state. |
| 2 | **Prowler replica** | Re-implements Prowler's exact pass/fail rule, linked to the [Prowler Hub](https://hub.prowler.com/) page for the check. Tells you what Prowler *should* say even without a Prowler file. |
| 3 | **Logs** | Corroborates from **Cloud Audit Logs** — e.g. the last config-change entry that set a database flag. |
| 4 | **Alternate** | A *different* signal or API path (e.g. `backupRuns.list()` instead of the backup setting; assigned IPs instead of the `ipv4Enabled` flag). Divergence between two vantage points is itself a finding. |
| 5 | **Exposure** | For public-exposure checks only: actually tries to reach the resource from the internet (TCP/TLS probe). A successful connect is strong confirmation. |

Not every method applies to every check. A method that does not apply returns
**N/A with a reason** rather than a fabricated verdict.

### How the verdict is formed
- Each applicable method returns `PASS` / `FAIL` / `N/A` / `MANUAL` / `ERROR`.
- **Consensus** = the combination of the *definite* methods (method 2 is excluded
  because it mirrors Prowler and would bias the comparison). Mixed signals lean
  conservative (a confirmed problem outweighs a clean read).
- **Agreement** compares consensus to the Prowler finding:
  - `AGREE` — verdicts match.
  - `LIKELY_FALSE_POSITIVE` — Prowler says FAIL, our evidence says PASS. **← the main thing you're hunting.**
  - `LIKELY_FALSE_NEGATIVE` — Prowler says PASS, our evidence says FAIL.
  - `INCONCLUSIVE` / `NO_PROWLER_FINDING` — not enough signal / nothing to compare.

## Install

```bash
cd gcp_validator
python -m venv .venv && . .venv/bin/activate      # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
```

## Authenticate

The tool only needs **read-only** access, and takes credentials three ways
(first match wins):

```bash
# 1. Pass the service-account JSON key directly:
python run_all.py --key-file /path/to/sa-key.json --prowler out.ocsf.json
#    (project defaults to the key's own project_id if you omit --project)

# 2. Or via the standard env var:
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json

# 3. Or user credentials from gcloud:
gcloud auth application-default login
```

Recommended read roles: `roles/cloudsql.viewer`, `roles/logging.viewer`
(add `roles/viewer` to cover the other services as they come online).

## Usage

```bash
# All implemented checks, compared against a Prowler OCSF or CSV export:
python run_all.py --project MY_PROJECT --prowler prowler-output.ocsf.json -o report.xlsx

# Only Cloud SQL:
python run_all.py -p MY_PROJECT --service cloudsql --prowler out.ocsf.json

# Turn on the method-5 internet probe (makes real outbound connections):
python run_all.py -p MY_PROJECT --service cloudsql --enable-exposure-probe

# List what's implemented:
python run_all.py --list

# Run ONE control by itself (from the gcp_validator directory):
python -m checks.cloudsql.cloudsql_instance_public_access -p MY_PROJECT --prowler out.ocsf.json
```

`--prowler` accepts either Prowler's **OCSF JSON** (`*.ocsf.json`) or a
**CSV** export. Without it, the tool still validates live GCP state and reports
each method's verdict (agreement column shows `NO_PROWLER_FINDING`).

## Output

A `.xlsx` with a **Validation** sheet (one row per resource per check) and a
**Summary** sheet. Columns: check id / service / severity / title / hub link,
resource identity, Prowler status + detail, each method's verdict + detail,
consensus, and the agreement flag (colour-coded). `LIKELY_FALSE_POSITIVE`
rows are highlighted amber.

## Coverage

**All 109 GCP checks across 16 services are implemented** and plug into the
same framework:

| Service | Checks | Service | Checks |
|---------|-------:|---------|-------:|
| compute | 31 | cloudsql | 24 |
| iam | 12 | cloudstorage | 10 |
| logging | 10 | apikeys | 4 |
| dns | 3 | bigquery | 3 |
| kms | 3 | cloudfunction | 2 |
| secretmanager | 2 | dataproc | 1 |
| artifacts | 1 | gemini | 1 |
| gke | 1 | gcr | 1 |

### Checks that need extra input or are best-effort
A few controls cannot be validated purely from project-scoped, read-only API
calls. These are implemented honestly — they run what they can and mark the
rest `MANUAL` / `N/A` with a reason rather than guessing:

- **`compute_public_address_shodan`** — needs `SHODAN_API_KEY` for methods 1/2;
  method 5 still probes ports directly.
- **`cloudstorage_uses_vpc_service_controls`**, **`iam_organization_essential_contacts_configured`**
  — VPC-SC perimeters and Essential Contacts are org-level; project creds see
  only a partial picture (reported `MANUAL` / best-effort proxy).
- **`iam_service_account_unused`**, **`iam_sa_user_managed_key_unused`** — "unused"
  needs last-authentication data, so method 3 (Cloud Audit Logs) is the real
  signal; method 1 reports `MANUAL`.
- **`logging_log_metric_filter_and_alert_*`** — matched by filter-substring
  heuristics against your log-based metrics + Monitoring alert policies; verify
  the pattern against your naming if a result looks off.
- **`gemini_api_disabled`**, other service-enablement checks — asserted via the
  Service Usage API; confirm the pass direction on the hub page for your Prowler
  version.

Method-specific notes and the exact predicate live in each check file's
docstring, alongside its Prowler Hub link.

## Adding a check

1. Create `checks/<service>/<check_id>.py`.
2. Subclass `gcpval.base_check.BaseCheck` (or a service base like
   `checks.cloudsql._base.CloudSqlCheck`), set `check_id`, implement
   `discover_resources()` and whichever of `api_check` / `prowler_replica_check`
   / `logs_check` / `alternate_check` / `exposure_check` apply.
3. That's it — `run_all.py` discovers it automatically, and
   `python -m checks.<service>.<check_id>` runs it standalone.
