# Manual verification playbook — INCONCLUSIVE checks (GCP)

`INCONCLUSIVE` means the tool **ran** but could not reach a definite PASS/FAIL
because the signal isn't available from a simple read-only API call (external
data, org-level data, or last-usage/activity data). These are the checks to
verify by hand — and the natural candidates to automate next.

> Not to be confused with **NOT_EVALUATED** (orange), which means the check
> couldn't run at all (auth/permission/API-disabled) — fix access, then re-run.

## General recipe (for any INCONCLUSIVE row)
1. Open the **Prowler Hub Link** in that row to see Prowler's exact pass/fail rule.
2. Reproduce it manually with the console path / `gcloud` command below.
3. To automate: add the read to the check's `evaluate()` (or the relevant
   `*_check` method) in `checks/<service>/<id>.py`, and grant the listed IAM role.
   Then that row starts returning a definite verdict instead of INCONCLUSIVE.

Set your project once: `PROJECT=prod-grc-project` (and `gcloud config set project $PROJECT`).

---

## 1. `compute_public_address_shodan`
**Rule:** external IPs should not be exposed / indexed by Shodan.
**Why inconclusive:** needs the Shodan API (external) — no `SHODAN_API_KEY`, and
the internet probe is off by default.

**Manual verify**
```bash
# a) enumerate public IPs (reserved + ephemeral)
gcloud compute addresses list --filter="addressType=EXTERNAL AND status=IN_USE" \
  --format="table(address,region,users.basename())"
gcloud compute instances list \
  --format="value(name,networkInterfaces[].accessConfigs[].natIP)"

# b) check each IP in Shodan
#    UI:  https://www.shodan.io/host/<IP>
#    API: curl "https://api.shodan.io/shodan/host/<IP>?key=YOUR_KEY"
```
Judge: any unexpected open ports/services listed = fail.

**Automate (already supported):**
- Set `SHODAN_API_KEY=...` → method 1 queries Shodan and returns a definite verdict.
- Or run with `--enable-exposure-probe` → method 5 does a direct TCP probe of common ports.

---

## 2. `cloudstorage_uses_vpc_service_controls`
**Rule:** the project/bucket is protected by a VPC Service Controls perimeter that
restricts `storage.googleapis.com`.
**Why inconclusive:** VPC-SC perimeters live at the **organization** level (Access
Context Manager); project-scoped credentials can't see them.

**Manual verify**
```bash
# Console: Security → VPC Service Controls (select the org). Confirm the project
# is inside a perimeter whose "Restricted services" include Cloud Storage.

# CLI:
ORG_ID=$(gcloud organizations list --format="value(ID)" | head -1)
POLICY=$(gcloud access-context-manager policies list --organization=$ORG_ID --format="value(name)")
gcloud access-context-manager perimeters list --policy=$POLICY \
  --format="table(title, status.resources.list(), status.restrictedServices.list())"
```
Judge: pass if a perimeter's `resources` include `projects/<PROJECT_NUMBER>` **and**
`restrictedServices` include `storage.googleapis.com`.

**Automate:** grant the SA `roles/accesscontextmanager.policyReader` at the org,
add an `--access-policy <id>` (or `--organization`) flag, then in the check query
`accesscontextmanager.accessPolicies.servicePerimeters.list` and test membership +
restricted service. (Same pattern applies to any future VPC-SC check.)

---

## 3. `iam_service_account_unused`
**Rule:** flag service accounts with no recent authentication activity.
**Why inconclusive:** "last used" is not a property of the SA object.

**Manual verify** (any one)
```bash
# a) Recommender (cleanest — Google computes "unused SA" directly):
gcloud recommender recommendations list --project=$PROJECT --location=global \
  --recommender=google.iam.serviceAccount.ChangeRecommender \
  --format="table(content.overview.member, content.overview.confidence)"

# b) Audit logs (no auth events in 90d ⇒ appears unused):
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="SA_EMAIL"' \
  --freshness=90d --limit=1 --project=$PROJECT

# c) Console: IAM & Admin → Service Accounts → column "Last used".
```

**Automate:** the tool's **method 3 already does (b)** — grant `roles/logging.viewer`
and this row becomes a definite PASS/FAIL. For a stronger signal, add the
Recommender API (a) and grant `roles/recommender.iamViewer`.

---

## 4. `iam_sa_user_managed_key_unused`
**Rule:** user-managed SA keys that aren't being used should be removed.
**Why inconclusive:** key last-use isn't on the key object.

**Manual verify**
```bash
# list user-managed keys on an SA:
gcloud iam service-accounts keys list --iam-account=SA_EMAIL --managed-by=user \
  --format="table(name.basename(), validAfterTime)"

# key authentication events in the last 90 days (none ⇒ appears unused):
gcloud logging read \
  'protoPayload.authenticationInfo.serviceAccountKeyName:"SA_EMAIL"' \
  --freshness=90d --limit=1 --project=$PROJECT
```

**Automate:** the tool's **method 3 already does the log query** — grant
`roles/logging.viewer` and this becomes definite.

---

## Bonus — confirming *exposure* for the public-access checks
`cloudsql_instance_public_access`, `cloudsql_instance_public_ip`,
`compute_instance_public_ip`, and `cloudstorage_bucket_public_access` already
return a **definite** verdict from config (method 1), so they are **not**
INCONCLUSIVE. Their method 5 ("exposure") is the only manual bit — it just adds
extra proof by trying to reach the resource:

```bash
# run with a real internet probe (makes outbound connections):
python run_all.py --key-file key.json --prowler out.ocsf.json --enable-exposure-probe
```
Use this when an auditor wants empirical proof of reachability, not just config.

---

## Summary — what unlocks each

| Check | Becomes automatic when you… |
|---|---|
| `compute_public_address_shodan` | set `SHODAN_API_KEY`, or use `--enable-exposure-probe` |
| `iam_service_account_unused` | grant `roles/logging.viewer` (method 3); optional `roles/recommender.iamViewer` |
| `iam_sa_user_managed_key_unused` | grant `roles/logging.viewer` (method 3) |
| `cloudstorage_uses_vpc_service_controls` | grant org `roles/accesscontextmanager.policyReader` + pass `--access-policy` (needs a code addition) |

So three of the four are unlocked purely by **granting the right read role** —
no code change — and the fourth needs a small addition to query Access Context
Manager.
