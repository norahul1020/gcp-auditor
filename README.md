# GCP Comprehensive Audit Script — README

## What it does
Read-only audit (no resource is ever modified) across Org/Folder/Project scope.
Outputs one CSV with **every finding + a Recommendation column**, plus an HTML view.

Columns: `scope_type, scope_id, resource_type, resource_name, category, check, finding, severity, evidence, recommendation`

## 1. Setup
```bash
gcloud auth login
gcloud auth application-default login   # needed for some asset/recommender calls
sudo apt-get install -y jq python3      # jq required, python3 optional (nicer HTML)
chmod +x gcp_comprehensive_audit.sh
```

## 2. Required IAM roles (grant to the identity running this, at the scope you're auditing)
- `roles/iam.securityReviewer`
- `roles/cloudasset.viewer`
- `roles/recommender.viewer` (per project)
- `roles/logging.viewer` (per project)
- `roles/securitycenter.findingsViewer` (org, only if you want the SCC section — optional)
- `roles/viewer` or `roles/browser` as a general fallback

## 3. Required APIs (per project being audited)
```
cloudasset.googleapis.com recommender.googleapis.com logging.googleapis.com
iam.googleapis.com serviceusage.googleapis.com securitycenter.googleapis.com
```

## 4. Configure & run
Edit the `CONFIGURATION` block at the top of the script, **or** just export env vars:
```bash
export ORG_ID="123456789012"          # org-wide audit (recommended)
# export FOLDER_ID="987654321098"     # OR folder-wide
# export PROJECT_ID="my-project"      # OR single project
# export PROJECTS_OVERRIDE="proj-a proj-b proj-c"   # OR explicit list

export SA_KEY_AGE_DAYS=90
export SA_INACTIVITY_DAYS=90
export LOG_LOOKBACK_DAYS=90
export RUN_SCC_AUDIT=true             # set false if SCC isn't enabled on your org
export RUN_EXTENDED_AUDIT=true        # Section D: network/DR/CI-CD/WIF/governance/manual checklist

# Optional: tune per-call timeouts if you're on a slow network/proxy
export GCLOUD_TIMEOUT=90              # seconds, normal/fast calls (default 90)
export GCLOUD_TIMEOUT_LONG=240        # seconds, slow calls: asset inventory, recommender, multi-region aggregated lists (default 240, auto-retries once doubled on timeout)

# Optional, enable extra Section D checks:
export BILLING_ACCOUNT_ID="012345-6789AB-CDEF01"   # enables billing budget audit
export ACCESS_POLICY_ID="123456789"                 # enables VPC Service Controls perimeter audit

# Optional, enable cost-prioritized auditing (Section F):
export BILLING_EXPORT_TABLE="my-project.billing_dataset.gcp_billing_export_v1_XXXXXX"
export BILLING_LOOKBACK_DAYS=30

./gcp_comprehensive_audit.sh
```

Output goes to `./gcp_audit_<timestamp>/`:
- `gcp_audit_report.csv` — open in Sheets/Excel
- `gcp_audit_report.html` — open in a browser, color-coded by severity
- `raw/` — the actual gcloud JSON evidence backing every finding (your audit trail)
- `run.log` — every command run + any errors/permission denials

## 5. What's covered

**A. IAM**
- All IAM bindings org/folder/project-wide (via Cloud Asset Inventory)
- Primitive role usage (Owner/Editor/Viewer) — over-privilege
- Public/anonymous IAM bindings (allUsers/allAuthenticatedUsers)
- IAM Recommender findings (unused/excessive permissions, 90-day usage based)
- Service account inventory, default SA usage
- Service account key age (user-managed keys) + flags any key present
- **Service account activity via Cloud Audit Logs** — flags SAs with zero logged activity in the lookback window (unused SA detection)
- Custom role review for high-risk permissions (setIamPolicy/delete/admin)

**B. Security**
- Org Policy constraints (SA key creation, OS Login, serial port, uniform bucket access, SQL public IP, domain restriction, etc.)
- VPC firewall rules: internet-exposed (0.0.0.0/0) ingress, risky ports, default-network rules
- Public GCS buckets (IAM-based, via Cloud Asset Inventory)
- Compute instances: public IPs, Shielded VM/Secure Boot, serial port access
- Cloud SQL: public IP, 0.0.0.0/0 authorized networks, SSL enforcement, backups
- KMS key rotation policy
- Logging: missing export sinks, unlocked log buckets
- GKE: private nodes, legacy ABAC, network policy, master authorized networks, Binary Authorization, Workload Identity
- Security Command Center active findings (org-wide, if SCC is enabled)

**C. Services / Misconfiguration / Secrets**
- Enabled API inventory per project (attack-surface review)
- Cloud Run / Cloud Functions: public unauthenticated invocation (allUsers)
- **Hardcoded secret pattern scanning** in Cloud Run/Functions env vars and GCE instance metadata/startup-scripts (AWS-style keys, Slack tokens, private key headers, password=/secret=/apikey= patterns) — values are never logged, only pattern-matched and flagged
- Storage bucket hygiene: uniform bucket-level access, versioning
- Public BigQuery datasets
- Secret Manager adoption (flags projects with zero secrets registered, signaling secrets likely live elsewhere insecurely)

**D. Extended (the "experienced-SRE" additions, beyond what was explicitly asked)**
- Network architecture: legacy default VPC still present, VPC Flow Logs, Private Google Access, Cloud NAT presence, Cloud Armor presence, SSL policy minimum TLS version, SSL certificate expiry, DNSSEC on public Cloud DNS zones
- Backup & DR: persistent disks with no snapshot schedule policy, GKE clusters with no Backup-for-GKE plan
- CI/CD supply chain: Cloud Build default SA still holding Editor, hardcoded secrets in Cloud Build trigger substitutions, public Artifact/Container Registry repos
- Workload Identity Federation: pools/providers inventory, flags WIF providers with no attribute condition (impersonation risk)
- Org governance: Essential Contacts missing SECURITY subscription, billing budgets/alerts missing (also a compromise-detection control, not just FinOps), Resource Manager deletion liens inventory, org-level IAM Deny policy presence
- VPC Service Controls perimeter check (only runs if you set `ACCESS_POLICY_ID`)
- A **manual-process checklist** (LOW severity, category "Process - Governance (manual review)") for things no API can verify: MFA/2FA enforcement, break-glass procedure, vendor/OAuth-app access reviews, IR runbook + tabletop cadence, pentest cadence, data classification/DLP, IaC drift detection, offboarding SLA. These rows are explicitly marked as not log-derived — they're there so the checklist doesn't get lost, not because the script "detected" anything.

**E. Storage & Database deep-dive** (goes beyond the basic checks in B/C)
- GCS: Public Access Prevention enforcement, CMEK vs Google-managed encryption, access logging, locked retention policy
- BigQuery: dataset-level CMEK, default table expiration, a sanity check that BigQuery audit-log activity actually exists if you think it's in use
- Cloud SQL: CMEK, deletion protection, High Availability (regional vs zonal)
- **Cloud Spanner** — public IAM bindings (CRITICAL if found) + informational flag to manually review databases/backups
- **Cloud Bigtable** — public IAM bindings
- **Memorystore (Redis)** — AUTH enabled, in-transit encryption
- **Filestore** — network exposure review flag

**F. Billing/usage-driven scope & coverage-gap detection** (the "audit what you actually pay for" idea)
- If you set `BILLING_EXPORT_TABLE` (a BigQuery Billing Export table), the script queries top services by actual spend over `BILLING_LOOKBACK_DAYS` and lists them — so you can cross-check: anything with real spend should have findings elsewhere in the report; if it doesn't, that's a gap.
- **Without billing export configured**, the script still does usage-driven discovery for free: it pulls every actually-deployed resource via Cloud Asset Inventory, groups by asset type, and explicitly flags any in-use resource type (e.g. Pub/Sub, Dataflow, Composer, Dataproc, Vertex AI, App Engine, Cloud Scheduler, API Gateway) that has **zero dedicated audit coverage** in this script — category `Services - Coverage Gap`. This is the mechanism that stops "we didn't think to check that service" from happening again as your stack grows.

## 6. Known limitations (be aware before you trust a "clean" result)
- **Timeouts (rc=124) on first run are usually transient.** Calls like `sql instances list`, `spanner instances list`, `redis instances list`, `functions list`, `recommender recommendations list`, and the asset-inventory searches now use a longer timeout (`GCLOUD_TIMEOUT_LONG`, default 240s) and auto-retry once with a doubled timeout before giving up. If you still see timeouts in `run.log` after that, raise `GCLOUD_TIMEOUT_LONG` further or check for a slow proxy/VPN between you and Google's APIs.
- **rc=1 errors usually mean "API not enabled" or "permission denied," not a script bug.** The WARN line now includes gcloud's actual last error message (e.g. `Kubernetes Engine API has not been used...`) so you can tell at a glance whether to enable an API or grant a role, rather than just seeing a bare exit code.
- Folder-scoped project discovery only finds projects *directly* parented at that folder; deeply nested sub-folders need a recursive folder walk (left as a TODO — see comment in `resolve_scope()`), or just use `ASSET_SCOPE` (org/folder) for the asset-inventory-based checks, which already cover nested resources correctly.
- SA "unused" detection via `logging read` only sees what's in Cloud Logging's retention window for that project (default 30 days unless you've extended it) intersected with `LOG_LOOKBACK_DAYS`. For a true 90+ day view, rely on the IAM Recommender section instead, which uses Google's own longer-window models.
- Secret pattern matching is regex-based — it will have false positives (flag non-secrets) and false negatives (miss obfuscated/encoded secrets). Treat hits as "investigate," not "confirmed breach."
- SCC section requires Security Command Center to be enabled/licensed on the org; otherwise it silently returns nothing (logged as a warning).
- The billing cost-by-service section requires the `bq` CLI (`gcloud components install bq`) and an existing BigQuery Billing Export — without it, the script automatically falls back to the free asset-inventory-based coverage-gap check, so you still get usage-driven scoping either way.
- Spanner/Bigtable checks confirm public-IAM exposure but don't loop into per-database backup/CMEK settings — treat those instances as "flagged for manual deep-dive," per the finding's recommendation.
- This script does not call any mutating API. To fix findings you'll action the Recommendation column manually (or script remediation separately, deliberately kept out of an audit tool).

## 7. Suggested cadence
Run weekly via cron/Cloud Scheduler + Cloud Build, diff the CSV against the previous run, and alert on any new CRITICAL/HIGH row.
