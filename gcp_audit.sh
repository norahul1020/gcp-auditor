#!/usr/bin/env bash
###############################################################################
# GCP COMPREHENSIVE AUDIT SCRIPT
#
# Audits IAM, Security, and Services/Misconfigurations across an Org, Folder,
# or Project (or a list of Projects), and produces a CSV (+ HTML) report with
# a Recommendation/Resolution column for every finding.
#
# Author intent: defensive security audit only. No destructive actions are
# ever taken by this script - it is strictly READ-ONLY (list/get/describe/
# search/read calls only).
#
# REQUIREMENTS
#   - gcloud CLI installed & authenticated: `gcloud auth login` /
#     `gcloud auth application-default login`
#   - The identity running this needs (at minimum, broadest -> narrowest):
#       roles/iam.securityReviewer            (org/folder/project)
#       roles/cloudasset.viewer                (org/folder/project)
#       roles/recommender.viewer               (project)
#       roles/logging.viewer                   (project)
#       roles/securitycenter.findingsViewer    (org, optional, needs SCC enabled)
#       roles/browser or roles/viewer          (org/folder/project, fallback)
#   - APIs recommended enabled on projects being audited:
#       cloudasset.googleapis.com, recommender.googleapis.com,
#       logging.googleapis.com, iam.googleapis.com,
#       securitycenter.googleapis.com (optional), serviceusage.googleapis.com
#
# USAGE
#   1. Edit the CONFIGURATION block below (or export the same-named env vars
#      before running, env vars take precedence over the defaults here).
#   2. chmod +x gcp_comprehensive_audit.sh && ./gcp_comprehensive_audit.sh
#   3. Open the CSV in Sheets/Excel, or the HTML file in a browser.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# 1. CONFIGURATION - EVERYTHING IS A VARIABLE. EDIT HERE OR PASS AS ENV VARS.
###############################################################################

# --- Scope: choose ONE primary scope. Leave the others blank. ---------------
ORG_ID="${ORG_ID:-}"            # e.g. "123456789012"
FOLDER_ID="${FOLDER_ID:-}"      # e.g. "987654321098"
PROJECT_ID="${PROJECT_ID:-}"    # e.g. "my-single-project"

# Explicit project list (space separated). If set, this OVERRIDES org/folder
# discovery for per-project checks (org/folder-wide checks still use ORG_ID
# /FOLDER_ID if set). Leave empty to auto-discover projects under org/folder.
PROJECTS_OVERRIDE="${PROJECTS_OVERRIDE:-}"

# --- Thresholds (days) -------------------------------------------------------
SA_KEY_AGE_DAYS="${SA_KEY_AGE_DAYS:-90}"          # flag user-managed keys older than this
SA_INACTIVITY_DAYS="${SA_INACTIVITY_DAYS:-90}"    # flag SAs with no activity in logs for this long
LOG_LOOKBACK_DAYS="${LOG_LOOKBACK_DAYS:-90}"       # how far back to search audit logs
KMS_ROTATION_MAX_DAYS="${KMS_ROTATION_MAX_DAYS:-90}"
CERT_EXPIRY_WARN_DAYS="${CERT_EXPIRY_WARN_DAYS:-30}"

# --- Risk definitions ---------------------------------------------------------
PRIMITIVE_ROLES="${PRIMITIVE_ROLES:-roles/owner roles/editor roles/viewer}"
RISKY_PORTS="${RISKY_PORTS:-20,21,22,23,135,445,1433,1434,3306,3389,5432,5900,5984,6379,9200,9300,11211,27017,27018}"
SECRET_REGEX="${SECRET_REGEX:-(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----|(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token)\\s*[=:]\\s*[\"'\''][^\"'\'']{6,})}"

# --- Optional inputs for the extended (Section D) checks ---------------------
# Leave blank to auto-skip that specific check with a log_info note.
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:-}"   # e.g. "012345-6789AB-CDEF01" -> enables billing budget audit
ACCESS_POLICY_ID="${ACCESS_POLICY_ID:-}"        # Access Context Manager policy ID -> enables VPC-SC perimeter audit
MIN_TLS_VERSION="${MIN_TLS_VERSION:-TLS_1_2}"   # minimum acceptable SSL policy version on load balancers
SSL_CERT_EXPIRY_WARN_DAYS="${SSL_CERT_EXPIRY_WARN_DAYS:-30}"

# --- Billing-driven scoping (use real spend/usage to find what to audit) -----
# If you have a BigQuery Billing Export configured, point this at it to get
# actual cost-by-service and prioritize the audit by what you're really paying
# for, not just what's theoretically enabled. Format: project.dataset.table
BILLING_EXPORT_TABLE="${BILLING_EXPORT_TABLE:-}"
BILLING_LOOKBACK_DAYS="${BILLING_LOOKBACK_DAYS:-30}"
BILLING_TOP_N_SERVICES="${BILLING_TOP_N_SERVICES:-25}"

# --- Toggles: turn whole sections on/off without editing logic ---------------
RUN_IAM_AUDIT="${RUN_IAM_AUDIT:-true}"
RUN_SECURITY_AUDIT="${RUN_SECURITY_AUDIT:-true}"
RUN_SERVICES_AUDIT="${RUN_SERVICES_AUDIT:-true}"
RUN_SCC_AUDIT="${RUN_SCC_AUDIT:-true}"           # requires Security Command Center
RUN_EXTENDED_AUDIT="${RUN_EXTENDED_AUDIT:-true}" # Section D: network/DR/CI-CD/governance/WIF/manual checklist
RUN_STORAGE_DB_DEEPDIVE="${RUN_STORAGE_DB_DEEPDIVE:-true}"   # Section E: GCS/BQ/SQL/Spanner/Bigtable/Memorystore/Filestore
RUN_BILLING_DRIVEN_AUDIT="${RUN_BILLING_DRIVEN_AUDIT:-true}" # Section F: spend/usage-based coverage-gap detection
ENABLE_LOG_BASED_SA_ACTIVITY="${ENABLE_LOG_BASED_SA_ACTIVITY:-true}"  # can be slow; set false to skip

# --- Output -------------------------------------------------------------------
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./gcp_audit_${TIMESTAMP}}"
CSV_FILE="${OUTPUT_DIR}/gcp_audit_report.csv"
HTML_FILE="${OUTPUT_DIR}/gcp_audit_report.html"
LOG_FILE="${OUTPUT_DIR}/run.log"
RAW_DIR="${OUTPUT_DIR}/raw"          # raw gcloud JSON kept as evidence

GCLOUD_TIMEOUT="${GCLOUD_TIMEOUT:-90}"        # seconds; per-call timeout for normal/fast gcloud calls
GCLOUD_TIMEOUT_LONG="${GCLOUD_TIMEOUT_LONG:-240}"  # seconds; for known-slow calls (asset inventory, recommender, aggregated multi-region listings, cold-start APIs). Both auto-retry once with a doubled timeout on rc=124 before giving up.

###############################################################################
# 2. INTERNAL STATE - DO NOT EDIT BELOW THIS LINE UNLESS EXTENDING THE SCRIPT
###############################################################################

mkdir -p "$OUTPUT_DIR" "$RAW_DIR"
: > "$LOG_FILE"

FINDINGS_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0

log()      { echo -e "[$(date +'%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_info() { log "INFO  - $*"; }
log_warn() { log "WARN  - $*"; }
log_err()  { log "ERROR - $*"; }

# CSV-safe field escaping
csv_escape() {
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

# add_finding SCOPE_TYPE SCOPE_ID RESOURCE_TYPE RESOURCE_NAME CATEGORY CHECK FINDING SEVERITY EVIDENCE RECOMMENDATION
add_finding() {
  local scope_type="$1" scope_id="$2" resource_type="$3" resource_name="$4"
  local category="$5" check="$6" finding="$7" severity="$8" evidence="$9" recommendation="${10}"
  {
    csv_escape "$scope_type";       printf ','
    csv_escape "$scope_id";         printf ','
    csv_escape "$resource_type";    printf ','
    csv_escape "$resource_name";    printf ','
    csv_escape "$category";         printf ','
    csv_escape "$check";            printf ','
    csv_escape "$finding";          printf ','
    csv_escape "$severity";         printf ','
    csv_escape "$evidence";         printf ','
    csv_escape "$recommendation";   printf '\n'
  } >> "$CSV_FILE"
  FINDINGS_COUNT=$((FINDINGS_COUNT+1))
  case "$severity" in
    CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT+1));;
    HIGH) HIGH_COUNT=$((HIGH_COUNT+1));;
  esac
}

# run_gcloud "description" -- gcloud args...
# run_gcloud_long "description" -- gcloud args...   (same, but uses GCLOUD_TIMEOUT_LONG)
#
# Wraps gcloud calls with a timeout + error capture so one failure never kills
# the run. On a timeout (rc=124) it retries ONCE with a doubled timeout before
# giving up, since cold API enablement / aggregated multi-region listings are
# often just slow on the first call, not actually broken. Whatever the final
# failure is, the WARN line includes gcloud's actual last error line (API
# disabled / permission denied / bad argument, etc.) so you don't have to dig
# through run.log to know what to fix.
_run_gcloud_internal() {
  local desc="$1" timeout_secs="$2"; shift 2
  local rc=0 err_file attempt=1 max_attempts=2
  err_file="$(mktemp)"

  while [ $attempt -le $max_attempts ]; do
    if command -v timeout >/dev/null 2>&1; then
      timeout "${timeout_secs}s" "$@" 2>"$err_file"
    else
      "$@" 2>"$err_file"
    fi
    rc=$?
    cat "$err_file" >> "$LOG_FILE" 2>/dev/null

    if [ $rc -eq 0 ]; then
      rm -f "$err_file"
      return 0
    fi

    if [ $rc -eq 124 ] && [ $attempt -lt $max_attempts ]; then
      log_warn "Timeout after ${timeout_secs}s (${desc}, attempt ${attempt}/${max_attempts}); retrying with doubled timeout..."
      timeout_secs=$(( timeout_secs * 2 ))
      attempt=$(( attempt + 1 ))
      : > "$err_file"
      continue
    fi
    break
  done

  local last_err
  last_err="$(grep -v '^$' "$err_file" 2>/dev/null | tail -n 1)"
  rm -f "$err_file"
  if [ $rc -eq 124 ]; then
    log_warn "Command timed out after ${timeout_secs}s on final attempt (${desc}), rc=124: $*  |  Likely cause: slow/cold API or network/proxy. Consider raising GCLOUD_TIMEOUT/GCLOUD_TIMEOUT_LONG and re-running."
  else
    log_warn "Command failed (${desc}), rc=${rc}${last_err:+ -> ${last_err}}: $*"
  fi
  return $rc
}

run_gcloud() {
  local desc="$1"; shift
  _run_gcloud_internal "$desc" "$GCLOUD_TIMEOUT" "$@"
}

run_gcloud_long() {
  local desc="$1"; shift
  _run_gcloud_internal "$desc" "$GCLOUD_TIMEOUT_LONG" "$@"
}

###############################################################################
# 3. PREREQUISITE CHECKS
###############################################################################

check_prerequisites() {
  log_info "Checking prerequisites..."

  if ! command -v gcloud >/dev/null 2>&1; then
    log_err "gcloud CLI not found in PATH. Install it: https://cloud.google.com/sdk/docs/install"
    exit 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    log_err "jq is required for JSON parsing. Install with: sudo apt-get install -y jq  (or brew install jq)"
    exit 1
  fi

  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .; then
    log_err "No active gcloud auth session found. Run: gcloud auth login"
    exit 1
  fi
  ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
  log_info "Authenticated as: ${ACTIVE_ACCOUNT}"

  if [ -z "$ORG_ID" ] && [ -z "$FOLDER_ID" ] && [ -z "$PROJECT_ID" ] && [ -z "$PROJECTS_OVERRIDE" ]; then
    log_err "No scope set. Set ORG_ID, FOLDER_ID, PROJECT_ID, or PROJECTS_OVERRIDE."
    exit 1
  fi

  echo "scope_type,scope_id,resource_type,resource_name,category,check,finding,severity,evidence,recommendation" > "$CSV_FILE"
  log_info "Report will be written to: $CSV_FILE"
}

###############################################################################
# 4. SCOPE / ASSET RESOLUTION
###############################################################################

# Builds: PROJECTS array, ASSET_SCOPE string (for cloudasset/asset search calls), ORG_DISPLAY
PROJECTS=()
ASSET_SCOPE=""

resolve_scope() {
  log_info "Resolving audit scope..."

  if [ -n "$ORG_ID" ]; then
    ASSET_SCOPE="organizations/${ORG_ID}"
  elif [ -n "$FOLDER_ID" ]; then
    ASSET_SCOPE="folders/${FOLDER_ID}"
  elif [ -n "$PROJECT_ID" ]; then
    ASSET_SCOPE="projects/${PROJECT_ID}"
  fi

  if [ -n "$PROJECTS_OVERRIDE" ]; then
    read -r -a PROJECTS <<< "$PROJECTS_OVERRIDE"
  elif [ -n "$PROJECT_ID" ]; then
    PROJECTS=("$PROJECT_ID")
  elif [ -n "$FOLDER_ID" ]; then
    mapfile -t PROJECTS < <(gcloud projects list --filter="parent.id=${FOLDER_ID} AND parent.type=folder" --format="value(projectId)" 2>>"$LOG_FILE")
    # Note: this only catches projects directly under the folder. For nested
    # sub-folders, use `gcloud resource-manager folders list --folder=$FOLDER_ID`
    # recursively, or prefer Cloud Asset Inventory (ASSET_SCOPE) for full coverage.
  elif [ -n "$ORG_ID" ]; then
    mapfile -t PROJECTS < <(gcloud projects list --filter="parent.id=${ORG_ID} AND parent.type=organization" --format="value(projectId)" 2>>"$LOG_FILE")
    if [ "${#PROJECTS[@]}" -eq 0 ]; then
      log_warn "No projects directly parented at org root found; falling back to Cloud Asset Inventory for project discovery."
      mapfile -t PROJECTS < <(gcloud asset search-all-resources --scope="$ASSET_SCOPE" --asset-types=cloudresourcemanager.googleapis.com/Project --format="value(project)" 2>>"$LOG_FILE" | sort -u)
    fi
  fi

  log_info "Asset scope: ${ASSET_SCOPE:-<none>}"
  log_info "Projects in scope (${#PROJECTS[@]}): ${PROJECTS[*]:-<none>}"

  if [ "${#PROJECTS[@]}" -eq 0 ] && [ -z "$ASSET_SCOPE" ]; then
    log_err "Could not resolve any projects to audit. Check your scope variables and IAM permissions."
    exit 1
  fi
}

###############################################################################
# 5. SECTION A — IAM AUDIT
#    (bindings, over-privilege, unused permissions, service accounts, keys,
#     activity via audit logs, custom roles, conditional bindings)
###############################################################################

audit_iam_org_wide_bindings() {
  log_info "[IAM] Pulling all IAM policy bindings across scope via Cloud Asset Inventory..."
  [ -z "$ASSET_SCOPE" ] && return 0
  local out="${RAW_DIR}/iam_policies.json"
  run_gcloud_long "search-all-iam-policies" gcloud asset search-all-iam-policies \
    --scope="$ASSET_SCOPE" --format=json > "$out" || return 0

  [ -s "$out" ] || return 0

  # 1) Primitive roles (Owner/Editor/Viewer) - over-privileged by default
  local primitive_hits
  primitive_hits=$(jq -r --arg roles "$PRIMITIVE_ROLES" '
    .[] as $r | $r.policy.bindings[]? as $b |
    select(($roles | split(" ") | index($b.role)) != null) |
    ($r.resource + "||" + $b.role + "||" + ($b.members | join(";")))
  ' "$out" 2>/dev/null)

  if [ -n "$primitive_hits" ]; then
    while IFS='||' read -r resource role members; do
      [ -z "$resource" ] && continue
      add_finding "IAM" "$ASSET_SCOPE" "IAM Binding" "$resource" "IAM" \
        "Primitive role usage" \
        "Primitive role '${role}' granted directly on ${resource} to: ${members}" \
        "HIGH" "search-all-iam-policies" \
        "Replace primitive roles (Owner/Editor/Viewer) with least-privilege predefined or custom roles. Use IAM Recommender (google.iam.policy.Recommender) to find the minimal role set. Owner/Editor at project level is one of the most common causes of breach blast-radius expansion."
    done <<< "$primitive_hits"
  fi

  # 2) Public / anonymous access (allUsers, allAuthenticatedUsers)
  local public_hits
  public_hits=$(jq -r '
    .[] as $r | $r.policy.bindings[]? as $b |
    select($b.members[]? | (. == "allUsers" or . == "allAuthenticatedUsers")) |
    ($r.resource + "||" + $b.role)
  ' "$out" 2>/dev/null)

  if [ -n "$public_hits" ]; then
    while IFS='||' read -r resource role; do
      [ -z "$resource" ] && continue
      add_finding "IAM" "$ASSET_SCOPE" "IAM Binding" "$resource" "IAM" \
        "Public IAM binding" \
        "Resource ${resource} grants '${role}' to allUsers/allAuthenticatedUsers" \
        "CRITICAL" "search-all-iam-policies" \
        "Remove allUsers/allAuthenticatedUsers bindings unless the resource is intentionally a public endpoint (e.g. a public website bucket). If intentional, document it and restrict to only the specific role/resource needed (e.g. objectViewer on a single bucket, not project-wide)."
    done <<< "$public_hits"
  fi

  # 3) Group-based/service-account broad grants at org/folder level (informational, for manual review)
  jq -r '
    .[] as $r | $r.policy.bindings[]? as $b |
    select($r.resource | test("organizations/|folders/")) |
    ($r.resource + "||" + $b.role + "||" + ($b.members | join(";")))
  ' "$out" 2>/dev/null | while IFS='||' read -r resource role members; do
    [ -z "$resource" ] && continue
    add_finding "IAM" "$ASSET_SCOPE" "IAM Binding" "$resource" "IAM" \
      "Org/Folder-level grant (review)" \
      "Role '${role}' granted at ${resource} to: ${members}" \
      "MEDIUM" "search-all-iam-policies" \
      "Org/folder-level grants apply to every project beneath them. Confirm this is intentional and scoped to the minimum role necessary; prefer granting at the project or resource level instead of org/folder where possible."
  done
}

audit_iam_unused_permissions_recommender() {
  log_info "[IAM] Checking IAM Recommender for over-privileged / unused-permission findings..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/iam_recommender_${proj}.json"
    run_gcloud_long "iam recommender ${proj}" gcloud recommender recommendations list \
      --project="$proj" \
      --recommender=google.iam.policy.Recommender \
      --location=global \
      --format=json > "$out" || continue
    [ -s "$out" ] || continue

    jq -c '.[]? | select(.stateInfo.state=="ACTIVE")' "$out" 2>/dev/null | while read -r rec; do
      local resource desc impact
      resource=$(echo "$rec" | jq -r '.content.overview.resource // .content.operationGroups[0].operations[0].resource // "unknown"')
      desc=$(echo "$rec" | jq -r '.description // "Unused or excessive IAM permissions detected"')
      impact=$(echo "$rec" | jq -r '.primaryImpact.category // "SECURITY"')
      add_finding "IAM" "$proj" "Service Account / Principal" "$resource" "IAM" \
        "Unused/excessive permissions (IAM Recommender)" \
        "$desc" "HIGH" "recommender.recommendations.list (google.iam.policy.Recommender)" \
        "Apply the IAM Recommender suggestion directly: 'gcloud recommender recommendations mark-claimed/mark-succeeded' after applying, or apply via Console > IAM > Recommendations tab. This automatically right-sizes the role based on 90 days of actual usage from audit logs."
    done
  done
}

audit_service_accounts_and_keys() {
  log_info "[IAM] Auditing service accounts and their keys..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local sa_out="${RAW_DIR}/service_accounts_${proj}.json"
    run_gcloud "list SAs ${proj}" gcloud iam service-accounts list --project="$proj" --format=json > "$sa_out" || continue
    [ -s "$sa_out" ] || continue

    local sa_count
    sa_count=$(jq 'length' "$sa_out" 2>/dev/null || echo 0)
    [ "$sa_count" -eq 0 ] && continue

    jq -r '.[].email' "$sa_out" | while read -r sa_email; do
      [ -z "$sa_email" ] && continue

      # Default compute/app-engine SAs flagged separately - they hold Editor by default in older projects
      if [[ "$sa_email" == *-compute@developer.gserviceaccount.com ]] || [[ "$sa_email" == *@appspot.gserviceaccount.com ]]; then
        add_finding "IAM" "$proj" "Service Account" "$sa_email" "IAM" \
          "Default service account in use" \
          "Default Compute/App Engine service account exists and may still be attached to running resources with broad (often Editor) permissions" \
          "MEDIUM" "iam service-accounts list" \
          "Avoid using default service accounts for workloads. Create dedicated, minimally-scoped service accounts per workload/app, disable or remove the default SA's broad roles, and prefer Workload Identity (GKE) or attached SA with custom roles instead."
      fi

      # --- Key age audit (user-managed keys only; Google-managed keys auto-rotate) ---
      local keys_out="${RAW_DIR}/keys_$(echo "$sa_email" | tr '@.' '__').json"
      run_gcloud "list keys for ${sa_email}" gcloud iam service-accounts keys list \
        --iam-account="$sa_email" --managed-by=user --format=json > "$keys_out" 2>/dev/null
      if [ -s "$keys_out" ]; then
        jq -c '.[]?' "$keys_out" 2>/dev/null | while read -r key; do
          local valid_after key_name age_days
          valid_after=$(echo "$key" | jq -r '.validAfterTime')
          key_name=$(echo "$key" | jq -r '.name')
          age_days=$(( ( $(date +%s) - $(date -d "$valid_after" +%s 2>/dev/null || echo 0) ) / 86400 ))
          if [ "$age_days" -ge "$SA_KEY_AGE_DAYS" ]; then
            add_finding "IAM" "$proj" "Service Account Key" "$key_name" "IAM" \
              "Stale user-managed SA key" \
              "Key for ${sa_email} is ${age_days} days old (threshold ${SA_KEY_AGE_DAYS})" \
              "HIGH" "iam service-accounts keys list --managed-by=user" \
              "Rotate or delete this key. User-managed SA keys are long-lived static credentials and a top exfiltration target. Prefer Workload Identity Federation (keyless) for workloads outside GCP, or attached service accounts (no key needed) for workloads on GCE/GKE/Cloud Run/Cloud Functions. If a key is unavoidable, rotate every <=90 days and store it in Secret Manager, never in code or env files."
          fi
        done
      fi

      # User-managed key existing at all is worth flagging once, even if young
      local key_count
      key_count=$(jq 'length' "$keys_out" 2>/dev/null || echo 0)
      if [ "$key_count" -gt 0 ]; then
        add_finding "IAM" "$proj" "Service Account" "$sa_email" "IAM" \
          "User-managed key(s) present" \
          "${sa_email} has ${key_count} user-managed key(s)" \
          "MEDIUM" "iam service-accounts keys list" \
          "Confirm this key is still required. If the consuming workload runs on GCP, switch to attached-identity auth (no key) or Workload Identity Federation and delete the key."
      fi

      # --- Activity / unused SA audit via Cloud Logging (Admin/Data Access logs) ---
      if [ "$ENABLE_LOG_BASED_SA_ACTIVITY" = "true" ]; then
        local last_seen
        last_seen=$(run_gcloud "activity for ${sa_email}" gcloud logging read \
          "protoPayload.authenticationInfo.principalEmail=\"${sa_email}\" AND timestamp>=\"$(date -d "-${LOG_LOOKBACK_DAYS} days" -u +%Y-%m-%dT%H:%M:%SZ)\"" \
          --project="$proj" --order=desc --limit=1 --format="value(timestamp)" 2>>"$LOG_FILE")
        if [ -z "$last_seen" ]; then
          add_finding "IAM" "$proj" "Service Account" "$sa_email" "IAM" \
            "Unused service account (no activity in audit logs)" \
            "No authenticated activity found for ${sa_email} in the last ${LOG_LOOKBACK_DAYS} days of audit logs" \
            "HIGH" "logging read protoPayload.authenticationInfo.principalEmail (last ${LOG_LOOKBACK_DAYS}d)" \
            "Confirm with the owning team whether this SA is still needed. If unused, disable it first ('gcloud iam service-accounts disable'), monitor for breakage, then delete it and any keys/role bindings. For a longer-horizon view, also check the IAM Recommender 'Unused service account' insights (google.iam.policy.Recommender) which uses 90+ day windows."
        fi
      fi
    done
  done
}

audit_custom_roles() {
  log_info "[IAM] Auditing custom IAM roles for risky permissions..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/custom_roles_${proj}.json"
    run_gcloud "list custom roles ${proj}" gcloud iam roles list --project="$proj" --format=json > "$out" || continue
    [ -s "$out" ] || continue
    jq -c '.[]?' "$out" 2>/dev/null | while read -r role; do
      local role_name perms_count is_disabled
      role_name=$(echo "$role" | jq -r '.name')
      perms_count=$(echo "$role" | jq '.includedPermissions | length' 2>/dev/null || echo 0)
      is_disabled=$(echo "$role" | jq -r '.stage // "GA"')
      if echo "$role" | jq -e '.includedPermissions[]? | select(test("\\.setIamPolicy$|\\.delete$|\\.admin$"))' >/dev/null 2>&1; then
        add_finding "IAM" "$proj" "Custom Role" "$role_name" "IAM" \
          "Custom role contains high-risk permissions" \
          "Custom role ${role_name} (${perms_count} permissions, stage=${is_disabled}) includes setIamPolicy/delete/admin-type permissions" \
          "MEDIUM" "iam roles list / describe" \
          "Review whether the role truly needs IAM-modification or delete-class permissions. Split into smaller roles following least privilege; avoid granting setIamPolicy broadly since it allows privilege escalation."
      fi
    done
  done
}

audit_iam_section() {
  [ "$RUN_IAM_AUDIT" != "true" ] && { log_info "[IAM] Skipped (RUN_IAM_AUDIT=false)"; return; }
  audit_iam_org_wide_bindings
  audit_iam_unused_permissions_recommender
  audit_service_accounts_and_keys
  audit_custom_roles
}

###############################################################################
# 6. SECTION B — SECURITY AUDIT
#    (org policies, firewalls, public exposure, encryption, logging config,
#     GKE hardening, SCC findings, network)
###############################################################################

audit_org_policies() {
  [ -z "$ORG_ID" ] && [ -z "$FOLDER_ID" ] && [ -z "$PROJECT_ID" ] && return 0
  log_info "[SECURITY] Auditing key Org Policy constraints..."
  local target=""
  [ -n "$ORG_ID" ] && target="organizations/${ORG_ID}"
  [ -n "$FOLDER_ID" ] && [ -z "$target" ] && target="folders/${FOLDER_ID}"
  [ -n "$PROJECT_ID" ] && [ -z "$target" ] && target="projects/${PROJECT_ID}"
  [ -z "$target" ] && return 0

  declare -A RECOMMENDED_CONSTRAINTS=(
    ["constraints/iam.disableServiceAccountKeyCreation"]="Prevents creation of new user-managed SA keys; enforce to push teams to Workload Identity / attached SAs"
    ["constraints/compute.disableSerialPortAccess"]="Blocks serial port access to VMs, a common lateral-movement / debug-backdoor vector"
    ["constraints/compute.requireOsLogin"]="Enforces OS Login (centralized, auditable SSH access) instead of static SSH keys in metadata"
    ["constraints/compute.vmExternalIpAccess"]="Restricts which VMs may have external IPs, reducing public attack surface"
    ["constraints/storage.uniformBucketLevelAccess"]="Forces uniform bucket-level access, removing legacy ACL-based misconfig risk on GCS"
    ["constraints/sql.restrictPublicIp"]="Prevents Cloud SQL instances from getting public IPs"
    ["constraints/iam.allowedPolicyMemberDomains"]="Restricts IAM members to approved domains/identities, blocking external/personal-Gmail grants"
    ["constraints/compute.restrictXpnProjectLienRemoval"]="Protects Shared VPC host projects from accidental/malicious un-sharing"
  )

  for constraint in "${!RECOMMENDED_CONSTRAINTS[@]}"; do
    local policy_out
    policy_out=$(run_gcloud "org-policy describe ${constraint}" gcloud org-policies describe "$constraint" --"${target%%/*}"="${target##*/}" --format=json 2>/dev/null)
    local enforced
    enforced=$(echo "$policy_out" | jq -r '.spec.rules[0].enforce // "unset"' 2>/dev/null)
    if [ -z "$policy_out" ] || [ "$enforced" != "true" ]; then
      add_finding "SECURITY" "$target" "Org Policy" "$constraint" "Security - Org Policy" \
        "Constraint not enforced" \
        "Org Policy constraint '${constraint}' is not set/enforced at ${target}" \
        "MEDIUM" "org-policies describe" \
        "${RECOMMENDED_CONSTRAINTS[$constraint]}. Enable with: gcloud org-policies set-policy <policy.yaml> --${target%%/*}=${target##*/} (set enforce: true)."
    fi
  done
}

audit_firewalls() {
  log_info "[SECURITY] Auditing VPC firewall rules for risky open access..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/firewalls_${proj}.json"
    run_gcloud "firewall-rules list ${proj}" gcloud compute firewall-rules list --project="$proj" --format=json > "$out" || continue
    [ -s "$out" ] || continue

    jq -c '.[]? | select(.disabled != true and .direction=="INGRESS")' "$out" 2>/dev/null | while read -r rule; do
      local name src_ranges allowed_str
      name=$(echo "$rule" | jq -r '.name')
      src_ranges=$(echo "$rule" | jq -r '(.sourceRanges // []) | join(",")')
      allowed_str=$(echo "$rule" | jq -r '(.allowed // []) | map((.IPProtocol)+":"+((.ports // ["all"]) | join(","))) | join("; ")')

      if [[ "$src_ranges" == *"0.0.0.0/0"* ]]; then
        # Check if any risky port is in the allowed list (or 'all' ports / IPProtocol=all)
        local risky_hit="false"
        if echo "$rule" | jq -e '.allowed[]? | select((.ports == null) or (.ports[]? as $p | ([$p] - ($ENV.RISKY_PORTS | split(","))) != [$p]))' >/dev/null 2>&1; then
          risky_hit="true"
        fi
        local severity="HIGH"
        echo "$allowed_str" | grep -Eq "(^|; )(tcp|udp):($RISKY_PORTS|all)(,|$|;)" && severity="CRITICAL"
        [ "$allowed_str" = *"all"* ] && severity="CRITICAL"

        add_finding "SECURITY" "$proj" "Firewall Rule" "$name" "Security - Network" \
          "Internet-exposed ingress rule" \
          "Rule '${name}' allows ${allowed_str} from 0.0.0.0/0" \
          "$severity" "compute firewall-rules list" \
          "Restrict sourceRanges to known IP ranges (corporate VPN/office CIDRs) or remove the 0.0.0.0/0 source entirely. For admin ports (22/3389/3306/5432/etc.) use Identity-Aware Proxy (IAP) TCP forwarding or a bastion/VPN instead of public exposure. Tag-scope the rule to only the instances that need it (avoid applying to all instances in the VPC)."
      fi
    done

    # Default-allow-* rules left in place on default network
    jq -r '.[]? | select(.name | test("default-allow-")) | .name' "$out" 2>/dev/null | while read -r dname; do
      [ -z "$dname" ] && continue
      add_finding "SECURITY" "$proj" "Firewall Rule" "$dname" "Security - Network" \
        "Default network firewall rule present" \
        "Rule '${dname}' is one of the GCP default-network auto-created rules (often overly permissive)" \
        "MEDIUM" "compute firewall-rules list" \
        "Review and remove unused default-allow-ssh/rdp/icmp/internal rules; replace with explicit, scoped rules. Consider deleting the legacy 'default' VPC network entirely in favor of custom-mode VPCs."
    done
  done
}

audit_public_storage() {
  log_info "[SECURITY] Auditing Cloud Storage buckets for public/anonymous access..."
  [ -z "$ASSET_SCOPE" ] && { for p in "${PROJECTS[@]}"; do ASSET_SCOPE="projects/$p"; _audit_public_storage_for_scope; done; return; }
  _audit_public_storage_for_scope
}
_audit_public_storage_for_scope() {
  local out="${RAW_DIR}/public_buckets.json"
  run_gcloud_long "search-all-iam-policies buckets" gcloud asset search-all-iam-policies \
    --scope="$ASSET_SCOPE" \
    --query='policy:(allUsers OR allAuthenticatedUsers)' \
    --asset-types=storage.googleapis.com/Bucket --format=json > "$out" 2>/dev/null
  [ -s "$out" ] || return 0
  jq -c '.[]?' "$out" 2>/dev/null | while read -r item; do
    local resource bindings
    resource=$(echo "$item" | jq -r '.resource')
    bindings=$(echo "$item" | jq -r '.policy.bindings[]? | select(.members[]?=="allUsers" or .members[]?=="allAuthenticatedUsers") | .role' | tr '\n' ';')
    add_finding "SECURITY" "$ASSET_SCOPE" "GCS Bucket" "$resource" "Security - Storage" \
      "Publicly accessible bucket" \
      "Bucket ${resource} grants role(s) [${bindings}] to allUsers/allAuthenticatedUsers" \
      "CRITICAL" "search-all-iam-policies (storage.googleapis.com/Bucket)" \
      "Remove public IAM bindings unless this bucket is intentionally a public static-content host. If intentional, scope the role to roles/storage.objectViewer only, enable a CDN/Cloud Armor in front of it, and enforce uniform bucket-level access + a bucket-specific allow-list rather than project-wide public grants."
  done
}

audit_public_compute_instances() {
  log_info "[SECURITY] Auditing Compute Engine instances for public IPs / weak config..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/instances_${proj}.json"
    run_gcloud "instances list ${proj}" gcloud compute instances list --project="$proj" --format=json > "$out" || continue
    [ -s "$out" ] || continue

    jq -c '.[]?' "$out" 2>/dev/null | while read -r inst; do
      local name zone ext_ip shielded_secure_boot os_login serial_enabled
      name=$(echo "$inst" | jq -r '.name')
      zone=$(echo "$inst" | jq -r '.zone' | awk -F/ '{print $NF}')
      ext_ip=$(echo "$inst" | jq -r '[.networkInterfaces[]?.accessConfigs[]?.natIP] | join(",")')
      shielded_secure_boot=$(echo "$inst" | jq -r '.shieldedInstanceConfig.enableSecureBoot // false')
      serial_enabled=$(echo "$inst" | jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value // "false"')

      if [ -n "$ext_ip" ]; then
        add_finding "SECURITY" "$proj" "Compute Instance" "$name (${zone})" "Security - Compute" \
          "Instance has external/public IP" \
          "Instance ${name} has external IP(s): ${ext_ip}" \
          "HIGH" "compute instances list" \
          "Remove the external IP if not required; use Cloud NAT for outbound-only internet access and Identity-Aware Proxy (IAP) or a bastion for inbound admin access. Apply the org policy constraints/compute.vmExternalIpAccess to prevent recurrence."
      fi
      if [ "$shielded_secure_boot" != "true" ]; then
        add_finding "SECURITY" "$proj" "Compute Instance" "$name (${zone})" "Security - Compute" \
          "Shielded VM (Secure Boot) not enabled" \
          "Instance ${name} does not have Secure Boot enabled" \
          "MEDIUM" "compute instances list" \
          "Enable Shielded VM options (Secure Boot, vTPM, Integrity Monitoring) to protect against rootkits/bootkits. Existing instances can be updated while stopped: 'gcloud compute instances update NAME --shielded-secure-boot'."
      fi
      if [ "$serial_enabled" = "true" ]; then
        add_finding "SECURITY" "$proj" "Compute Instance" "$name (${zone})" "Security - Compute" \
          "Serial port access enabled" \
          "Instance ${name} has serial-port-enable=true in metadata" \
          "MEDIUM" "compute instances list" \
          "Disable serial port access unless actively needed for debugging ('gcloud compute instances add-metadata --metadata serial-port-enable=false'). Enforce via org policy constraints/compute.disableSerialPortAccess."
      fi
    done
  done
}

audit_cloudsql() {
  log_info "[SECURITY] Auditing Cloud SQL instances for public exposure / SSL / backups..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/sql_${proj}.json"
    run_gcloud_long "sql instances list ${proj}" gcloud sql instances list --project="$proj" --format=json > "$out" || continue
    [ -s "$out" ] || continue

    jq -c '.[]?' "$out" 2>/dev/null | while read -r inst; do
      local name ipv4 require_ssl auth_networks backup_enabled
      name=$(echo "$inst" | jq -r '.name')
      ipv4=$(echo "$inst" | jq -r '.settings.ipConfiguration.ipv4Enabled // false')
      require_ssl=$(echo "$inst" | jq -r '.settings.ipConfiguration.requireSsl // false')
      auth_networks=$(echo "$inst" | jq -r '[.settings.ipConfiguration.authorizedNetworks[]?.value] | join(",")')
      backup_enabled=$(echo "$inst" | jq -r '.settings.backupConfiguration.enabled // false')

      if [ "$ipv4" = "true" ]; then
        add_finding "SECURITY" "$proj" "Cloud SQL Instance" "$name" "Security - Database" \
          "Public IP enabled on Cloud SQL" \
          "Instance ${name} has a public IPv4 address enabled" \
          "HIGH" "sql instances list" \
          "Disable public IP and use Private Service Connect / Private IP + Cloud SQL Auth Proxy / Cloud SQL connector instead. Enforce via org policy constraints/sql.restrictPublicIp."
      fi
      if [[ "$auth_networks" == *"0.0.0.0/0"* ]]; then
        add_finding "SECURITY" "$proj" "Cloud SQL Instance" "$name" "Security - Database" \
          "Authorized network 0.0.0.0/0" \
          "Instance ${name} authorizes connections from 0.0.0.0/0" \
          "CRITICAL" "sql instances list" \
          "Remove the 0.0.0.0/0 authorized network immediately; replace with specific CIDR ranges or, preferably, Private IP + Cloud SQL Auth Proxy with IAM database authentication."
      fi
      if [ "$require_ssl" != "true" ]; then
        add_finding "SECURITY" "$proj" "Cloud SQL Instance" "$name" "Security - Database" \
          "SSL/TLS not enforced" \
          "Instance ${name} does not require SSL for connections" \
          "HIGH" "sql instances list" \
          "Set requireSsl=true (or enforce 'Encrypted only' with trusted CA / mutual TLS) so all client connections are encrypted in transit: 'gcloud sql instances patch NAME --require-ssl'."
      fi
      if [ "$backup_enabled" != "true" ]; then
        add_finding "SECURITY" "$proj" "Cloud SQL Instance" "$name" "Security - Database" \
          "Automated backups disabled" \
          "Instance ${name} does not have automated backups enabled" \
          "HIGH" "sql instances list" \
          "Enable automated daily backups and point-in-time recovery: 'gcloud sql instances patch NAME --backup-start-time=HH:MM --enable-bin-log'."
      fi
    done
  done
}

audit_kms() {
  log_info "[SECURITY] Auditing KMS key rotation policies..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local locs_out="${RAW_DIR}/kms_locations_${proj}.json"
    run_gcloud_long "kms locations list" gcloud kms keyrings list --project="$proj" --location=- --format=json > "$locs_out" 2>/dev/null
    [ -s "$locs_out" ] || continue
    jq -r '.[]?.name' "$locs_out" 2>/dev/null | while read -r keyring; do
      [ -z "$keyring" ] && continue
      local keys_out="${RAW_DIR}/kms_keys_$(basename "$keyring").json"
      run_gcloud_long "kms keys list" gcloud kms keys list --keyring="$keyring" --location="$(echo "$keyring" | awk -F/ '{print $4}')" --project="$proj" --format=json > "$keys_out" 2>/dev/null
      jq -c '.[]?' "$keys_out" 2>/dev/null | while read -r key; do
        local key_name rotation_period
        key_name=$(echo "$key" | jq -r '.name')
        rotation_period=$(echo "$key" | jq -r '.rotationPeriod // "none"')
        if [ "$rotation_period" = "none" ] || [ "$rotation_period" = "null" ]; then
          add_finding "SECURITY" "$proj" "KMS Key" "$key_name" "Security - Encryption" \
            "No automatic key rotation configured" \
            "Key ${key_name} has no rotationPeriod set" \
            "MEDIUM" "kms keys list" \
            "Set automatic rotation (e.g. every ${KMS_ROTATION_MAX_DAYS} days): 'gcloud kms keys update NAME --rotation-period=${KMS_ROTATION_MAX_DAYS}d --next-rotation-time=...'. Periodic rotation limits the blast radius of a compromised key version."
        fi
      done
    done
  done
}

audit_logging_and_monitoring() {
  log_info "[SECURITY] Auditing log sinks, retention, and monitoring coverage..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local sinks_out="${RAW_DIR}/sinks_${proj}.json"
    run_gcloud "logging sinks list" gcloud logging sinks list --project="$proj" --format=json > "$sinks_out" || continue
    local sink_count
    sink_count=$(jq 'length' "$sinks_out" 2>/dev/null || echo 0)
    if [ "$sink_count" -eq 0 ]; then
      add_finding "SECURITY" "$proj" "Logging" "project/${proj}" "Security - Logging" \
        "No log export sink configured" \
        "Project ${proj} has no log sinks exporting to BigQuery/GCS/Pub-Sub" \
        "HIGH" "logging sinks list" \
        "Create at least one aggregated sink exporting Admin Activity + Data Access + System Event audit logs to a separate, access-restricted project/bucket (ideally with a locked retention policy) so logs survive even if this project is compromised: 'gcloud logging sinks create ...'."
    fi

    # Check default bucket retention as a proxy for log retention posture
    local buckets_out="${RAW_DIR}/log_buckets_${proj}.json"
    run_gcloud "logging buckets list" gcloud logging buckets list --project="$proj" --location=global --format=json > "$buckets_out" 2>/dev/null
    jq -c '.[]?' "$buckets_out" 2>/dev/null | while read -r b; do
      local bname retention locked
      bname=$(echo "$b" | jq -r '.name')
      retention=$(echo "$b" | jq -r '.retentionDays // 30')
      locked=$(echo "$b" | jq -r '.locked // false')
      if [ "$locked" != "true" ]; then
        add_finding "SECURITY" "$proj" "Log Bucket" "$bname" "Security - Logging" \
          "Log bucket not locked" \
          "Log bucket ${bname} (retention ${retention}d) is not locked" \
          "MEDIUM" "logging buckets list" \
          "Lock critical log buckets (especially the _Default and any security/audit sink buckets) to prevent retention-policy tampering or early deletion by a compromised admin: 'gcloud logging buckets update NAME --locked'."
      fi
    done
  done
}

audit_gke_clusters() {
  log_info "[SECURITY] Auditing GKE cluster hardening settings..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/gke_${proj}.json"
    run_gcloud_long "gke clusters list" gcloud container clusters list --project="$proj" --format=json > "$out" || continue
    [ -s "$out" ] || continue

    jq -c '.[]?' "$out" 2>/dev/null | while read -r c; do
      local name private_nodes legacy_abac net_policy master_auth_nets bin_auth workload_identity
      name=$(echo "$c" | jq -r '.name')
      private_nodes=$(echo "$c" | jq -r '.privateClusterConfig.enablePrivateNodes // false')
      legacy_abac=$(echo "$c" | jq -r '.legacyAbac.enabled // false')
      net_policy=$(echo "$c" | jq -r '.networkPolicy.enabled // false')
      master_auth_nets=$(echo "$c" | jq -r '.masterAuthorizedNetworksConfig.enabled // false')
      bin_auth=$(echo "$c" | jq -r '.binaryAuthorization.evaluationMode // "DISABLED"')
      workload_identity=$(echo "$c" | jq -r '.workloadIdentityConfig.workloadPool // "none"')

      [ "$private_nodes" != "true" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Cluster nodes are not private" "Cluster ${name} does not use private nodes" "HIGH" "container clusters list" \
        "Recreate/migrate to a private cluster (--enable-private-nodes) so node VMs only have internal IPs; use Cloud NAT for egress."

      [ "$legacy_abac" = "true" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Legacy ABAC enabled" "Cluster ${name} has legacy Attribute-Based Access Control enabled" "HIGH" "container clusters list" \
        "Disable legacy ABAC and rely solely on RBAC: 'gcloud container clusters update NAME --no-enable-legacy-authorization'."

      [ "$net_policy" != "true" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Network Policy disabled" "Cluster ${name} has no NetworkPolicy enforcement (Calico/Dataplane V2)" "MEDIUM" "container clusters list" \
        "Enable network policy enforcement to allow pod-to-pod traffic segmentation: 'gcloud container clusters update NAME --enable-network-policy' (or use Dataplane V2)."

      [ "$master_auth_nets" != "true" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Control plane not IP-restricted" "Cluster ${name} control plane is reachable without authorized network restrictions" "HIGH" "container clusters list" \
        "Enable Master Authorized Networks and list only trusted CIDRs (office/VPN/CI) that may reach the Kubernetes API: 'gcloud container clusters update NAME --enable-master-authorized-networks --master-authorized-networks=<CIDRs>'."

      [ "$bin_auth" = "DISABLED" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Binary Authorization disabled" "Cluster ${name} does not enforce Binary Authorization" "MEDIUM" "container clusters list" \
        "Enable Binary Authorization with a policy requiring images to be signed/attested by your CI pipeline, blocking unverified images from running: 'gcloud container clusters update NAME --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE'."

      [ "$workload_identity" = "none" ] && add_finding "SECURITY" "$proj" "GKE Cluster" "$name" "Security - GKE" \
        "Workload Identity not configured" "Cluster ${name} does not use Workload Identity" "MEDIUM" "container clusters list" \
        "Enable Workload Identity so pods authenticate to GCP APIs via short-lived federated tokens instead of mounted SA key files: 'gcloud container clusters update NAME --workload-pool=PROJECT_ID.svc.id.goog'."
    done
  done
}

audit_scc_findings() {
  [ "$RUN_SCC_AUDIT" != "true" ] && return 0
  [ -z "$ORG_ID" ] && { log_warn "[SECURITY] Skipping Security Command Center audit - ORG_ID not set."; return 0; }
  log_info "[SECURITY] Pulling active Security Command Center findings (requires SCC enabled on the org)..."
  local out="${RAW_DIR}/scc_findings.json"
  run_gcloud_long "scc findings list" gcloud scc findings list "organizations/${ORG_ID}" \
    --filter='state="ACTIVE"' --format=json > "$out" 2>/dev/null
  [ -s "$out" ] || { log_warn "[SECURITY] No SCC findings returned (SCC may not be enabled/licensed, or no access)."; return 0; }

  jq -c '.[]? | .finding // .' "$out" 2>/dev/null | while read -r f; do
    local category resource severity name
    category=$(echo "$f" | jq -r '.category // "UNKNOWN"')
    resource=$(echo "$f" | jq -r '.resourceName // "unknown"')
    severity=$(echo "$f" | jq -r '.severity // "MEDIUM"')
    name=$(echo "$f" | jq -r '.name // "unknown"')
    add_finding "SECURITY" "organizations/${ORG_ID}" "SCC Finding" "$resource" "Security - SCC" \
      "$category" "Active Security Command Center finding: ${category} on ${resource}" \
      "$severity" "scc findings list (${name})" \
      "Open this finding in Security Command Center for full remediation steps specific to the category. Triage by severity, assign an owner, and re-run SCC export after remediation to confirm the finding closes."
  done
}

audit_security_section() {
  [ "$RUN_SECURITY_AUDIT" != "true" ] && { log_info "[SECURITY] Skipped (RUN_SECURITY_AUDIT=false)"; return; }
  audit_org_policies
  audit_firewalls
  audit_public_storage
  audit_public_compute_instances
  audit_cloudsql
  audit_kms
  audit_logging_and_monitoring
  audit_gke_clusters
  audit_scc_findings
}

###############################################################################
# 7. SECTION C — SERVICES / APPLICATION MISCONFIGURATION / HARDCODED SECRETS
###############################################################################

audit_enabled_apis() {
  log_info "[SERVICES] Auditing enabled APIs per project..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/apis_${proj}.json"
    run_gcloud_long "services list ${proj}" gcloud services list --enabled --project="$proj" --format=json > "$out" || continue
    local count
    count=$(jq 'length' "$out" 2>/dev/null || echo 0)
    add_finding "SERVICES" "$proj" "Project" "$proj" "Services - API Surface" \
      "Enabled API inventory (informational)" \
      "Project ${proj} has ${count} APIs enabled - see raw/apis_${proj}.json for full list" \
      "LOW" "services list --enabled" \
      "Periodically review enabled APIs and disable any not in active use to reduce attack surface ('gcloud services disable API_NAME'). Pay special attention to powerful/legacy APIs (e.g. compute, iam, cloudfunctions, deploymentmanager) being enabled in projects that don't need them."
  done
}

audit_public_serverless() {
  log_info "[SERVICES] Auditing Cloud Run / Cloud Functions for unauthenticated public access..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue

    # Cloud Run
    local run_out="${RAW_DIR}/run_${proj}.json"
    run_gcloud "run services list" gcloud run services list --project="$proj" --platform=managed --format=json > "$run_out" 2>/dev/null
    jq -r '.[]?.metadata.name' "$run_out" 2>/dev/null | while read -r svc; do
      [ -z "$svc" ] && continue
      local region
      region=$(jq -r --arg s "$svc" '.[] | select(.metadata.name==$s) | .metadata.labels["cloud.googleapis.com/location"] // .metadata.namespace' "$run_out" 2>/dev/null)
      local policy
      policy=$(run_gcloud "run get-iam-policy" gcloud run services get-iam-policy "$svc" --project="$proj" --region="$region" --format=json 2>/dev/null)
      if echo "$policy" | grep -q "allUsers"; then
        add_finding "SERVICES" "$proj" "Cloud Run Service" "$svc" "Services - Serverless" \
          "Unauthenticated public invocation allowed" \
          "Cloud Run service ${svc} allows allUsers as invoker" \
          "HIGH" "run services get-iam-policy" \
          "Confirm this service is meant to be public (e.g. a public API/webhook). If not, remove the allUsers binding and require authentication ('gcloud run services remove-iam-policy-binding'), then use IAM, an API gateway, or signed requests for callers. If it must be public, put Cloud Armor / a WAF and rate limiting in front of it."
      fi

      # Check env vars for hardcoded secrets
      local env_dump
      env_dump=$(jq -r --arg s "$svc" '.[] | select(.metadata.name==$s) | .spec.template.spec.containers[]?.env[]? | (.name + "=" + (.value // ""))' "$run_out" 2>/dev/null)
      if echo "$env_dump" | grep -E -i "$SECRET_REGEX" >/dev/null 2>&1; then
        add_finding "SERVICES" "$proj" "Cloud Run Service" "$svc" "Services - Secrets" \
          "Possible hardcoded secret in env vars" \
          "Environment variables on Cloud Run service ${svc} match a secret-like pattern (value redacted in this report)" \
          "CRITICAL" "run services describe (env vars pattern-matched, not logged)" \
          "Move this value into Secret Manager immediately and mount it as a secret env var/volume instead of a plaintext env var ('gcloud run services update --update-secrets'). Rotate the exposed credential, since it has likely been visible in deploy logs/IaC history."
      fi
    done

    # Cloud Functions (Gen1 + Gen2 covered by `functions list`)
    local fn_out="${RAW_DIR}/functions_${proj}.json"
    run_gcloud_long "functions list" gcloud functions list --project="$proj" --format=json > "$fn_out" 2>/dev/null
    jq -r '.[]?.name' "$fn_out" 2>/dev/null | while read -r fn; do
      [ -z "$fn" ] && continue
      local fn_short policy
      fn_short=$(basename "$fn")
      policy=$(run_gcloud "functions get-iam-policy" gcloud functions get-iam-policy "$fn_short" --project="$proj" --format=json 2>/dev/null)
      if echo "$policy" | grep -q "allUsers"; then
        add_finding "SERVICES" "$proj" "Cloud Function" "$fn_short" "Services - Serverless" \
          "Unauthenticated public invocation allowed" \
          "Cloud Function ${fn_short} allows allUsers as invoker" \
          "HIGH" "functions get-iam-policy" \
          "If this function isn't meant to be public, remove the allUsers binding and require IAM auth or an authenticated gateway in front of it."
      fi
      local env_dump
      env_dump=$(jq -r --arg n "$fn" '.[] | select(.name==$n) | (.environmentVariables // {}) | to_entries[] | (.key+"="+(.value|tostring))' "$fn_out" 2>/dev/null)
      if echo "$env_dump" | grep -E -i "$SECRET_REGEX" >/dev/null 2>&1; then
        add_finding "SERVICES" "$proj" "Cloud Function" "$fn_short" "Services - Secrets" \
          "Possible hardcoded secret in env vars" \
          "Environment variables on function ${fn_short} match a secret-like pattern (value redacted)" \
          "CRITICAL" "functions describe (pattern-matched, not logged)" \
          "Move the value to Secret Manager and reference it via --set-secrets instead of --set-env-vars. Rotate the credential."
      fi
    done
  done
}

audit_compute_metadata_secrets() {
  log_info "[SERVICES] Scanning GCE instance metadata/startup-scripts for hardcoded secrets..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/instances_${proj}.json"
    [ -s "$out" ] || run_gcloud "instances list ${proj}" gcloud compute instances list --project="$proj" --format=json > "$out" 2>/dev/null
    [ -s "$out" ] || continue

    jq -c '.[]?' "$out" 2>/dev/null | while read -r inst; do
      local name meta_blob
      name=$(echo "$inst" | jq -r '.name')
      meta_blob=$(echo "$inst" | jq -r '.metadata.items[]? | (.key + "=" + (.value // ""))' 2>/dev/null)
      if echo "$meta_blob" | grep -E -i "$SECRET_REGEX" >/dev/null 2>&1; then
        add_finding "SERVICES" "$proj" "Compute Instance" "$name" "Services - Secrets" \
          "Possible hardcoded secret in instance metadata/startup-script" \
          "Custom metadata on instance ${name} matches a secret-like pattern (value redacted)" \
          "CRITICAL" "compute instances describe (pattern-matched, not logged)" \
          "Remove credentials from instance metadata/startup scripts. Use Secret Manager + the metadata server's attached service-account identity to fetch secrets at boot time instead of embedding them as plaintext metadata."
      fi
    done
  done
}

audit_storage_hygiene() {
  log_info "[SERVICES] Auditing storage bucket hygiene (versioning, lifecycle, uniform access)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/buckets_${proj}.json"
    run_gcloud "storage buckets list" gcloud storage buckets list --project="$proj" --format=json > "$out" 2>/dev/null
    jq -c '.[]?' "$out" 2>/dev/null | while read -r b; do
      local name uniform versioning
      name=$(echo "$b" | jq -r '.name')
      uniform=$(echo "$b" | jq -r '.iamConfiguration.uniformBucketLevelAccess.enabled // false')
      versioning=$(echo "$b" | jq -r '.versioning.enabled // false')
      if [ "$uniform" != "true" ]; then
        add_finding "SERVICES" "$proj" "GCS Bucket" "$name" "Services - Storage Hygiene" \
          "Uniform bucket-level access disabled" \
          "Bucket ${name} still allows legacy per-object ACLs" \
          "MEDIUM" "storage buckets list" \
          "Enable uniform bucket-level access to eliminate ACL-based misconfiguration risk: 'gcloud storage buckets update gs://NAME --uniform-bucket-level-access'."
      fi
      if [ "$versioning" != "true" ]; then
        add_finding "SERVICES" "$proj" "GCS Bucket" "$name" "Services - Storage Hygiene" \
          "Object versioning disabled" \
          "Bucket ${name} has no object versioning, increasing risk of unrecoverable accidental/malicious deletion" \
          "LOW" "storage buckets list" \
          "Enable versioning on buckets holding important data, paired with a lifecycle rule to expire old versions after a reasonable period."
      fi
    done
  done
}

audit_bigquery_public_datasets() {
  log_info "[SERVICES] Checking for publicly shared BigQuery datasets..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/bq_${proj}.json"
    run_gcloud "bq ls" gcloud alpha bq datasets list --project="$proj" --format=json > "$out" 2>/dev/null
    jq -r '.[]?.datasetReference.datasetId' "$out" 2>/dev/null | while read -r ds; do
      [ -z "$ds" ] && continue
      local iam
      iam=$(run_gcloud "bq dataset iam" gcloud alpha bq datasets get-iam-policy "$ds" --project="$proj" --format=json 2>/dev/null)
      if echo "$iam" | grep -Eq 'allUsers|allAuthenticatedUsers'; then
        add_finding "SERVICES" "$proj" "BigQuery Dataset" "$ds" "Services - Data" \
          "Publicly accessible BigQuery dataset" \
          "Dataset ${ds} grants access to allUsers/allAuthenticatedUsers" \
          "CRITICAL" "bq datasets get-iam-policy" \
          "Remove public bindings unless this is an intentionally published open dataset. Restrict to named principals/groups and enable column/row-level security for sensitive tables."
      fi
    done
  done
}

audit_secret_manager_adoption() {
  log_info "[SERVICES] Checking Secret Manager adoption vs. plaintext secret patterns found elsewhere..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/secrets_${proj}.json"
    run_gcloud "secrets list" gcloud secrets list --project="$proj" --format=json > "$out" 2>/dev/null
    local count
    count=$(jq 'length' "$out" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
      add_finding "SERVICES" "$proj" "Project" "$proj" "Services - Secrets" \
        "Secret Manager not used in this project" \
        "Project ${proj} has zero secrets registered in Secret Manager" \
        "LOW" "secrets list" \
        "If this project's workloads need credentials/API keys/tokens, migrate them into Secret Manager rather than env vars, metadata, or source code. This also gives you automatic audit logging of every secret access."
    fi
  done
}

audit_services_section() {
  [ "$RUN_SERVICES_AUDIT" != "true" ] && { log_info "[SERVICES] Skipped (RUN_SERVICES_AUDIT=false)"; return; }
  audit_enabled_apis
  audit_public_serverless
  audit_compute_metadata_secrets
  audit_storage_hygiene
  audit_bigquery_public_datasets
  audit_secret_manager_adoption
}

###############################################################################
# 7B. SECTION D — EXTENDED AUDIT (the "things an experienced SRE/security
#     reviewer checks that weren't explicitly asked for"): network
#     architecture, backup/DR, CI/CD supply-chain, workload identity
#     federation, org-level governance, and a manual-process checklist.
###############################################################################

audit_network_hardening() {
  log_info "[EXTENDED] Auditing network hardening (flow logs, NAT, Armor, DNSSEC, TLS, default network)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue

    # Default network still present?
    if gcloud compute networks describe default --project="$proj" --format="value(name)" >/dev/null 2>>"$LOG_FILE"; then
      add_finding "SECURITY" "$proj" "VPC Network" "default" "Security - Network Architecture" \
        "Legacy 'default' auto-mode network present" \
        "Project ${proj} still has the GCP-created 'default' network with its auto-generated permissive firewall rules" \
        "MEDIUM" "compute networks describe default" \
        "Migrate workloads to a custom-mode VPC with explicit, scoped subnets/firewall rules, then delete the default network. Auto-mode default networks are a recurring source of forgotten public exposure."
    fi

    # VPC Flow Logs on subnets
    local subnets_out="${RAW_DIR}/subnets_${proj}.json"
    run_gcloud "subnets list" gcloud compute networks subnets list --project="$proj" --format=json > "$subnets_out" 2>/dev/null
    jq -c '.[]?' "$subnets_out" 2>/dev/null | while read -r sn; do
      local sn_name flow_logs priv_access
      sn_name=$(echo "$sn" | jq -r '.name + " (" + (.region|split("/")|last) + ")"')
      flow_logs=$(echo "$sn" | jq -r '.enableFlowLogs // false')
      priv_access=$(echo "$sn" | jq -r '.privateIpGoogleAccess // false')
      [ "$flow_logs" != "true" ] && add_finding "SECURITY" "$proj" "Subnet" "$sn_name" "Security - Network Architecture" \
        "VPC Flow Logs disabled" "Subnet ${sn_name} does not have Flow Logs enabled" "MEDIUM" "compute networks subnets list" \
        "Enable VPC Flow Logs for network forensics/incident response and anomaly detection: 'gcloud compute networks subnets update NAME --enable-flow-logs'."
      [ "$priv_access" != "true" ] && add_finding "SECURITY" "$proj" "Subnet" "$sn_name" "Security - Network Architecture" \
        "Private Google Access disabled" "Subnet ${sn_name} cannot reach Google APIs without external IPs" "LOW" "compute networks subnets list" \
        "Enable Private Google Access so VMs without external IPs can still reach Google APIs/services, reducing the need for public IPs: 'gcloud compute networks subnets update NAME --enable-private-ip-google-access'."
    done

    # Cloud NAT presence (only meaningful if there are private-only workloads, but useful to know either way)
    # Note: `compute routers nats list` requires a specific --router name, so it
    # can't be used to check "any NAT anywhere in the project". Instead, list all
    # routers (which embed their .nats[] config) and count NATs across all of them.
    local routers_out="${RAW_DIR}/routers_${proj}.json"
    run_gcloud "routers list" gcloud compute routers list --project="$proj" --format=json > "$routers_out" 2>/dev/null
    local nat_total
    nat_total=$(jq '[.[].nats[]?] | length' "$routers_out" 2>/dev/null || echo 0)
    if [ "$nat_total" -eq 0 ]; then
      add_finding "SECURITY" "$proj" "Cloud NAT" "project/${proj}" "Security - Network Architecture" \
        "No Cloud NAT configured (informational)" \
        "No Cloud NAT gateways found in ${proj} - confirm this is expected (e.g. no private-only egress workloads)" \
        "LOW" "compute routers list (.nats[] field)" \
        "If any instances/GKE nodes here rely on external IPs purely for outbound internet access, switch them to private-only + Cloud NAT instead, removing unnecessary inbound attack surface."
    fi

    # Cloud Armor security policies
    local armor_out="${RAW_DIR}/armor_${proj}.json"
    run_gcloud "armor list" gcloud compute security-policies list --project="$proj" --format=json > "$armor_out" 2>/dev/null
    if [ "$(jq 'length' "$armor_out" 2>/dev/null || echo 0)" -eq 0 ]; then
      add_finding "SECURITY" "$proj" "Cloud Armor" "project/${proj}" "Security - Network Architecture" \
        "No Cloud Armor policies configured" \
        "Project ${proj} has no Cloud Armor security policies" \
        "LOW" "compute security-policies list" \
        "If this project serves internet-facing HTTP(S) load balancers, put a Cloud Armor WAF policy in front (rate limiting + OWASP preconfigured rules) to absorb L7 attacks/credential-stuffing/bot traffic before it reaches your app."
    fi

    # SSL Policies - minimum TLS version
    local ssl_out="${RAW_DIR}/sslpolicies_${proj}.json"
    run_gcloud "ssl-policies list" gcloud compute ssl-policies list --project="$proj" --format=json > "$ssl_out" 2>/dev/null
    jq -c '.[]?' "$ssl_out" 2>/dev/null | while read -r sp; do
      local sp_name min_tls
      sp_name=$(echo "$sp" | jq -r '.name')
      min_tls=$(echo "$sp" | jq -r '.minTlsVersion')
      if [[ "$min_tls" < "$MIN_TLS_VERSION" ]]; then
        add_finding "SECURITY" "$proj" "SSL Policy" "$sp_name" "Security - Network Architecture" \
          "Weak minimum TLS version" "SSL policy ${sp_name} allows down to ${min_tls}" "HIGH" "compute ssl-policies list" \
          "Raise the minimum TLS version to ${MIN_TLS_VERSION} or higher and use the MODERN/RESTRICTED profile: 'gcloud compute ssl-policies update NAME --min-tls-version=${MIN_TLS_VERSION} --profile=RESTRICTED'."
      fi
    done

    # SSL certificate expiry
    local cert_out="${RAW_DIR}/sslcerts_${proj}.json"
    run_gcloud "ssl-certificates list" gcloud compute ssl-certificates list --project="$proj" --format=json > "$cert_out" 2>/dev/null
    jq -c '.[]? | select(.expireTime != null)' "$cert_out" 2>/dev/null | while read -r cert; do
      local cname expire days_left
      cname=$(echo "$cert" | jq -r '.name')
      expire=$(echo "$cert" | jq -r '.expireTime')
      days_left=$(( ( $(date -d "$expire" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
      if [ "$days_left" -le "$SSL_CERT_EXPIRY_WARN_DAYS" ]; then
        add_finding "SECURITY" "$proj" "SSL Certificate" "$cname" "Security - Network Architecture" \
          "Certificate expiring soon or expired" "Certificate ${cname} expires in ${days_left} day(s) (${expire})" "HIGH" "compute ssl-certificates list" \
          "Renew/rotate this certificate now, or migrate to Google-managed certificates so renewal is automatic: 'gcloud compute ssl-certificates create ... --domains=...'."
      fi
    done
  done

  # DNSSEC on Cloud DNS managed zones (org/project level, check per project)
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local dns_out="${RAW_DIR}/dns_${proj}.json"
    run_gcloud_long "dns zones list" gcloud dns managed-zones list --project="$proj" --format=json > "$dns_out" 2>/dev/null
    jq -c '.[]? | select(.visibility=="public" or .visibility==null)' "$dns_out" 2>/dev/null | while read -r z; do
      local zname dnssec_state
      zname=$(echo "$z" | jq -r '.name')
      dnssec_state=$(echo "$z" | jq -r '.dnssecConfig.state // "off"')
      if [ "$dnssec_state" != "on" ]; then
        add_finding "SECURITY" "$proj" "Cloud DNS Zone" "$zname" "Security - Network Architecture" \
          "DNSSEC not enabled on public zone" "Public DNS zone ${zname} has DNSSEC state=${dnssec_state}" "MEDIUM" "dns managed-zones list" \
          "Enable DNSSEC to prevent DNS spoofing/cache-poisoning of your public domains: 'gcloud dns managed-zones update NAME --dnssec-state=on'."
      fi
    done
  done
}

audit_backup_and_dr() {
  log_info "[EXTENDED] Auditing backup & disaster-recovery posture (disks, GKE)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local disks_out="${RAW_DIR}/disks_${proj}.json"
    run_gcloud "disks list" gcloud compute disks list --project="$proj" --format=json > "$disks_out" 2>/dev/null
    jq -c '.[]?' "$disks_out" 2>/dev/null | while read -r d; do
      local dname zone has_policy
      dname=$(echo "$d" | jq -r '.name')
      zone=$(echo "$d" | jq -r '.zone // .region // "unknown"' | awk -F/ '{print $NF}')
      has_policy=$(echo "$d" | jq -r '(.resourcePolicies // []) | length')
      if [ "$has_policy" -eq 0 ]; then
        add_finding "SECURITY" "$proj" "Persistent Disk" "$dname (${zone})" "Security - Backup/DR" \
          "No scheduled snapshot policy attached" \
          "Disk ${dname} has zero resource (snapshot schedule) policies attached" \
          "HIGH" "compute disks list" \
          "Attach a snapshot schedule so this disk is recoverable from ransomware/accidental-deletion/corruption: 'gcloud compute resource-policies create snapshot-schedule ...' then 'gcloud compute disks add-resource-policies NAME --resource-policies=POLICY'."
      fi
    done

    # GKE Backup for GKE plans (only meaningful if clusters exist)
    local gke_out="${RAW_DIR}/gke_${proj}.json"
    if [ -s "$gke_out" ] && [ "$(jq 'length' "$gke_out" 2>/dev/null || echo 0)" -gt 0 ]; then
      local bk_out="${RAW_DIR}/gke_backup_${proj}.json"
      run_gcloud "gke backup-plans list" gcloud beta container backup-plans list --project="$proj" --format=json > "$bk_out" 2>/dev/null
      if [ ! -s "$bk_out" ] || [ "$(jq 'length' "$bk_out" 2>/dev/null || echo 0)" -eq 0 ]; then
        add_finding "SECURITY" "$proj" "GKE" "project/${proj}" "Security - Backup/DR" \
          "No Backup for GKE plan configured" \
          "Project ${proj} runs GKE clusters but has no Backup for GKE plan" \
          "MEDIUM" "beta container backup-plans list" \
          "Configure Backup for GKE to protect cluster state and workload data (PVs) against accidental deletion or cluster-level failure."
      fi
    fi
  done
}

audit_cicd_and_registries() {
  log_info "[EXTENDED] Auditing CI/CD (Cloud Build) and Artifact/Container Registry exposure..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue

    # Cloud Build default service account - historically granted Editor by default
    local cb_sa="$(gcloud projects describe "$proj" --format='value(projectNumber)' 2>>"$LOG_FILE")@cloudbuild.gserviceaccount.com"
    local iam_out="${RAW_DIR}/project_iam_${proj}.json"
    run_gcloud "project iam policy" gcloud projects get-iam-policy "$proj" --format=json > "$iam_out" 2>/dev/null
    if jq -e --arg sa "serviceAccount:${cb_sa}" '.bindings[]? | select(.role=="roles/editor") | .members[]? | select(.==$sa)' "$iam_out" >/dev/null 2>&1; then
      add_finding "IAM" "$proj" "Service Account" "$cb_sa" "Security - CI/CD" \
        "Cloud Build default SA still has project Editor" \
        "The Cloud Build default service account holds roles/editor on ${proj}" \
        "HIGH" "projects get-iam-policy" \
        "Replace the default Cloud Build SA's Editor role with a custom least-privilege role scoped to exactly what your build/deploy pipeline needs (e.g. specific Cloud Run deploy, Artifact Registry push). A compromised build pipeline with Editor can pivot to the entire project."
    fi

    # Cloud Build triggers - scan substitutions for hardcoded secrets, check unrestricted branch triggers
    local triggers_out="${RAW_DIR}/cb_triggers_${proj}.json"
    run_gcloud_long "build triggers list" gcloud builds triggers list --project="$proj" --format=json > "$triggers_out" 2>/dev/null
    jq -c '.[]?' "$triggers_out" 2>/dev/null | while read -r t; do
      local tname subs
      tname=$(echo "$t" | jq -r '.name')
      subs=$(echo "$t" | jq -r '(.substitutions // {}) | to_entries[]? | (.key+"="+.value)')
      if echo "$subs" | grep -E -i "$SECRET_REGEX" >/dev/null 2>&1; then
        add_finding "SERVICES" "$proj" "Cloud Build Trigger" "$tname" "Security - CI/CD" \
          "Possible hardcoded secret in build trigger substitutions" \
          "Trigger ${tname} has substitution variables matching a secret-like pattern (value redacted)" \
          "CRITICAL" "builds triggers list (pattern-matched, not logged)" \
          "Move this value to Secret Manager and reference it in cloudbuild.yaml via availableSecrets/secretEnv instead of a plaintext substitution variable. Rotate the exposed credential."
      fi
    done

    # Artifact Registry public exposure
    local ar_out="${RAW_DIR}/artifact_repos_${proj}.json"
    run_gcloud_long "artifact repos list" gcloud artifacts repositories list --project="$proj" --format=json > "$ar_out" 2>/dev/null
    jq -r '.[]?.name' "$ar_out" 2>/dev/null | while read -r repo; do
      [ -z "$repo" ] && continue
      local repo_short loc policy
      repo_short=$(basename "$repo")
      loc=$(echo "$repo" | awk -F/ '{print $4}')
      policy=$(run_gcloud "artifact repo iam" gcloud artifacts repositories get-iam-policy "$repo_short" --location="$loc" --project="$proj" --format=json 2>/dev/null)
      if echo "$policy" | grep -Eq 'allUsers|allAuthenticatedUsers'; then
        add_finding "SECURITY" "$proj" "Artifact Registry Repo" "$repo_short" "Security - CI/CD" \
          "Publicly accessible artifact/container repository" \
          "Repository ${repo_short} grants access to allUsers/allAuthenticatedUsers" \
          "CRITICAL" "artifacts repositories get-iam-policy" \
          "Remove public bindings unless this is an intentionally published public image/package repo. Otherwise restrict to specific service accounts/principals and enable vulnerability scanning (Container/Artifact Analysis) on all images."
      fi
    done
  done
}

audit_workload_identity_federation() {
  log_info "[EXTENDED] Auditing Workload Identity Federation pools (keyless external auth)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local wif_out="${RAW_DIR}/wif_pools_${proj}.json"
    run_gcloud_long "wif pools list" gcloud iam workload-identity-pools list --project="$proj" --location=global --format=json > "$wif_out" 2>/dev/null
    local pool_count
    pool_count=$(jq 'length' "$wif_out" 2>/dev/null || echo 0)
    if [ "$pool_count" -eq 0 ]; then
      add_finding "IAM" "$proj" "Project" "$proj" "IAM - Workload Identity" \
        "No Workload Identity Federation pools configured (informational)" \
        "Project ${proj} has no WIF pools - external workloads (CI/CD, on-prem, other clouds) likely authenticate with static SA keys instead" \
        "LOW" "iam workload-identity-pools list" \
        "For any external system (GitHub Actions, GitLab CI, AWS, on-prem) that currently authenticates to this project with a downloaded SA key, migrate to Workload Identity Federation for short-lived, keyless auth - it eliminates the long-lived-credential risk entirely."
    else
      jq -r '.[]?.name' "$wif_out" 2>/dev/null | while read -r pool; do
        [ -z "$pool" ] && continue
        local pool_short providers_out
        pool_short=$(basename "$pool")
        providers_out="${RAW_DIR}/wif_providers_${pool_short}.json"
        run_gcloud_long "wif providers list" gcloud iam workload-identity-pools providers list --project="$proj" --location=global --workload-identity-pool="$pool_short" --format=json > "$providers_out" 2>/dev/null
        jq -c '.[]?' "$providers_out" 2>/dev/null | while read -r p; do
          local pname cond
          pname=$(echo "$p" | jq -r '.name')
          cond=$(echo "$p" | jq -r '.attributeCondition // "none"')
          if [ "$cond" = "none" ] || [ "$cond" = "null" ]; then
            add_finding "IAM" "$proj" "WIF Provider" "$pname" "IAM - Workload Identity" \
              "No attribute condition restricting WIF provider" \
              "Provider ${pname} has no attributeCondition set" \
              "HIGH" "iam workload-identity-pools providers list" \
              "Add an attributeCondition restricting which external identities (e.g. specific GitHub repo/branch, specific AWS role) can assume this pool's identity. Without it, any token issued by the external IdP that matches the audience can potentially impersonate into GCP."
          fi
        done
      done
    fi
  done
}

audit_org_governance_extras() {
  log_info "[EXTENDED] Auditing org-level governance (Essential Contacts, billing budgets, liens)..."

  if [ -n "$ORG_ID" ]; then
    local ec_out="${RAW_DIR}/essential_contacts.json"
    run_gcloud "essential contacts" gcloud essential-contacts list --organization="$ORG_ID" --format=json > "$ec_out" 2>/dev/null
    if ! jq -e '.[]? | select(.notificationCategorySubscriptions[]?=="SECURITY")' "$ec_out" >/dev/null 2>&1; then
      add_finding "SECURITY" "organizations/${ORG_ID}" "Essential Contacts" "organization" "Security - Governance" \
        "No Essential Contact subscribed to SECURITY notifications" \
        "No essential contact at the org level is subscribed to the SECURITY notification category" \
        "HIGH" "essential-contacts list" \
        "Add at least one (ideally a distribution list, not a single person) Essential Contact subscribed to SECURITY and LEGAL categories at the org level, so Google's direct security notifications (e.g. compromised credentials, abuse) reach your team immediately even if individual employees leave."
    fi
  fi

  if [ -n "$BILLING_ACCOUNT_ID" ]; then
    local budgets_out="${RAW_DIR}/billing_budgets.json"
    run_gcloud "billing budgets list" gcloud billing budgets list --billing-account="$BILLING_ACCOUNT_ID" --format=json > "$budgets_out" 2>/dev/null
    if [ "$(jq 'length' "$budgets_out" 2>/dev/null || echo 0)" -eq 0 ]; then
      add_finding "SERVICES" "billingAccounts/${BILLING_ACCOUNT_ID}" "Billing Account" "$BILLING_ACCOUNT_ID" "Services - Cost Governance" \
        "No billing budgets/alerts configured" \
        "Billing account ${BILLING_ACCOUNT_ID} has zero budgets configured" \
        "MEDIUM" "billing budgets list" \
        "Create at least one budget with alert thresholds (e.g. 50/90/100%) per project or for the whole billing account. This is also a security control - a sudden cost spike is often the first signal of a compromised account being used for crypto-mining or resource abuse."
    fi
  else
    log_info "[EXTENDED] Skipping billing budget audit - set BILLING_ACCOUNT_ID to enable."
  fi

  if [ -n "$ORG_ID" ]; then
    local liens_out="${RAW_DIR}/liens.json"
    run_gcloud "resource manager liens" gcloud alpha resource-manager liens list --format=json > "$liens_out" 2>/dev/null
    add_finding "SECURITY" "organizations/${ORG_ID}" "Resource Manager Liens" "organization" "Security - Governance" \
      "Resource Manager Lien inventory (informational)" \
      "Found $(jq 'length' "$liens_out" 2>/dev/null || echo 0) lien(s) protecting projects from accidental deletion" \
      "LOW" "alpha resource-manager liens list" \
      "Add a deletion lien on business-critical projects (billing, security tooling, prod) so they cannot be deleted without first explicitly removing the lien: 'gcloud alpha resource-manager liens create --restrictions=resourcemanager.projects.delete --reason=...'."
  fi

  # IAM Deny policies - advanced control, worth flagging if entirely unused at org level
  if [ -n "$ORG_ID" ]; then
    local deny_out="${RAW_DIR}/deny_policies.json"
    run_gcloud "iam deny policies" gcloud iam policies list --attachment-point="cloudresourcemanager.googleapis.com%2Forganizations%2F${ORG_ID}" --kind=denypolicies --format=json > "$deny_out" 2>/dev/null
    if [ ! -s "$deny_out" ] || [ "$(jq 'length' "$deny_out" 2>/dev/null || echo 0)" -eq 0 ]; then
      add_finding "IAM" "organizations/${ORG_ID}" "IAM Deny Policy" "organization" "IAM - Governance" \
        "No org-level IAM Deny policy configured (informational)" \
        "No Deny policies found attached at the organization node" \
        "LOW" "iam policies list --kind=denypolicies" \
        "Consider an org-level Deny policy as a hard backstop for your highest-risk permissions (e.g. deny iam.serviceAccountKeys.create for everyone except a tightly scoped break-glass group) - Deny policies override any Allow grant, including future misconfigurations."
    fi
  fi
}

audit_manual_process_checklist() {
  log_info "[EXTENDED] Adding non-scriptable governance/process items for manual review..."
  local scope_label="${ASSET_SCOPE:-${PROJECT_ID:-manual-review}}"
  local items=(
    "2FA/MFA enforcement for all human users (Cloud Identity 2-Step Verification, ideally phishing-resistant security keys for admins)|This cannot be verified via gcloud for most Cloud Identity/Workspace setups; check in Admin Console > Security > 2-Step Verification enrollment, and enforce org-wide."
    "Break-glass / emergency-access process for IAM and production|Confirm a documented, tested break-glass procedure exists for when normal SSO/IAM access is unavailable, with post-use audit review."
    "Third-party / vendor access review|Periodically review any external vendor service accounts, OAuth app grants (Cloud Identity > Security > API controls), and Marketplace-installed apps for scope creep."
    "Incident response runbook + tabletop exercises|Confirm an IR runbook exists covering GCP-specific scenarios (compromised SA key, public bucket exposure, crypto-mining instance) and has been tested in the last 12 months."
    "Penetration testing / red-team cadence|Confirm external or internal pentest covering both the GCP control plane (IAM/network) and the application layer has occurred within your compliance-required cadence."
    "Data classification & DLP scanning|Confirm sensitive data (PII/PCI/PHI) locations are known and Cloud DLP (or equivalent) scanning/classification is applied to storage/BigQuery holding it."
    "Change management / IaC drift detection|Confirm infrastructure changes go through IaC (Terraform/Deployment Manager) + review, and periodically diff live state vs IaC to catch manual console drift."
    "Employee offboarding IAM cleanup SLA|Confirm a defined SLA (e.g. <24h) exists for revoking GCP access (IAM bindings, SA key ownership, OAuth tokens) after an employee/contractor offboards."
  )
  for item in "${items[@]}"; do
    IFS='|' read -r title rec <<< "$item"
    add_finding "PROCESS" "$scope_label" "Manual Review" "N/A" "Process - Governance (manual review)" \
      "$title" "Not verifiable via gcloud API - requires manual confirmation with the responsible team" \
      "LOW" "manual checklist item (not derived from logs/API)" "$rec"
  done
}

audit_vpc_service_controls() {
  if [ -z "$ACCESS_POLICY_ID" ]; then
    log_info "[EXTENDED] Skipping VPC Service Controls audit - set ACCESS_POLICY_ID to enable."
    return 0
  fi
  log_info "[EXTENDED] Auditing VPC Service Controls perimeters..."
  local out="${RAW_DIR}/vpcsc_perimeters.json"
  run_gcloud "vpcsc perimeters list" gcloud access-context-manager perimeters list --policy="$ACCESS_POLICY_ID" --format=json > "$out" 2>/dev/null
  local count
  count=$(jq 'length' "$out" 2>/dev/null || echo 0)
  if [ "$count" -eq 0 ]; then
    add_finding "SECURITY" "accessPolicies/${ACCESS_POLICY_ID}" "VPC Service Controls" "policy/${ACCESS_POLICY_ID}" "Security - Governance" \
      "No VPC Service Controls perimeters defined" \
      "Access policy ${ACCESS_POLICY_ID} has zero service perimeters configured" \
      "MEDIUM" "access-context-manager perimeters list" \
      "For projects holding sensitive data (BigQuery/GCS with regulated data), define a VPC-SC perimeter to block data exfiltration via stolen credentials/misconfigured IAM - it's a network-layer control independent of IAM."
  fi
}

audit_extended_section() {
  [ "$RUN_EXTENDED_AUDIT" != "true" ] && { log_info "[EXTENDED] Skipped (RUN_EXTENDED_AUDIT=false)"; return; }
  audit_network_hardening
  audit_backup_and_dr
  audit_cicd_and_registries
  audit_workload_identity_federation
  audit_org_governance_extras
  audit_vpc_service_controls
  audit_manual_process_checklist
}

###############################################################################
# 7C. SECTION E — STORAGE & DATABASE DEEP-DIVE
#     (GCS, BigQuery, Cloud SQL go deeper than the basic checks in Section B/C;
#      Spanner, Bigtable, Memorystore, Filestore are net-new here.)
###############################################################################

audit_gcs_deep() {
  log_info "[STORAGE/DB] Deep-diving GCS buckets (PAP, retention lock, CMEK, access logging)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/buckets_${proj}.json"
    [ -s "$out" ] || run_gcloud "storage buckets list" gcloud storage buckets list --project="$proj" --format=json > "$out" 2>/dev/null
    [ -s "$out" ] || continue
    jq -c '.[]?' "$out" 2>/dev/null | while read -r b; do
      local name pap retention_locked cmek logging_enabled
      name=$(echo "$b" | jq -r '.name')
      pap=$(echo "$b" | jq -r '.iamConfiguration.publicAccessPrevention // "inherited"')
      retention_locked=$(echo "$b" | jq -r '.retentionPolicy.isLocked // false')
      cmek=$(echo "$b" | jq -r '.encryption.defaultKmsKeyName // "google-managed"')
      logging_enabled=$(echo "$b" | jq -r '.logging.logBucket // "none"')

      [ "$pap" != "enforced" ] && add_finding "SECURITY" "$proj" "GCS Bucket" "$name" "Security - Storage Deep-Dive" \
        "Public Access Prevention not enforced" "Bucket ${name} has publicAccessPrevention=${pap}" "MEDIUM" "storage buckets list" \
        "Set Public Access Prevention to 'enforced' so the bucket cannot be made public even by a future IAM/ACL mistake: 'gcloud storage buckets update gs://NAME --public-access-prevention'."

      if [ "$cmek" = "google-managed" ]; then
        add_finding "SERVICES" "$proj" "GCS Bucket" "$name" "Security - Storage Deep-Dive" \
          "Bucket uses Google-managed encryption, not CMEK" "Bucket ${name} has no defaultKmsKeyName set" "LOW" "storage buckets list" \
          "If this bucket holds regulated/sensitive data, switch to Customer-Managed Encryption Keys (CMEK) for direct control over key rotation/revocation: 'gcloud storage buckets update gs://NAME --default-encryption-key=KMS_KEY'."
      fi
      if [ "$logging_enabled" = "none" ]; then
        add_finding "SECURITY" "$proj" "GCS Bucket" "$name" "Security - Storage Deep-Dive" \
          "Bucket access logging not configured" "Bucket ${name} has no usage/storage logging sink configured" "LOW" "storage buckets list" \
          "Enable bucket access logs (or rely on Data Access audit logs if enabled) so you have an evidence trail of who read/wrote objects, important for breach investigation and compliance."
      fi
      if [ "$retention_locked" != "true" ]; then
        add_finding "SERVICES" "$proj" "GCS Bucket" "$name" "Security - Storage Deep-Dive" \
          "No locked retention policy (informational)" "Bucket ${name} has no locked retention policy" "LOW" "storage buckets list" \
          "For compliance-relevant or backup buckets, set a retention policy and lock it ('gcloud storage buckets update gs://NAME --retention-period=Xs --lock-retention-policy') so not even a project Owner can shorten retention or delete data early - useful against both ransomware and insider risk."
      fi
    done
  done
}

audit_bigquery_deep() {
  log_info "[STORAGE/DB] Deep-diving BigQuery (CMEK, table expiration, authorized views, audit logging)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/bq_${proj}.json"
    [ -s "$out" ] || run_gcloud "bq ls" gcloud alpha bq datasets list --project="$proj" --format=json > "$out" 2>/dev/null
    [ -s "$out" ] || continue
    jq -r '.[]?.datasetReference.datasetId' "$out" 2>/dev/null | while read -r ds; do
      [ -z "$ds" ] && continue
      local detail cmek default_exp
      detail=$(run_gcloud "bq dataset describe" gcloud alpha bq datasets describe "$ds" --project="$proj" --format=json 2>/dev/null)
      cmek=$(echo "$detail" | jq -r '.defaultEncryptionConfiguration.kmsKeyName // "google-managed"' 2>/dev/null)
      default_exp=$(echo "$detail" | jq -r '.defaultTableExpirationMs // "none"' 2>/dev/null)

      if [ "$cmek" = "google-managed" ]; then
        add_finding "SERVICES" "$proj" "BigQuery Dataset" "$ds" "Security - Storage Deep-Dive" \
          "Dataset uses Google-managed encryption, not CMEK" "Dataset ${ds} has no defaultEncryptionConfiguration" "LOW" "bq datasets describe" \
          "For datasets holding sensitive/regulated data, set a default CMEK key so all tables inherit customer-managed encryption: 'bq update --default_kms_key=KMS_KEY project:dataset'."
      fi
      if [ "$default_exp" = "none" ]; then
        add_finding "SERVICES" "$proj" "BigQuery Dataset" "$ds" "Services - Storage Hygiene" \
          "No default table expiration set (informational)" "Dataset ${ds} has no defaultTableExpirationMs" "LOW" "bq datasets describe" \
          "If this dataset is used for staging/ad-hoc/temp tables, set a default table expiration to auto-clean stale data and reduce both cost and the amount of sensitive data sitting around unnecessarily."
      fi
    done

    # Data Access audit logs for BigQuery (informational - confirm via log read whether jobs are being logged)
    local bq_log_check
    bq_log_check=$(run_gcloud "bq audit log check" gcloud logging read \
      "resource.type=\"bigquery_resource\" AND timestamp>=\"$(date -d "-7 days" -u +%Y-%m-%dT%H:%M:%SZ)\"" \
      --project="$proj" --limit=1 --format="value(timestamp)" 2>>"$LOG_FILE")
    if [ -z "$bq_log_check" ]; then
      add_finding "SECURITY" "$proj" "BigQuery" "project/${proj}" "Security - Storage Deep-Dive" \
        "No recent BigQuery audit log activity found (informational)" \
        "No bigquery_resource log entries found in the last 7 days for ${proj} - confirm whether BigQuery is actually unused here, or whether Data Access logs need enabling" \
        "LOW" "logging read resource.type=bigquery_resource" \
        "If BigQuery is in active use, confirm Data Access audit logs are enabled (they are charged separately from Admin Activity logs) so query-level access is captured for forensics. If BigQuery truly isn't used, this is just confirmation - no action needed."
    fi
  done
}

audit_cloudsql_deep() {
  log_info "[STORAGE/DB] Deep-diving Cloud SQL (CMEK, deletion protection, HA, maintenance window)..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue
    local out="${RAW_DIR}/sql_${proj}.json"
    [ -s "$out" ] || run_gcloud_long "sql instances list" gcloud sql instances list --project="$proj" --format=json > "$out" 2>/dev/null
    [ -s "$out" ] || continue
    jq -c '.[]?' "$out" 2>/dev/null | while read -r inst; do
      local name cmek deletion_protection availability
      name=$(echo "$inst" | jq -r '.name')
      cmek=$(echo "$inst" | jq -r '.diskEncryptionConfiguration.kmsKeyName // "google-managed"')
      deletion_protection=$(echo "$inst" | jq -r '.settings.deletionProtectionEnabled // false')
      availability=$(echo "$inst" | jq -r '.settings.availabilityType // "ZONAL"')

      [ "$cmek" = "google-managed" ] && add_finding "SERVICES" "$proj" "Cloud SQL Instance" "$name" "Security - Storage Deep-Dive" \
        "Instance uses Google-managed encryption, not CMEK" "Instance ${name} has no diskEncryptionConfiguration" "LOW" "sql instances list" \
        "For regulated data, recreate/configure the instance with a CMEK key for direct control over key lifecycle."

      [ "$deletion_protection" != "true" ] && add_finding "SECURITY" "$proj" "Cloud SQL Instance" "$name" "Security - Storage Deep-Dive" \
        "Deletion protection disabled" "Instance ${name} can be deleted without an extra confirmation step" "MEDIUM" "sql instances list" \
        "Enable deletion protection so this instance can't be deleted by a single mistaken/malicious command: 'gcloud sql instances patch NAME --deletion-protection'."

      [ "$availability" = "ZONAL" ] && add_finding "SERVICES" "$proj" "Cloud SQL Instance" "$name" "Services - Storage Deep-Dive" \
        "No High Availability configured (informational)" "Instance ${name} is ZONAL (single zone, no automatic failover)" "LOW" "sql instances list" \
        "If this is a production database, switch to REGIONAL availabilityType for automatic failover across zones - this is a resilience, not strictly security, recommendation but belongs in the same review."
    done
  done
}

audit_spanner_and_bigtable() {
  log_info "[STORAGE/DB] Auditing Cloud Spanner and Bigtable instances for public IAM bindings..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue

    local sp_out="${RAW_DIR}/spanner_${proj}.json"
    run_gcloud_long "spanner instances list" gcloud spanner instances list --project="$proj" --format=json > "$sp_out" 2>/dev/null
    jq -r '.[]?.name' "$sp_out" 2>/dev/null | while read -r inst; do
      [ -z "$inst" ] && continue
      local inst_short policy
      inst_short=$(basename "$inst")
      policy=$(run_gcloud "spanner iam policy" gcloud spanner instances get-iam-policy "$inst_short" --project="$proj" --format=json 2>/dev/null)
      if echo "$policy" | grep -Eq 'allUsers|allAuthenticatedUsers'; then
        add_finding "SECURITY" "$proj" "Cloud Spanner Instance" "$inst_short" "Security - Storage Deep-Dive" \
          "Publicly accessible Spanner instance" "Instance ${inst_short} grants access to allUsers/allAuthenticatedUsers" \
          "CRITICAL" "spanner instances get-iam-policy" \
          "Remove the public binding immediately and restrict to named principals/service accounts. Spanner typically holds primary transactional data - public exposure here is a top-tier incident."
      else
        add_finding "SERVICES" "$proj" "Cloud Spanner Instance" "$inst_short" "Services - Storage Deep-Dive" \
          "Spanner instance in use (informational - review databases manually)" \
          "Instance ${inst_short} exists; review its databases individually for CMEK, IAM, and backup schedule, which this script does not enumerate at the database level" \
          "LOW" "spanner instances list" \
          "Run 'gcloud spanner databases list --instance=${inst_short}' and check each database's backup schedule and encryption config manually, or extend this script's spanner function to loop databases too."
      fi
    done

    local bt_out="${RAW_DIR}/bigtable_${proj}.json"
    run_gcloud_long "bigtable instances list" gcloud bigtable instances list --project="$proj" --format=json > "$bt_out" 2>/dev/null
    jq -r '.[]?.name' "$bt_out" 2>/dev/null | while read -r inst; do
      [ -z "$inst" ] && continue
      local inst_short policy
      inst_short=$(basename "$inst")
      policy=$(run_gcloud "bigtable iam policy" gcloud bigtable instances get-iam-policy "$inst_short" --project="$proj" --format=json 2>/dev/null)
      if echo "$policy" | grep -Eq 'allUsers|allAuthenticatedUsers'; then
        add_finding "SECURITY" "$proj" "Bigtable Instance" "$inst_short" "Security - Storage Deep-Dive" \
          "Publicly accessible Bigtable instance" "Instance ${inst_short} grants access to allUsers/allAuthenticatedUsers" \
          "CRITICAL" "bigtable instances get-iam-policy" \
          "Remove the public binding immediately and restrict to named principals/service accounts."
      fi
    done
  done
}

audit_memorystore_and_filestore() {
  log_info "[STORAGE/DB] Auditing Memorystore (Redis) and Filestore for auth/encryption/network exposure..."
  for proj in "${PROJECTS[@]}"; do
    [ -z "$proj" ] && continue

    local redis_out="${RAW_DIR}/redis_${proj}.json"
    run_gcloud_long "redis instances list" gcloud redis instances list --project="$proj" --region=- --format=json > "$redis_out" 2>/dev/null
    jq -c '.[]?' "$redis_out" 2>/dev/null | while read -r r; do
      local name auth_enabled transit_enc
      name=$(echo "$r" | jq -r '.name' | awk -F/ '{print $NF}')
      auth_enabled=$(echo "$r" | jq -r '.authEnabled // false')
      transit_enc=$(echo "$r" | jq -r '.transitEncryptionMode // "DISABLED"')

      [ "$auth_enabled" != "true" ] && add_finding "SECURITY" "$proj" "Memorystore Redis" "$name" "Security - Storage Deep-Dive" \
        "AUTH not enabled on Redis instance" "Instance ${name} does not require an AUTH token to connect" "HIGH" "redis instances list" \
        "Enable AUTH so any client on the network path still needs a credential to connect: 'gcloud redis instances update NAME --auth-enabled --region=REGION'. Even though Memorystore is VPC-internal, defense in depth matters for lateral-movement scenarios."

      [ "$transit_enc" = "DISABLED" ] && add_finding "SECURITY" "$proj" "Memorystore Redis" "$name" "Security - Storage Deep-Dive" \
        "In-transit encryption disabled" "Instance ${name} does not encrypt traffic in transit" "MEDIUM" "redis instances list" \
        "Enable in-transit encryption (TLS) if your client library supports it: 'gcloud redis instances update NAME --transit-encryption-mode=SERVER_AUTHENTICATION'."
    done

    local fs_out="${RAW_DIR}/filestore_${proj}.json"
    run_gcloud_long "filestore instances list" gcloud filestore instances list --project="$proj" --format=json > "$fs_out" 2>/dev/null
    jq -c '.[]?' "$fs_out" 2>/dev/null | while read -r f; do
      local name net_mode
      name=$(echo "$f" | jq -r '.name' | awk -F/ '{print $NF}')
      net_mode=$(echo "$f" | jq -r '.networks[0].modes[0] // "unknown"')
      add_finding "SERVICES" "$proj" "Filestore Instance" "$name" "Services - Storage Deep-Dive" \
        "Filestore instance in use (informational)" \
        "Instance ${name} uses network mode ${net_mode} - confirm it's reachable only from intended VPC/subnets, with NFS exports scoped to specific IP ranges, not 0.0.0.0/0" \
        "LOW" "filestore instances list" \
        "Manually confirm the NFS export's ipRanges restrict access to only the client subnets that need it ('gcloud filestore instances describe NAME' -> fileShares[].nfsExportOptions)."
    done
  done
}

audit_storage_db_deepdive_section() {
  [ "$RUN_STORAGE_DB_DEEPDIVE" != "true" ] && { log_info "[STORAGE/DB] Skipped (RUN_STORAGE_DB_DEEPDIVE=false)"; return; }
  audit_gcs_deep
  audit_bigquery_deep
  audit_cloudsql_deep
  audit_spanner_and_bigtable
  audit_memorystore_and_filestore
}

###############################################################################
# 7D. SECTION F — BILLING/USAGE-DRIVEN SCOPE & COVERAGE-GAP DETECTION
#
#     Idea: don't just audit what we assumed exists - audit what you're
#     actually being billed for / actually running, and explicitly call out
#     any in-use service this script does NOT have a dedicated check for yet,
#     so nothing expensive-and-running slips through unaudited.
###############################################################################

# Asset types this script has a dedicated, specific audit function for.
# Keep this in sync whenever you add a new audit_* function above.
COVERED_ASSET_TYPES=(
  "compute.googleapis.com/Instance"
  "compute.googleapis.com/Firewall"
  "compute.googleapis.com/Disk"
  "compute.googleapis.com/Subnetwork"
  "compute.googleapis.com/Network"
  "storage.googleapis.com/Bucket"
  "sqladmin.googleapis.com/Instance"
  "container.googleapis.com/Cluster"
  "cloudkms.googleapis.com/CryptoKey"
  "run.googleapis.com/Service"
  "cloudfunctions.googleapis.com/CloudFunction"
  "bigquery.googleapis.com/Dataset"
  "artifactregistry.googleapis.com/Repository"
  "iam.googleapis.com/ServiceAccount"
  "dns.googleapis.com/ManagedZone"
  "spanner.googleapis.com/Instance"
  "bigtableadmin.googleapis.com/Instance"
  "redis.googleapis.com/Instance"
  "file.googleapis.com/Instance"
  "cloudbuild.googleapis.com/Build"
)

audit_billing_cost_by_service() {
  if [ -z "$BILLING_EXPORT_TABLE" ]; then
    log_info "[BILLING] Skipping cost-based prioritization - set BILLING_EXPORT_TABLE (BigQuery billing export) to enable."
    add_finding "SERVICES" "${ASSET_SCOPE:-N/A}" "Billing Export" "N/A" "Services - Cost Governance" \
      "BigQuery Billing Export not configured for this audit run" \
      "BILLING_EXPORT_TABLE was not set, so cost-by-service prioritization could not run" \
      "LOW" "n/a" \
      "Enable BigQuery Billing Export (Billing > Billing export > BigQuery export) and re-run this script with BILLING_EXPORT_TABLE set. This lets the audit prioritize by what you actually pay for, surfacing forgotten-but-running resources (e.g. an old Spanner instance nobody remembers) that asset inventory alone won't flag as 'important'."
    return 0
  fi
  if ! command -v bq >/dev/null 2>&1; then
    log_warn "[BILLING] 'bq' CLI not found; cannot query BILLING_EXPORT_TABLE. Install via: gcloud components install bq  (or apt-get install google-cloud-cli-bq)"
    return 0
  fi

  log_info "[BILLING] Querying top ${BILLING_TOP_N_SERVICES} services by spend over last ${BILLING_LOOKBACK_DAYS} days..."
  local out="${RAW_DIR}/billing_top_services.json"
  bq query --use_legacy_sql=false --format=json --quiet "
    SELECT service.description AS service, ROUND(SUM(cost),2) AS total_cost, currency
    FROM \`${BILLING_EXPORT_TABLE}\`
    WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL ${BILLING_LOOKBACK_DAYS} DAY)
    GROUP BY service, currency
    ORDER BY total_cost DESC
    LIMIT ${BILLING_TOP_N_SERVICES}
  " > "$out" 2>>"$LOG_FILE"

  if [ ! -s "$out" ] || ! jq -e 'length > 0' "$out" >/dev/null 2>&1; then
    log_warn "[BILLING] Billing export query returned no rows - check BILLING_EXPORT_TABLE and permissions."
    return 0
  fi

  jq -c '.[]?' "$out" 2>/dev/null | while read -r row; do
    local svc cost cur
    svc=$(echo "$row" | jq -r '.service')
    cost=$(echo "$row" | jq -r '.total_cost')
    cur=$(echo "$row" | jq -r '.currency')
    add_finding "SERVICES" "${ASSET_SCOPE:-N/A}" "Billed Service" "$svc" "Services - Cost Governance" \
      "Active spend detected (informational, cost-prioritization signal)" \
      "Service '${svc}' incurred ${cost} ${cur} over the last ${BILLING_LOOKBACK_DAYS} days" \
      "LOW" "BigQuery billing export query" \
      "Cross-reference this against the rest of the report: any service here with real spend should have at least one finding above addressing its IAM/network/encryption posture. If it has zero other findings in this report, that's a coverage gap - review it manually or extend the script."
  done
}

audit_usage_driven_coverage_gaps() {
  [ -z "$ASSET_SCOPE" ] && { log_info "[BILLING] Skipping usage-driven coverage-gap check - no ASSET_SCOPE."; return 0; }
  log_info "[BILLING] Cross-checking actual deployed asset types against this script's audit coverage..."
  local out="${RAW_DIR}/all_resource_asset_types.json"
  run_gcloud_long "search-all-resources" gcloud asset search-all-resources \
    --scope="$ASSET_SCOPE" --format=json > "$out" || return 0
  [ -s "$out" ] || return 0

  jq -r '.[].assetType' "$out" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count atype; do
    [ -z "$atype" ] && continue
    local covered="false"
    for c in "${COVERED_ASSET_TYPES[@]}"; do
      [ "$c" = "$atype" ] && covered="true" && break
    done
    if [ "$covered" = "false" ]; then
      add_finding "SERVICES" "$ASSET_SCOPE" "Asset Type" "$atype" "Services - Coverage Gap" \
        "In-use resource type with no dedicated audit check" \
        "${count} resource(s) of type '${atype}' exist in scope but this script has no dedicated security check for that type" \
        "MEDIUM" "asset search-all-resources (grouped by assetType)" \
        "This resource type is actually deployed (not just theoretically enabled) and currently has zero targeted coverage in this audit. At minimum, manually review its IAM bindings ('gcloud asset search-all-iam-policies --scope=${ASSET_SCOPE} --query=\"resource:${atype}\"') and any public/network exposure. Consider adding a dedicated audit_* function for it (common candidates: Pub/Sub, Dataflow, Composer, Dataproc, Vertex AI, App Engine, Cloud Tasks, Cloud Scheduler, API Gateway, Cloud Interconnect/VPN)."
    fi
  done
}

audit_billing_section() {
  [ "$RUN_BILLING_DRIVEN_AUDIT" != "true" ] && { log_info "[BILLING] Skipped (RUN_BILLING_DRIVEN_AUDIT=false)"; return; }
  audit_billing_cost_by_service
  audit_usage_driven_coverage_gaps
}

###############################################################################
# 8. REPORT GENERATION (HTML view on top of the CSV)
###############################################################################

generate_html_report() {
  log_info "Generating HTML report..."
  {
    echo "<html><head><meta charset='utf-8'><title>GCP Audit Report ${TIMESTAMP}</title>"
    echo "<style>
      body{font-family:Arial,sans-serif;margin:20px;background:#f7f7f8}
      h1{color:#1a73e8} .summary{margin-bottom:16px}
      table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
      th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
      th{background:#1a73e8;color:#fff;position:sticky;top:0}
      tr:nth-child(even){background:#f2f2f2}
      .CRITICAL{background:#fde7e9!important;font-weight:bold}
      .HIGH{background:#fff1e0!important}
      .MEDIUM{background:#fff9db!important}
      .LOW{background:#e9f7ef!important}
    </style></head><body>"
    echo "<h1>GCP Comprehensive Audit Report</h1>"
    echo "<div class='summary'>Generated: ${TIMESTAMP} | Scope: ${ASSET_SCOPE:-N/A} | Projects: ${#PROJECTS[@]} | Total findings: ${FINDINGS_COUNT} | Critical: ${CRITICAL_COUNT} | High: ${HIGH_COUNT}</div>"
    echo "<table><tr><th>Scope Type</th><th>Scope</th><th>Resource Type</th><th>Resource</th><th>Category</th><th>Check</th><th>Finding</th><th>Severity</th><th>Evidence</th><th>Recommendation</th></tr>"
    tail -n +2 "$CSV_FILE" | while IFS=, read -r -a fields; do
      : # placeholder, replaced below by python-free awk approach
    done
  } > "$HTML_FILE"

  # Use a small awk CSV->HTML converter that handles quoted commas correctly.
  awk -F'\0' 'BEGIN{print ""}' /dev/null # no-op to keep awk available check simple
  python3 - "$CSV_FILE" >> "$HTML_FILE" <<'PYEOF' 2>/dev/null || {
import csv,sys,html
with open(sys.argv[1], newline='', encoding='utf-8') as f:
    r = csv.reader(f)
    next(r, None)
    for row in r:
        if len(row) < 10: continue
        sev = row[7].strip()
        cells = "".join(f"<td>{html.escape(c)}</td>" for c in row)
        print(f"<tr class='{html.escape(sev)}'>{cells}</tr>")
PYEOF
    log_warn "python3 not available for HTML row conversion; HTML report will only contain headers. CSV report is fully populated regardless."
  }
  echo "</table></body></html>" >> "$HTML_FILE"
}

print_summary() {
  echo ""
  echo "==================================================================="
  echo " GCP AUDIT COMPLETE"
  echo "==================================================================="
  echo " Scope:            ${ASSET_SCOPE:-N/A}"
  echo " Projects audited: ${#PROJECTS[@]}"
  echo " Total findings:   ${FINDINGS_COUNT}"
  echo "   CRITICAL:       ${CRITICAL_COUNT}"
  echo "   HIGH:           ${HIGH_COUNT}"
  echo " CSV report:       ${CSV_FILE}"
  echo " HTML report:      ${HTML_FILE}"
  echo " Raw evidence:     ${RAW_DIR}/"
  echo " Run log:          ${LOG_FILE}"
  echo "==================================================================="
}

###############################################################################
# 9. MAIN
###############################################################################

main() {
  check_prerequisites
  resolve_scope
  audit_iam_section
  audit_security_section
  audit_services_section
  audit_extended_section
  audit_storage_db_deepdive_section
  audit_billing_section
  generate_html_report
  print_summary
}

main "$@"
