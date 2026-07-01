#Requires -Version 5.1
<#
###############################################################################
# GCP COMPREHENSIVE AUDIT SCRIPT (PowerShell port)
#
# Audits IAM, Security, and Services/Misconfigurations across an Org, Folder,
# or Project (or a list of Projects), and produces a CSV (+ HTML) report with
# a Recommendation/Resolution column for every finding.
#
# Defensive security audit only. Strictly READ-ONLY (list/get/describe/
# search/read calls only) - no destructive actions are ever taken.
#
# REQUIREMENTS
#   - gcloud CLI installed & authenticated: `gcloud auth login` /
#     `gcloud auth application-default login`
#   - PowerShell 7+ recommended (5.1 works, but ForEach-Object -Parallel for
#     multi-project runs needs 7+; see notes at the bottom of this file).
#   - Same IAM roles / enabled APIs as the bash version (see original header).
#
# USAGE
#   1. Set the env vars below (see "CONFIGURATION" section) before running,
#      or edit the $Defaults hashtable directly.
#   2. .\gcp_comprehensive_audit.ps1
#   3. Open the CSV in Excel/Sheets, or the HTML file in a browser.
###############################################################################
#>

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

###############################################################################
# 1. CONFIGURATION - EVERYTHING IS A VARIABLE. EDIT HERE OR SET ENV VARS FIRST.
###############################################################################

function Get-EnvOrDefault {
    param([string]$Name, [string]$Default = '')
    $val = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($val)) { return $Default }
    return $val
}

# --- Scope: choose ONE primary scope. Leave the others blank. ---------------
$OrgId     = Get-EnvOrDefault 'ORG_ID'     ''   # e.g. "123456789012"
$FolderId  = Get-EnvOrDefault 'FOLDER_ID'  ''   # e.g. "987654321098"
$ProjectId = Get-EnvOrDefault 'PROJECT_ID' ''   # e.g. "my-single-project"

# Explicit project list (space separated). If set, OVERRIDES org/folder
# discovery for per-project checks (org/folder-wide checks still use OrgId/FolderId).
$ProjectsOverride = Get-EnvOrDefault 'PROJECTS_OVERRIDE' ''

# --- Thresholds (days) -------------------------------------------------------
$SaKeyAgeDays          = [int](Get-EnvOrDefault 'SA_KEY_AGE_DAYS' '90')
$SaInactivityDays      = [int](Get-EnvOrDefault 'SA_INACTIVITY_DAYS' '90')
$LogLookbackDays       = [int](Get-EnvOrDefault 'LOG_LOOKBACK_DAYS' '90')
$KmsRotationMaxDays    = [int](Get-EnvOrDefault 'KMS_ROTATION_MAX_DAYS' '90')
$CertExpiryWarnDays    = [int](Get-EnvOrDefault 'CERT_EXPIRY_WARN_DAYS' '30')

# --- Risk definitions ---------------------------------------------------------
$PrimitiveRoles = (Get-EnvOrDefault 'PRIMITIVE_ROLES' 'roles/owner roles/editor roles/viewer') -split ' '
$RiskyPorts     = (Get-EnvOrDefault 'RISKY_PORTS' '20,21,22,23,135,445,1433,1434,3306,3389,5432,5900,5984,6379,9200,9300,11211,27017,27018') -split ','
# Secret-like pattern (case-insensitive). Same intent as the bash SECRET_REGEX.
$SecretRegex = Get-EnvOrDefault 'SECRET_REGEX' '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----|(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token)\s*[=:]\s*[\"''][^\"'']{6,})'

# --- Optional inputs for the extended (Section D) checks ---------------------
$BillingAccountId    = Get-EnvOrDefault 'BILLING_ACCOUNT_ID' ''
$AccessPolicyId      = Get-EnvOrDefault 'ACCESS_POLICY_ID' ''
$MinTlsVersion       = Get-EnvOrDefault 'MIN_TLS_VERSION' 'TLS_1_2'
$SslCertExpiryWarnDays = [int](Get-EnvOrDefault 'SSL_CERT_EXPIRY_WARN_DAYS' '30')

# --- Billing-driven scoping ---------------------------------------------------
$BillingExportTable    = Get-EnvOrDefault 'BILLING_EXPORT_TABLE' ''
$BillingLookbackDays   = [int](Get-EnvOrDefault 'BILLING_LOOKBACK_DAYS' '30')
$BillingTopNServices   = [int](Get-EnvOrDefault 'BILLING_TOP_N_SERVICES' '25')

# --- Toggles -------------------------------------------------------------------
$RunIamAudit               = (Get-EnvOrDefault 'RUN_IAM_AUDIT' 'true') -eq 'true'
$RunSecurityAudit          = (Get-EnvOrDefault 'RUN_SECURITY_AUDIT' 'true') -eq 'true'
$RunServicesAudit          = (Get-EnvOrDefault 'RUN_SERVICES_AUDIT' 'true') -eq 'true'
$RunSccAudit               = (Get-EnvOrDefault 'RUN_SCC_AUDIT' 'true') -eq 'true'
$RunExtendedAudit          = (Get-EnvOrDefault 'RUN_EXTENDED_AUDIT' 'true') -eq 'true'
$RunStorageDbDeepdive      = (Get-EnvOrDefault 'RUN_STORAGE_DB_DEEPDIVE' 'true') -eq 'true'
$RunBillingDrivenAudit     = (Get-EnvOrDefault 'RUN_BILLING_DRIVEN_AUDIT' 'true') -eq 'true'
$EnableLogBasedSaActivity  = (Get-EnvOrDefault 'ENABLE_LOG_BASED_SA_ACTIVITY' 'true') -eq 'true'

# --- Output -------------------------------------------------------------------
$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutputDir  = Get-EnvOrDefault 'OUTPUT_DIR' ".\gcp_audit_$Timestamp"
$CsvFile    = Join-Path $OutputDir 'gcp_audit_report.csv'
$HtmlFile   = Join-Path $OutputDir 'gcp_audit_report.html'
$LogFile    = Join-Path $OutputDir 'run.log'
$RawDir     = Join-Path $OutputDir 'raw'

$GcloudTimeout     = [int](Get-EnvOrDefault 'GCLOUD_TIMEOUT' '90')       # seconds
$GcloudTimeoutLong = [int](Get-EnvOrDefault 'GCLOUD_TIMEOUT_LONG' '240') # seconds

###############################################################################
# 2. INTERNAL STATE
###############################################################################

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path $RawDir | Out-Null
New-Item -ItemType File -Force -Path $LogFile | Out-Null

$script:FindingsCount = 0
$script:CriticalCount = 0
$script:HighCount     = 0
$script:Findings      = [System.Collections.Generic.List[object]]::new()

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}
function Log-Info { param([string]$m) Write-Log "INFO  - $m" }
function Log-Warn { param([string]$m) Write-Log "WARN  - $m" }
function Log-Err  { param([string]$m) Write-Log "ERROR - $m" }

# Add-Finding: mirrors add_finding() in the bash script.
function Add-Finding {
    param(
        [string]$ScopeType, [string]$ScopeId, [string]$ResourceType, [string]$ResourceName,
        [string]$Category, [string]$Check, [string]$Finding, [string]$Severity,
        [string]$Evidence, [string]$Recommendation
    )
    $script:Findings.Add([PSCustomObject]@{
        scope_type     = $ScopeType
        scope_id       = $ScopeId
        resource_type  = $ResourceType
        resource_name  = $ResourceName
        category       = $Category
        check          = $Check
        finding        = $Finding
        severity       = $Severity
        evidence       = $Evidence
        recommendation = $Recommendation
    })
    $script:FindingsCount++
    switch ($Severity) {
        'CRITICAL' { $script:CriticalCount++ }
        'HIGH'     { $script:HighCount++ }
    }
}

# Invoke-Gcloud: runs an external command (gcloud/bq/etc.) with a timeout and
# ONE retry with a doubled timeout on timeout - mirrors run_gcloud/run_gcloud_long.
# Returns raw stdout text, or $null on failure. Always logs stderr to $LogFile.
function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSeconds = 90
    )
    $attempt = 1
    $maxAttempts = 2
    $timeout = $TimeoutSeconds

    while ($attempt -le $maxAttempts) {
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        try {
            $psi = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
                -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile

            $finished = $psi.WaitForExit($timeout * 1000)
            if (-not $finished) {
                try { $psi.Kill() } catch {}
                Get-Content $stderrFile -ErrorAction SilentlyContinue | Add-Content -Path $LogFile
                if ($attempt -lt $maxAttempts) {
                    Log-Warn "Timeout after ${timeout}s ($Description, attempt $attempt/$maxAttempts); retrying with doubled timeout..."
                    $timeout = $timeout * 2
                    $attempt++
                    Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
                    continue
                } else {
                    Log-Warn "Command timed out after ${timeout}s on final attempt ($Description), rc=124: $FilePath $($Arguments -join ' ')  |  Consider raising -TimeoutSeconds and re-running."
                    Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
                    return $null
                }
            }

            $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
            $stderrLines = Get-Content $stderrFile -ErrorAction SilentlyContinue
            if ($stderrLines) { $stderrLines | Add-Content -Path $LogFile }

            if ($psi.ExitCode -eq 0) {
                Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
                return $stdout
            } else {
                $lastErr = ($stderrLines | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -Last 1)
                Log-Warn "Command failed ($Description), rc=$($psi.ExitCode)$(if ($lastErr) { " -> $lastErr" }): $FilePath $($Arguments -join ' ')"
                Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
                return $null
            }
        }
        finally {
            Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
        }
    }
    return $null
}

# Convenience wrappers matching run_gcloud / run_gcloud_long. Pass gcloud args
# as a string array; --format=json is added by the caller when JSON is wanted.
function Invoke-Gcloud {
    param([string]$Description, [string[]]$GcloudArgs)
    Invoke-ExternalCommand -Description $Description -FilePath 'gcloud' -Arguments $GcloudArgs -TimeoutSeconds $GcloudTimeout
}
function Invoke-GcloudLong {
    param([string]$Description, [string[]]$GcloudArgs)
    Invoke-ExternalCommand -Description $Description -FilePath 'gcloud' -Arguments $GcloudArgs -TimeoutSeconds $GcloudTimeoutLong
}

# Runs a gcloud command expected to return JSON, parses it, returns an array
# (empty array on failure/empty output) - mirrors the "run_gcloud ... > out.json; jq" pattern.
function Get-GcloudJson {
    param([string]$Description, [string[]]$GcloudArgs, [switch]$Long, [string]$RawFile)
    $args2 = $GcloudArgs
    if ($args2 -notcontains '--format=json') { $args2 += '--format=json' }
    $raw = if ($Long) { Invoke-GcloudLong -Description $Description -GcloudArgs $args2 } else { Invoke-Gcloud -Description $Description -GcloudArgs $args2 }
    if ($RawFile -and $raw) { Set-Content -Path $RawFile -Value $raw }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $parsed) { return @() }
        if ($parsed -is [System.Array]) { return $parsed }
        return @($parsed)
    } catch {
        return @()
    }
}

function Test-SecretPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return [regex]::IsMatch($Text, $SecretRegex, 'IgnoreCase')
}

###############################################################################
# 3. PREREQUISITE CHECKS
###############################################################################

function Test-Prerequisites {
    Log-Info "Checking prerequisites..."

    if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
        Log-Err "gcloud CLI not found in PATH. Install it: https://cloud.google.com/sdk/docs/install"
        exit 1
    }

    $accounts = Invoke-Gcloud -Description "auth list" -GcloudArgs @('auth','list','--filter=status:ACTIVE','--format=value(account)')
    if ([string]::IsNullOrWhiteSpace($accounts)) {
        Log-Err "No active gcloud auth session found. Run: gcloud auth login"
        exit 1
    }
    $script:ActiveAccount = ($accounts -split "`n")[0].Trim()
    Log-Info "Authenticated as: $script:ActiveAccount"

    if ([string]::IsNullOrEmpty($OrgId) -and [string]::IsNullOrEmpty($FolderId) -and [string]::IsNullOrEmpty($ProjectId) -and [string]::IsNullOrEmpty($ProjectsOverride)) {
        Log-Err "No scope set. Set ORG_ID, FOLDER_ID, PROJECT_ID, or PROJECTS_OVERRIDE (as environment variables)."
        exit 1
    }

    Log-Info "Report will be written to: $CsvFile"
}

###############################################################################
# 4. SCOPE / ASSET RESOLUTION
###############################################################################

$script:Projects   = @()
$script:AssetScope = ''

function Resolve-Scope {
    Log-Info "Resolving audit scope..."

    if ($OrgId)     { $script:AssetScope = "organizations/$OrgId" }
    elseif ($FolderId)  { $script:AssetScope = "folders/$FolderId" }
    elseif ($ProjectId) { $script:AssetScope = "projects/$ProjectId" }

    if ($ProjectsOverride) {
        $script:Projects = $ProjectsOverride -split '\s+' | Where-Object { $_ }
    }
    elseif ($ProjectId) {
        $script:Projects = @($ProjectId)
    }
    elseif ($FolderId) {
        $raw = Invoke-Gcloud -Description "projects list (folder)" -GcloudArgs @('projects','list',"--filter=parent.id=$FolderId AND parent.type=folder",'--format=value(projectId)')
        $script:Projects = @($raw -split "`n" | Where-Object { $_ -and $_.Trim() -ne '' })
    }
    elseif ($OrgId) {
        $raw = Invoke-Gcloud -Description "projects list (org)" -GcloudArgs @('projects','list',"--filter=parent.id=$OrgId AND parent.type=organization",'--format=value(projectId)')
        $script:Projects = @($raw -split "`n" | Where-Object { $_ -and $_.Trim() -ne '' })
        if ($script:Projects.Count -eq 0) {
            Log-Warn "No projects directly parented at org root found; falling back to Cloud Asset Inventory for project discovery."
            $raw2 = Invoke-GcloudLong -Description "asset search-all-resources (projects)" -GcloudArgs @('asset','search-all-resources',"--scope=$script:AssetScope",'--asset-types=cloudresourcemanager.googleapis.com/Project','--format=value(project)')
            $script:Projects = @($raw2 -split "`n" | Where-Object { $_ } | Sort-Object -Unique)
        }
    }

    Log-Info "Asset scope: $(if ($script:AssetScope) { $script:AssetScope } else { '<none>' })"
    Log-Info "Projects in scope ($($script:Projects.Count)): $($script:Projects -join ' ')"

    if ($script:Projects.Count -eq 0 -and [string]::IsNullOrEmpty($script:AssetScope)) {
        Log-Err "Could not resolve any projects to audit. Check your scope variables and IAM permissions."
        exit 1
    }
}

###############################################################################
# 5. SECTION A - IAM AUDIT
###############################################################################

function Invoke-IamOrgWideBindings {
    Log-Info "[IAM] Pulling all IAM policy bindings across scope via Cloud Asset Inventory..."
    if (-not $script:AssetScope) { return }
    $out = Join-Path $RawDir 'iam_policies.json'
    $policies = Get-GcloudJson -Description "search-all-iam-policies" -Long -RawFile $out -GcloudArgs @('asset','search-all-iam-policies',"--scope=$script:AssetScope")
    if ($policies.Count -eq 0) { return }

    foreach ($r in $policies) {
        foreach ($b in @($r.policy.bindings)) {
            if (-not $b) { continue }
            $members = @($b.members)

            # 1) Primitive roles
            if ($PrimitiveRoles -contains $b.role) {
                Add-Finding "IAM" $script:AssetScope "IAM Binding" $r.resource "IAM" `
                    "Primitive role usage" `
                    "Primitive role '$($b.role)' granted directly on $($r.resource) to: $($members -join ';')" `
                    "HIGH" "search-all-iam-policies" `
                    "Replace primitive roles (Owner/Editor/Viewer) with least-privilege predefined or custom roles. Use IAM Recommender (google.iam.policy.Recommender) to find the minimal role set. Owner/Editor at project level is one of the most common causes of breach blast-radius expansion."
            }

            # 2) Public / anonymous access
            if ($members -contains 'allUsers' -or $members -contains 'allAuthenticatedUsers') {
                Add-Finding "IAM" $script:AssetScope "IAM Binding" $r.resource "IAM" `
                    "Public IAM binding" `
                    "Resource $($r.resource) grants '$($b.role)' to allUsers/allAuthenticatedUsers" `
                    "CRITICAL" "search-all-iam-policies" `
                    "Remove allUsers/allAuthenticatedUsers bindings unless the resource is intentionally a public endpoint (e.g. a public website bucket). If intentional, document it and restrict to only the specific role/resource needed (e.g. objectViewer on a single bucket, not project-wide)."
            }

            # 3) Org/Folder-level grants (informational)
            if ($r.resource -match 'organizations/|folders/') {
                Add-Finding "IAM" $script:AssetScope "IAM Binding" $r.resource "IAM" `
                    "Org/Folder-level grant (review)" `
                    "Role '$($b.role)' granted at $($r.resource) to: $($members -join ';')" `
                    "MEDIUM" "search-all-iam-policies" `
                    "Org/folder-level grants apply to every project beneath them. Confirm this is intentional and scoped to the minimum role necessary; prefer granting at the project or resource level instead of org/folder where possible."
            }
        }
    }
}

function Invoke-IamUnusedPermissionsRecommender {
    Log-Info "[IAM] Checking IAM Recommender for over-privileged / unused-permission findings..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "iam_recommender_$proj.json"
        $recs = Get-GcloudJson -Description "iam recommender $proj" -Long -RawFile $out -GcloudArgs @('recommender','recommendations','list',"--project=$proj",'--recommender=google.iam.policy.Recommender','--location=global')
        foreach ($rec in $recs) {
            if ($rec.stateInfo.state -ne 'ACTIVE') { continue }
            $resource = $rec.content.overview.resource
            if (-not $resource) { $resource = $rec.content.operationGroups[0].operations[0].resource }
            if (-not $resource) { $resource = 'unknown' }
            $desc = if ($rec.description) { $rec.description } else { 'Unused or excessive IAM permissions detected' }
            Add-Finding "IAM" $proj "Service Account / Principal" $resource "IAM" `
                "Unused/excessive permissions (IAM Recommender)" `
                $desc "HIGH" "recommender.recommendations.list (google.iam.policy.Recommender)" `
                "Apply the IAM Recommender suggestion directly: 'gcloud recommender recommendations mark-claimed/mark-succeeded' after applying, or apply via Console > IAM > Recommendations tab. This automatically right-sizes the role based on 90 days of actual usage from audit logs."
        }
    }
}

function Invoke-ServiceAccountsAndKeys {
    Log-Info "[IAM] Auditing service accounts and their keys..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $saOut = Join-Path $RawDir "service_accounts_$proj.json"
        $sas = Get-GcloudJson -Description "list SAs $proj" -RawFile $saOut -GcloudArgs @('iam','service-accounts','list',"--project=$proj")
        if ($sas.Count -eq 0) { continue }

        foreach ($sa in $sas) {
            $saEmail = $sa.email
            if (-not $saEmail) { continue }

            if ($saEmail -match '-compute@developer\.gserviceaccount\.com$' -or $saEmail -match '@appspot\.gserviceaccount\.com$') {
                Add-Finding "IAM" $proj "Service Account" $saEmail "IAM" `
                    "Default service account in use" `
                    "Default Compute/App Engine service account exists and may still be attached to running resources with broad (often Editor) permissions" `
                    "MEDIUM" "iam service-accounts list" `
                    "Avoid using default service accounts for workloads. Create dedicated, minimally-scoped service accounts per workload/app, disable or remove the default SA's broad roles, and prefer Workload Identity (GKE) or attached SA with custom roles instead."
            }

            # --- Key age audit ---
            $safeName = ($saEmail -replace '[@.]', '_')
            $keysOut = Join-Path $RawDir "keys_$safeName.json"
            $keys = Get-GcloudJson -Description "list keys for $saEmail" -RawFile $keysOut -GcloudArgs @('iam','service-accounts','keys','list',"--iam-account=$saEmail",'--managed-by=user')

            foreach ($key in $keys) {
                $validAfter = $key.validAfterTime
                $ageDays = 0
                try { $ageDays = [int]((Get-Date) - [datetime]$validAfter).TotalDays } catch { $ageDays = 0 }
                if ($ageDays -ge $SaKeyAgeDays) {
                    Add-Finding "IAM" $proj "Service Account Key" $key.name "IAM" `
                        "Stale user-managed SA key" `
                        "Key for $saEmail is $ageDays days old (threshold $SaKeyAgeDays)" `
                        "HIGH" "iam service-accounts keys list --managed-by=user" `
                        "Rotate or delete this key. User-managed SA keys are long-lived static credentials and a top exfiltration target. Prefer Workload Identity Federation (keyless) for workloads outside GCP, or attached service accounts (no key needed) for workloads on GCE/GKE/Cloud Run/Cloud Functions. If a key is unavoidable, rotate every <=90 days and store it in Secret Manager, never in code or env files."
                }
            }
            if ($keys.Count -gt 0) {
                Add-Finding "IAM" $proj "Service Account" $saEmail "IAM" `
                    "User-managed key(s) present" `
                    "$saEmail has $($keys.Count) user-managed key(s)" `
                    "MEDIUM" "iam service-accounts keys list" `
                    "Confirm this key is still required. If the consuming workload runs on GCP, switch to attached-identity auth (no key) or Workload Identity Federation and delete the key."
            }

            # --- Activity / unused SA audit via Cloud Logging ---
            if ($EnableLogBasedSaActivity) {
                $since = (Get-Date).AddDays(-$LogLookbackDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $filter = "protoPayload.authenticationInfo.principalEmail=`"$saEmail`" AND timestamp>=`"$since`""
                $lastSeen = Invoke-Gcloud -Description "activity for $saEmail" -GcloudArgs @('logging','read',$filter,"--project=$proj",'--order=desc','--limit=1','--format=value(timestamp)')
                if ([string]::IsNullOrWhiteSpace($lastSeen)) {
                    Add-Finding "IAM" $proj "Service Account" $saEmail "IAM" `
                        "Unused service account (no activity in audit logs)" `
                        "No authenticated activity found for $saEmail in the last $LogLookbackDays days of audit logs" `
                        "HIGH" "logging read protoPayload.authenticationInfo.principalEmail (last ${LogLookbackDays}d)" `
                        "Confirm with the owning team whether this SA is still needed. If unused, disable it first ('gcloud iam service-accounts disable'), monitor for breakage, then delete it and any keys/role bindings. For a longer-horizon view, also check the IAM Recommender 'Unused service account' insights (google.iam.policy.Recommender) which uses 90+ day windows."
                }
            }
        }
    }
}

function Invoke-CustomRoles {
    Log-Info "[IAM] Auditing custom IAM roles for risky permissions..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "custom_roles_$proj.json"
        $roles = Get-GcloudJson -Description "list custom roles $proj" -RawFile $out -GcloudArgs @('iam','roles','list',"--project=$proj")
        foreach ($role in $roles) {
            $perms = @($role.includedPermissions)
            $risky = $perms | Where-Object { $_ -match '\.setIamPolicy$|\.delete$|\.admin$' }
            if ($risky) {
                Add-Finding "IAM" $proj "Custom Role" $role.name "IAM" `
                    "Custom role contains high-risk permissions" `
                    "Custom role $($role.name) ($($perms.Count) permissions, stage=$($role.stage)) includes setIamPolicy/delete/admin-type permissions" `
                    "MEDIUM" "iam roles list / describe" `
                    "Review whether the role truly needs IAM-modification or delete-class permissions. Split into smaller roles following least privilege; avoid granting setIamPolicy broadly since it allows privilege escalation."
            }
        }
    }
}

function Invoke-IamSection {
    if (-not $RunIamAudit) { Log-Info "[IAM] Skipped (RUN_IAM_AUDIT=false)"; return }
    Invoke-IamOrgWideBindings
    Invoke-IamUnusedPermissionsRecommender
    Invoke-ServiceAccountsAndKeys
    Invoke-CustomRoles
}

###############################################################################
# 6. SECTION B - SECURITY AUDIT
###############################################################################

function Invoke-OrgPolicies {
    if (-not $OrgId -and -not $FolderId -and -not $ProjectId) { return }
    Log-Info "[SECURITY] Auditing key Org Policy constraints..."
    $target = ''
    if ($OrgId) { $target = "organizations/$OrgId" }
    elseif ($FolderId) { $target = "folders/$FolderId" }
    elseif ($ProjectId) { $target = "projects/$ProjectId" }
    if (-not $target) { return }
    $targetType, $targetVal = $target -split '/', 2

    $recommended = [ordered]@{
        'constraints/iam.disableServiceAccountKeyCreation' = "Prevents creation of new user-managed SA keys; enforce to push teams to Workload Identity / attached SAs"
        'constraints/compute.disableSerialPortAccess'       = "Blocks serial port access to VMs, a common lateral-movement / debug-backdoor vector"
        'constraints/compute.requireOsLogin'                = "Enforces OS Login (centralized, auditable SSH access) instead of static SSH keys in metadata"
        'constraints/compute.vmExternalIpAccess'            = "Restricts which VMs may have external IPs, reducing public attack surface"
        'constraints/storage.uniformBucketLevelAccess'      = "Forces uniform bucket-level access, removing legacy ACL-based misconfig risk on GCS"
        'constraints/sql.restrictPublicIp'                  = "Prevents Cloud SQL instances from getting public IPs"
        'constraints/iam.allowedPolicyMemberDomains'        = "Restricts IAM members to approved domains/identities, blocking external/personal-Gmail grants"
        'constraints/compute.restrictXpnProjectLienRemoval' = "Protects Shared VPC host projects from accidental/malicious un-sharing"
    }

    foreach ($constraint in $recommended.Keys) {
        $raw = Invoke-Gcloud -Description "org-policy describe $constraint" -GcloudArgs @('org-policies','describe',$constraint,"--$targetType=$targetVal",'--format=json')
        $enforced = 'unset'
        if ($raw) {
            try { $parsed = $raw | ConvertFrom-Json; $enforced = $parsed.spec.rules[0].enforce } catch {}
        }
        if (-not $raw -or $enforced -ne $true) {
            Add-Finding "SECURITY" $target "Org Policy" $constraint "Security - Org Policy" `
                "Constraint not enforced" `
                "Org Policy constraint '$constraint' is not set/enforced at $target" `
                "MEDIUM" "org-policies describe" `
                "$($recommended[$constraint]). Enable with: gcloud org-policies set-policy <policy.yaml> --$targetType=$targetVal (set enforce: true)."
        }
    }
}

function Invoke-Firewalls {
    Log-Info "[SECURITY] Auditing VPC firewall rules for risky open access..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "firewalls_$proj.json"
        $rules = Get-GcloudJson -Description "firewall-rules list $proj" -RawFile $out -GcloudArgs @('compute','firewall-rules','list',"--project=$proj")
        foreach ($rule in $rules) {
            if ($rule.disabled -eq $true -or $rule.direction -ne 'INGRESS') { continue }
            $name = $rule.name
            $srcRanges = @($rule.sourceRanges) -join ','
            $allowedStr = (@($rule.allowed) | ForEach-Object { "$($_.IPProtocol):$((@($_.ports) -join ',') -replace '^$','all')" }) -join '; '

            if ($srcRanges -match '0\.0\.0\.0/0') {
                $severity = 'HIGH'
                $riskyPattern = ($RiskyPorts -join '|')
                if ($allowedStr -match "(tcp|udp):($riskyPattern|all)") { $severity = 'CRITICAL' }
                if ($allowedStr -match 'all') { $severity = 'CRITICAL' }

                Add-Finding "SECURITY" $proj "Firewall Rule" $name "Security - Network" `
                    "Internet-exposed ingress rule" `
                    "Rule '$name' allows $allowedStr from 0.0.0.0/0" `
                    $severity "compute firewall-rules list" `
                    "Restrict sourceRanges to known IP ranges (corporate VPN/office CIDRs) or remove the 0.0.0.0/0 source entirely. For admin ports (22/3389/3306/5432/etc.) use Identity-Aware Proxy (IAP) TCP forwarding or a bastion/VPN instead of public exposure. Tag-scope the rule to only the instances that need it (avoid applying to all instances in the VPC)."
            }
            if ($name -match 'default-allow-') {
                Add-Finding "SECURITY" $proj "Firewall Rule" $name "Security - Network" `
                    "Default network firewall rule present" `
                    "Rule '$name' is one of the GCP default-network auto-created rules (often overly permissive)" `
                    "MEDIUM" "compute firewall-rules list" `
                    "Review and remove unused default-allow-ssh/rdp/icmp/internal rules; replace with explicit, scoped rules. Consider deleting the legacy 'default' VPC network entirely in favor of custom-mode VPCs."
            }
        }
    }
}

function Invoke-PublicStorage {
    Log-Info "[SECURITY] Auditing Cloud Storage buckets for public/anonymous access..."
    $scopesToCheck = if ($script:AssetScope) { @($script:AssetScope) } else { $script:Projects | ForEach-Object { "projects/$_" } }
    foreach ($scope in $scopesToCheck) {
        $out = Join-Path $RawDir 'public_buckets.json'
        $items = Get-GcloudJson -Description "search-all-iam-policies buckets" -Long -RawFile $out -GcloudArgs @('asset','search-all-iam-policies',"--scope=$scope",'--query=policy:(allUsers OR allAuthenticatedUsers)','--asset-types=storage.googleapis.com/Bucket')
        foreach ($item in $items) {
            $bindings = (@($item.policy.bindings) | Where-Object { $_.members -contains 'allUsers' -or $_.members -contains 'allAuthenticatedUsers' } | ForEach-Object { $_.role }) -join ';'
            Add-Finding "SECURITY" $scope "GCS Bucket" $item.resource "Security - Storage" `
                "Publicly accessible bucket" `
                "Bucket $($item.resource) grants role(s) [$bindings] to allUsers/allAuthenticatedUsers" `
                "CRITICAL" "search-all-iam-policies (storage.googleapis.com/Bucket)" `
                "Remove public IAM bindings unless this bucket is intentionally a public static-content host. If intentional, scope the role to roles/storage.objectViewer only, enable a CDN/Cloud Armor in front of it, and enforce uniform bucket-level access + a bucket-specific allow-list rather than project-wide public grants."
        }
    }
}

function Invoke-PublicComputeInstances {
    Log-Info "[SECURITY] Auditing Compute Engine instances for public IPs / weak config..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "instances_$proj.json"
        $instances = Get-GcloudJson -Description "instances list $proj" -RawFile $out -GcloudArgs @('compute','instances','list',"--project=$proj")
        foreach ($inst in $instances) {
            $name = $inst.name
            $zone = ($inst.zone -split '/')[-1]
            $extIps = @($inst.networkInterfaces | ForEach-Object { $_.accessConfigs } | Where-Object { $_ } | ForEach-Object { $_.natIP }) -join ','
            $secureBoot = $inst.shieldedInstanceConfig.enableSecureBoot
            $serialItem = $inst.metadata.items | Where-Object { $_.key -eq 'serial-port-enable' }
            $serialEnabled = if ($serialItem) { $serialItem.value } else { 'false' }

            if ($extIps) {
                Add-Finding "SECURITY" $proj "Compute Instance" "$name ($zone)" "Security - Compute" `
                    "Instance has external/public IP" `
                    "Instance $name has external IP(s): $extIps" `
                    "HIGH" "compute instances list" `
                    "Remove the external IP if not required; use Cloud NAT for outbound-only internet access and Identity-Aware Proxy (IAP) or a bastion for inbound admin access. Apply the org policy constraints/compute.vmExternalIpAccess to prevent recurrence."
            }
            if ($secureBoot -ne $true) {
                Add-Finding "SECURITY" $proj "Compute Instance" "$name ($zone)" "Security - Compute" `
                    "Shielded VM (Secure Boot) not enabled" `
                    "Instance $name does not have Secure Boot enabled" `
                    "MEDIUM" "compute instances list" `
                    "Enable Shielded VM options (Secure Boot, vTPM, Integrity Monitoring) to protect against rootkits/bootkits. Existing instances can be updated while stopped: 'gcloud compute instances update NAME --shielded-secure-boot'."
            }
            if ("$serialEnabled" -eq 'true') {
                Add-Finding "SECURITY" $proj "Compute Instance" "$name ($zone)" "Security - Compute" `
                    "Serial port access enabled" `
                    "Instance $name has serial-port-enable=true in metadata" `
                    "MEDIUM" "compute instances list" `
                    "Disable serial port access unless actively needed for debugging ('gcloud compute instances add-metadata --metadata serial-port-enable=false'). Enforce via org policy constraints/compute.disableSerialPortAccess."
            }
        }
    }
}

function Invoke-CloudSql {
    Log-Info "[SECURITY] Auditing Cloud SQL instances for public exposure / SSL / backups..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "sql_$proj.json"
        $instances = Get-GcloudJson -Description "sql instances list $proj" -Long -RawFile $out -GcloudArgs @('sql','instances','list',"--project=$proj")
        foreach ($inst in $instances) {
            $name = $inst.name
            $ipv4 = $inst.settings.ipConfiguration.ipv4Enabled
            $requireSsl = $inst.settings.ipConfiguration.requireSsl
            $authNetworks = (@($inst.settings.ipConfiguration.authorizedNetworks) | ForEach-Object { $_.value }) -join ','
            $backupEnabled = $inst.settings.backupConfiguration.enabled

            if ($ipv4 -eq $true) {
                Add-Finding "SECURITY" $proj "Cloud SQL Instance" $name "Security - Database" `
                    "Public IP enabled on Cloud SQL" "Instance $name has a public IPv4 address enabled" "HIGH" "sql instances list" `
                    "Disable public IP and use Private Service Connect / Private IP + Cloud SQL Auth Proxy / Cloud SQL connector instead. Enforce via org policy constraints/sql.restrictPublicIp."
            }
            if ($authNetworks -match '0\.0\.0\.0/0') {
                Add-Finding "SECURITY" $proj "Cloud SQL Instance" $name "Security - Database" `
                    "Authorized network 0.0.0.0/0" "Instance $name authorizes connections from 0.0.0.0/0" "CRITICAL" "sql instances list" `
                    "Remove the 0.0.0.0/0 authorized network immediately; replace with specific CIDR ranges or, preferably, Private IP + Cloud SQL Auth Proxy with IAM database authentication."
            }
            if ($requireSsl -ne $true) {
                Add-Finding "SECURITY" $proj "Cloud SQL Instance" $name "Security - Database" `
                    "SSL/TLS not enforced" "Instance $name does not require SSL for connections" "HIGH" "sql instances list" `
                    "Set requireSsl=true (or enforce 'Encrypted only' with trusted CA / mutual TLS) so all client connections are encrypted in transit: 'gcloud sql instances patch NAME --require-ssl'."
            }
            if ($backupEnabled -ne $true) {
                Add-Finding "SECURITY" $proj "Cloud SQL Instance" $name "Security - Database" `
                    "Automated backups disabled" "Instance $name does not have automated backups enabled" "HIGH" "sql instances list" `
                    "Enable automated daily backups and point-in-time recovery: 'gcloud sql instances patch NAME --backup-start-time=HH:MM --enable-bin-log'."
            }
        }
    }
}

function Invoke-Kms {
    Log-Info "[SECURITY] Auditing KMS key rotation policies..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $locsOut = Join-Path $RawDir "kms_locations_$proj.json"
        $keyrings = Get-GcloudJson -Description "kms locations list" -Long -RawFile $locsOut -GcloudArgs @('kms','keyrings','list',"--project=$proj",'--location=-')
        foreach ($kr in $keyrings) {
            $keyring = $kr.name
            if (-not $keyring) { continue }
            $location = ($keyring -split '/')[3]
            $keysOut = Join-Path $RawDir "kms_keys_$(Split-Path $keyring -Leaf).json"
            $keys = Get-GcloudJson -Description "kms keys list" -Long -RawFile $keysOut -GcloudArgs @('kms','keys','list',"--keyring=$keyring","--location=$location","--project=$proj")
            foreach ($key in $keys) {
                if (-not $key.rotationPeriod) {
                    Add-Finding "SECURITY" $proj "KMS Key" $key.name "Security - Encryption" `
                        "No automatic key rotation configured" "Key $($key.name) has no rotationPeriod set" "MEDIUM" "kms keys list" `
                        "Set automatic rotation (e.g. every $KmsRotationMaxDays days): 'gcloud kms keys update NAME --rotation-period=${KmsRotationMaxDays}d --next-rotation-time=...'. Periodic rotation limits the blast radius of a compromised key version."
                }
            }
        }
    }
}

function Invoke-LoggingAndMonitoring {
    Log-Info "[SECURITY] Auditing log sinks, retention, and monitoring coverage..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $sinksOut = Join-Path $RawDir "sinks_$proj.json"
        $sinks = Get-GcloudJson -Description "logging sinks list" -RawFile $sinksOut -GcloudArgs @('logging','sinks','list',"--project=$proj")
        if ($sinks.Count -eq 0) {
            Add-Finding "SECURITY" $proj "Logging" "project/$proj" "Security - Logging" `
                "No log export sink configured" "Project $proj has no log sinks exporting to BigQuery/GCS/Pub-Sub" "HIGH" "logging sinks list" `
                "Create at least one aggregated sink exporting Admin Activity + Data Access + System Event audit logs to a separate, access-restricted project/bucket (ideally with a locked retention policy) so logs survive even if this project is compromised: 'gcloud logging sinks create ...'."
        }

        $bucketsOut = Join-Path $RawDir "log_buckets_$proj.json"
        $buckets = Get-GcloudJson -Description "logging buckets list" -RawFile $bucketsOut -GcloudArgs @('logging','buckets','list',"--project=$proj",'--location=global')
        foreach ($b in $buckets) {
            $retention = if ($b.retentionDays) { $b.retentionDays } else { 30 }
            if ($b.locked -ne $true) {
                Add-Finding "SECURITY" $proj "Log Bucket" $b.name "Security - Logging" `
                    "Log bucket not locked" "Log bucket $($b.name) (retention ${retention}d) is not locked" "MEDIUM" "logging buckets list" `
                    "Lock critical log buckets (especially the _Default and any security/audit sink buckets) to prevent retention-policy tampering or early deletion by a compromised admin: 'gcloud logging buckets update NAME --locked'."
            }
        }
    }
}

function Invoke-GkeClusters {
    Log-Info "[SECURITY] Auditing GKE cluster hardening settings..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "gke_$proj.json"
        $clusters = Get-GcloudJson -Description "gke clusters list" -Long -RawFile $out -GcloudArgs @('container','clusters','list',"--project=$proj")
        foreach ($c in $clusters) {
            $name = $c.name
            if ($c.privateClusterConfig.enablePrivateNodes -ne $true) {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Cluster nodes are not private" "Cluster $name does not use private nodes" "HIGH" "container clusters list" `
                    "Recreate/migrate to a private cluster (--enable-private-nodes) so node VMs only have internal IPs; use Cloud NAT for egress."
            }
            if ($c.legacyAbac.enabled -eq $true) {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Legacy ABAC enabled" "Cluster $name has legacy Attribute-Based Access Control enabled" "HIGH" "container clusters list" `
                    "Disable legacy ABAC and rely solely on RBAC: 'gcloud container clusters update NAME --no-enable-legacy-authorization'."
            }
            if ($c.networkPolicy.enabled -ne $true) {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Network Policy disabled" "Cluster $name has no NetworkPolicy enforcement (Calico/Dataplane V2)" "MEDIUM" "container clusters list" `
                    "Enable network policy enforcement to allow pod-to-pod traffic segmentation: 'gcloud container clusters update NAME --enable-network-policy' (or use Dataplane V2)."
            }
            if ($c.masterAuthorizedNetworksConfig.enabled -ne $true) {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Control plane not IP-restricted" "Cluster $name control plane is reachable without authorized network restrictions" "HIGH" "container clusters list" `
                    "Enable Master Authorized Networks and list only trusted CIDRs (office/VPN/CI) that may reach the Kubernetes API: 'gcloud container clusters update NAME --enable-master-authorized-networks --master-authorized-networks=<CIDRs>'."
            }
            $binAuth = if ($c.binaryAuthorization.evaluationMode) { $c.binaryAuthorization.evaluationMode } else { 'DISABLED' }
            if ($binAuth -eq 'DISABLED') {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Binary Authorization disabled" "Cluster $name does not enforce Binary Authorization" "MEDIUM" "container clusters list" `
                    "Enable Binary Authorization with a policy requiring images to be signed/attested by your CI pipeline, blocking unverified images from running: 'gcloud container clusters update NAME --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE'."
            }
            if (-not $c.workloadIdentityConfig.workloadPool) {
                Add-Finding "SECURITY" $proj "GKE Cluster" $name "Security - GKE" "Workload Identity not configured" "Cluster $name does not use Workload Identity" "MEDIUM" "container clusters list" `
                    "Enable Workload Identity so pods authenticate to GCP APIs via short-lived federated tokens instead of mounted SA key files: 'gcloud container clusters update NAME --workload-pool=PROJECT_ID.svc.id.goog'."
            }
        }
    }
}

function Invoke-SccFindings {
    if (-not $RunSccAudit) { return }
    if (-not $OrgId) { Log-Warn "[SECURITY] Skipping Security Command Center audit - ORG_ID not set."; return }
    Log-Info "[SECURITY] Pulling active Security Command Center findings (requires SCC enabled on the org)..."
    $out = Join-Path $RawDir 'scc_findings.json'
    $findings = Get-GcloudJson -Description "scc findings list" -Long -RawFile $out -GcloudArgs @('scc','findings','list',"organizations/$OrgId",'--filter=state="ACTIVE"')
    if ($findings.Count -eq 0) { Log-Warn "[SECURITY] No SCC findings returned (SCC may not be enabled/licensed, or no access)."; return }

    foreach ($item in $findings) {
        $f = if ($item.finding) { $item.finding } else { $item }
        $category = if ($f.category) { $f.category } else { 'UNKNOWN' }
        $resource = if ($f.resourceName) { $f.resourceName } else { 'unknown' }
        $severity = if ($f.severity) { $f.severity } else { 'MEDIUM' }
        Add-Finding "SECURITY" "organizations/$OrgId" "SCC Finding" $resource "Security - SCC" `
            $category "Active Security Command Center finding: $category on $resource" `
            $severity "scc findings list ($($f.name))" `
            "Open this finding in Security Command Center for full remediation steps specific to the category. Triage by severity, assign an owner, and re-run SCC export after remediation to confirm the finding closes."
    }
}

function Invoke-SecuritySection {
    if (-not $RunSecurityAudit) { Log-Info "[SECURITY] Skipped (RUN_SECURITY_AUDIT=false)"; return }
    Invoke-OrgPolicies
    Invoke-Firewalls
    Invoke-PublicStorage
    Invoke-PublicComputeInstances
    Invoke-CloudSql
    Invoke-Kms
    Invoke-LoggingAndMonitoring
    Invoke-GkeClusters
    Invoke-SccFindings
}

###############################################################################
# 7. SECTION C - SERVICES / APPLICATION MISCONFIGURATION / HARDCODED SECRETS
###############################################################################

function Invoke-EnabledApis {
    Log-Info "[SERVICES] Auditing enabled APIs per project..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "apis_$proj.json"
        $apis = Get-GcloudJson -Description "services list $proj" -Long -RawFile $out -GcloudArgs @('services','list','--enabled',"--project=$proj")
        Add-Finding "SERVICES" $proj "Project" $proj "Services - API Surface" `
            "Enabled API inventory (informational)" `
            "Project $proj has $($apis.Count) APIs enabled - see raw/apis_$proj.json for full list" `
            "LOW" "services list --enabled" `
            "Periodically review enabled APIs and disable any not in active use to reduce attack surface ('gcloud services disable API_NAME'). Pay special attention to powerful/legacy APIs (e.g. compute, iam, cloudfunctions, deploymentmanager) being enabled in projects that don't need them."
    }
}

function Invoke-PublicServerless {
    Log-Info "[SERVICES] Auditing Cloud Run / Cloud Functions for unauthenticated public access..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }

        $runOut = Join-Path $RawDir "run_$proj.json"
        $runSvcs = Get-GcloudJson -Description "run services list" -RawFile $runOut -GcloudArgs @('run','services','list',"--project=$proj",'--platform=managed')
        foreach ($svc in $runSvcs) {
            $name = $svc.metadata.name
            if (-not $name) { continue }
            $region = $svc.metadata.labels.'cloud.googleapis.com/location'
            if (-not $region) { $region = $svc.metadata.namespace }
            $policyRaw = Invoke-Gcloud -Description "run get-iam-policy" -GcloudArgs @('run','services','get-iam-policy',$name,"--project=$proj","--region=$region",'--format=json')
            if ($policyRaw -match 'allUsers') {
                Add-Finding "SERVICES" $proj "Cloud Run Service" $name "Services - Serverless" `
                    "Unauthenticated public invocation allowed" "Cloud Run service $name allows allUsers as invoker" "HIGH" "run services get-iam-policy" `
                    "Confirm this service is meant to be public (e.g. a public API/webhook). If not, remove the allUsers binding and require authentication ('gcloud run services remove-iam-policy-binding'), then use IAM, an API gateway, or signed requests for callers. If it must be public, put Cloud Armor / a WAF and rate limiting in front of it."
            }
            $envVars = @($svc.spec.template.spec.containers | ForEach-Object { $_.env } | Where-Object { $_ })
            $envText = ($envVars | ForEach-Object { "$($_.name)=$($_.value)" }) -join "`n"
            if (Test-SecretPattern $envText) {
                Add-Finding "SERVICES" $proj "Cloud Run Service" $name "Services - Secrets" `
                    "Possible hardcoded secret in env vars" "Environment variables on Cloud Run service $name match a secret-like pattern (value redacted in this report)" "CRITICAL" "run services describe (env vars pattern-matched, not logged)" `
                    "Move this value into Secret Manager immediately and mount it as a secret env var/volume instead of a plaintext env var ('gcloud run services update --update-secrets'). Rotate the exposed credential, since it has likely been visible in deploy logs/IaC history."
            }
        }

        $fnOut = Join-Path $RawDir "functions_$proj.json"
        $fns = Get-GcloudJson -Description "functions list" -Long -RawFile $fnOut -GcloudArgs @('functions','list',"--project=$proj")
        foreach ($fn in $fns) {
            $fullName = $fn.name
            if (-not $fullName) { continue }
            $fnShort = Split-Path $fullName -Leaf
            $policyRaw = Invoke-Gcloud -Description "functions get-iam-policy" -GcloudArgs @('functions','get-iam-policy',$fnShort,"--project=$proj",'--format=json')
            if ($policyRaw -match 'allUsers') {
                Add-Finding "SERVICES" $proj "Cloud Function" $fnShort "Services - Serverless" `
                    "Unauthenticated public invocation allowed" "Cloud Function $fnShort allows allUsers as invoker" "HIGH" "functions get-iam-policy" `
                    "If this function isn't meant to be public, remove the allUsers binding and require IAM auth or an authenticated gateway in front of it."
            }
            $envText = ($fn.environmentVariables.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "`n"
            if (Test-SecretPattern $envText) {
                Add-Finding "SERVICES" $proj "Cloud Function" $fnShort "Services - Secrets" `
                    "Possible hardcoded secret in env vars" "Environment variables on function $fnShort match a secret-like pattern (value redacted)" "CRITICAL" "functions describe (pattern-matched, not logged)" `
                    "Move the value to Secret Manager and reference it via --set-secrets instead of --set-env-vars. Rotate the credential."
            }
        }
    }
}

function Invoke-ComputeMetadataSecrets {
    Log-Info "[SERVICES] Scanning GCE instance metadata/startup-scripts for hardcoded secrets..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "instances_$proj.json"
        $instances = if (Test-Path $out) { (Get-Content $out -Raw | ConvertFrom-Json) } else { Get-GcloudJson -Description "instances list $proj" -RawFile $out -GcloudArgs @('compute','instances','list',"--project=$proj") }
        foreach ($inst in $instances) {
            $metaText = ($inst.metadata.items | ForEach-Object { "$($_.key)=$($_.value)" }) -join "`n"
            if (Test-SecretPattern $metaText) {
                Add-Finding "SERVICES" $proj "Compute Instance" $inst.name "Services - Secrets" `
                    "Possible hardcoded secret in instance metadata/startup-script" "Custom metadata on instance $($inst.name) matches a secret-like pattern (value redacted)" "CRITICAL" "compute instances describe (pattern-matched, not logged)" `
                    "Remove credentials from instance metadata/startup scripts. Use Secret Manager + the metadata server's attached service-account identity to fetch secrets at boot time instead of embedding them as plaintext metadata."
            }
        }
    }
}

function Invoke-StorageHygiene {
    Log-Info "[SERVICES] Auditing storage bucket hygiene (versioning, lifecycle, uniform access)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "buckets_$proj.json"
        $buckets = Get-GcloudJson -Description "storage buckets list" -RawFile $out -GcloudArgs @('storage','buckets','list',"--project=$proj")
        foreach ($b in $buckets) {
            if ($b.iamConfiguration.uniformBucketLevelAccess.enabled -ne $true) {
                Add-Finding "SERVICES" $proj "GCS Bucket" $b.name "Services - Storage Hygiene" `
                    "Uniform bucket-level access disabled" "Bucket $($b.name) still allows legacy per-object ACLs" "MEDIUM" "storage buckets list" `
                    "Enable uniform bucket-level access to eliminate ACL-based misconfiguration risk: 'gcloud storage buckets update gs://NAME --uniform-bucket-level-access'."
            }
            if ($b.versioning.enabled -ne $true) {
                Add-Finding "SERVICES" $proj "GCS Bucket" $b.name "Services - Storage Hygiene" `
                    "Object versioning disabled" "Bucket $($b.name) has no object versioning, increasing risk of unrecoverable accidental/malicious deletion" "LOW" "storage buckets list" `
                    "Enable versioning on buckets holding important data, paired with a lifecycle rule to expire old versions after a reasonable period."
            }
        }
    }
}

function Invoke-BigQueryPublicDatasets {
    Log-Info "[SERVICES] Checking for publicly shared BigQuery datasets..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "bq_$proj.json"
        $datasets = Get-GcloudJson -Description "bq ls" -RawFile $out -GcloudArgs @('alpha','bq','datasets','list',"--project=$proj")
        foreach ($ds in $datasets) {
            $dsId = $ds.datasetReference.datasetId
            if (-not $dsId) { continue }
            $iamRaw = Invoke-Gcloud -Description "bq dataset iam" -GcloudArgs @('alpha','bq','datasets','get-iam-policy',$dsId,"--project=$proj",'--format=json')
            if ($iamRaw -match 'allUsers|allAuthenticatedUsers') {
                Add-Finding "SERVICES" $proj "BigQuery Dataset" $dsId "Services - Data" `
                    "Publicly accessible BigQuery dataset" "Dataset $dsId grants access to allUsers/allAuthenticatedUsers" "CRITICAL" "bq datasets get-iam-policy" `
                    "Remove public bindings unless this is an intentionally published open dataset. Restrict to named principals/groups and enable column/row-level security for sensitive tables."
            }
        }
    }
}

function Invoke-SecretManagerAdoption {
    Log-Info "[SERVICES] Checking Secret Manager adoption vs. plaintext secret patterns found elsewhere..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "secrets_$proj.json"
        $secrets = Get-GcloudJson -Description "secrets list" -RawFile $out -GcloudArgs @('secrets','list',"--project=$proj")
        if ($secrets.Count -eq 0) {
            Add-Finding "SERVICES" $proj "Project" $proj "Services - Secrets" `
                "Secret Manager not used in this project" "Project $proj has zero secrets registered in Secret Manager" "LOW" "secrets list" `
                "If this project's workloads need credentials/API keys/tokens, migrate them into Secret Manager rather than env vars, metadata, or source code. This also gives you automatic audit logging of every secret access."
        }
    }
}

function Invoke-ServicesSection {
    if (-not $RunServicesAudit) { Log-Info "[SERVICES] Skipped (RUN_SERVICES_AUDIT=false)"; return }
    Invoke-EnabledApis
    Invoke-PublicServerless
    Invoke-ComputeMetadataSecrets
    Invoke-StorageHygiene
    Invoke-BigQueryPublicDatasets
    Invoke-SecretManagerAdoption
}

###############################################################################
# 7B. SECTION D - EXTENDED AUDIT
###############################################################################

function Invoke-NetworkHardening {
    Log-Info "[EXTENDED] Auditing network hardening (flow logs, NAT, Armor, DNSSEC, TLS, default network)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }

        $defaultNetRaw = Invoke-Gcloud -Description "networks describe default" -GcloudArgs @('compute','networks','describe','default',"--project=$proj",'--format=value(name)')
        if (-not [string]::IsNullOrWhiteSpace($defaultNetRaw)) {
            Add-Finding "SECURITY" $proj "VPC Network" "default" "Security - Network Architecture" `
                "Legacy 'default' auto-mode network present" "Project $proj still has the GCP-created 'default' network with its auto-generated permissive firewall rules" "MEDIUM" "compute networks describe default" `
                "Migrate workloads to a custom-mode VPC with explicit, scoped subnets/firewall rules, then delete the default network. Auto-mode default networks are a recurring source of forgotten public exposure."
        }

        $subnetsOut = Join-Path $RawDir "subnets_$proj.json"
        $subnets = Get-GcloudJson -Description "subnets list" -RawFile $subnetsOut -GcloudArgs @('compute','networks','subnets','list',"--project=$proj")
        foreach ($sn in $subnets) {
            $snName = "$($sn.name) ($((($sn.region -split '/')[-1])))"
            if ($sn.enableFlowLogs -ne $true) {
                Add-Finding "SECURITY" $proj "Subnet" $snName "Security - Network Architecture" `
                    "VPC Flow Logs disabled" "Subnet $snName does not have Flow Logs enabled" "MEDIUM" "compute networks subnets list" `
                    "Enable VPC Flow Logs for network forensics/incident response and anomaly detection: 'gcloud compute networks subnets update NAME --enable-flow-logs'."
            }
            if ($sn.privateIpGoogleAccess -ne $true) {
                Add-Finding "SECURITY" $proj "Subnet" $snName "Security - Network Architecture" `
                    "Private Google Access disabled" "Subnet $snName cannot reach Google APIs without external IPs" "LOW" "compute networks subnets list" `
                    "Enable Private Google Access so VMs without external IPs can still reach Google APIs/services, reducing the need for public IPs: 'gcloud compute networks subnets update NAME --enable-private-ip-google-access'."
            }
        }

        $routersOut = Join-Path $RawDir "routers_$proj.json"
        $routers = Get-GcloudJson -Description "routers list" -RawFile $routersOut -GcloudArgs @('compute','routers','list',"--project=$proj")
        $natTotal = ($routers | ForEach-Object { @($_.nats) } | Measure-Object).Count
        if ($natTotal -eq 0) {
            Add-Finding "SECURITY" $proj "Cloud NAT" "project/$proj" "Security - Network Architecture" `
                "No Cloud NAT configured (informational)" "No Cloud NAT gateways found in $proj - confirm this is expected (e.g. no private-only egress workloads)" "LOW" "compute routers list (.nats[] field)" `
                "If any instances/GKE nodes here rely on external IPs purely for outbound internet access, switch them to private-only + Cloud NAT instead, removing unnecessary inbound attack surface."
        }

        $armorOut = Join-Path $RawDir "armor_$proj.json"
        $armor = Get-GcloudJson -Description "armor list" -RawFile $armorOut -GcloudArgs @('compute','security-policies','list',"--project=$proj")
        if ($armor.Count -eq 0) {
            Add-Finding "SECURITY" $proj "Cloud Armor" "project/$proj" "Security - Network Architecture" `
                "No Cloud Armor policies configured" "Project $proj has no Cloud Armor security policies" "LOW" "compute security-policies list" `
                "If this project serves internet-facing HTTP(S) load balancers, put a Cloud Armor WAF policy in front (rate limiting + OWASP preconfigured rules) to absorb L7 attacks/credential-stuffing/bot traffic before it reaches your app."
        }

        $sslOut = Join-Path $RawDir "sslpolicies_$proj.json"
        $sslPolicies = Get-GcloudJson -Description "ssl-policies list" -RawFile $sslOut -GcloudArgs @('compute','ssl-policies','list',"--project=$proj")
        foreach ($sp in $sslPolicies) {
            if ([string]::CompareOrdinal($sp.minTlsVersion, $MinTlsVersion) -lt 0) {
                Add-Finding "SECURITY" $proj "SSL Policy" $sp.name "Security - Network Architecture" `
                    "Weak minimum TLS version" "SSL policy $($sp.name) allows down to $($sp.minTlsVersion)" "HIGH" "compute ssl-policies list" `
                    "Raise the minimum TLS version to $MinTlsVersion or higher and use the MODERN/RESTRICTED profile: 'gcloud compute ssl-policies update NAME --min-tls-version=$MinTlsVersion --profile=RESTRICTED'."
            }
        }

        $certOut = Join-Path $RawDir "sslcerts_$proj.json"
        $certs = Get-GcloudJson -Description "ssl-certificates list" -RawFile $certOut -GcloudArgs @('compute','ssl-certificates','list',"--project=$proj")
        foreach ($cert in $certs) {
            if (-not $cert.expireTime) { continue }
            $daysLeft = 0
            try { $daysLeft = [int]([datetime]$cert.expireTime - (Get-Date)).TotalDays } catch {}
            if ($daysLeft -le $SslCertExpiryWarnDays) {
                Add-Finding "SECURITY" $proj "SSL Certificate" $cert.name "Security - Network Architecture" `
                    "Certificate expiring soon or expired" "Certificate $($cert.name) expires in $daysLeft day(s) ($($cert.expireTime))" "HIGH" "compute ssl-certificates list" `
                    "Renew/rotate this certificate now, or migrate to Google-managed certificates so renewal is automatic: 'gcloud compute ssl-certificates create ... --domains=...'."
            }
        }

        $dnsOut = Join-Path $RawDir "dns_$proj.json"
        $zones = Get-GcloudJson -Description "dns zones list" -Long -RawFile $dnsOut -GcloudArgs @('dns','managed-zones','list',"--project=$proj")
        foreach ($z in ($zones | Where-Object { -not $_.visibility -or $_.visibility -eq 'public' })) {
            $dnssecState = if ($z.dnssecConfig.state) { $z.dnssecConfig.state } else { 'off' }
            if ($dnssecState -ne 'on') {
                Add-Finding "SECURITY" $proj "Cloud DNS Zone" $z.name "Security - Network Architecture" `
                    "DNSSEC not enabled on public zone" "Public DNS zone $($z.name) has DNSSEC state=$dnssecState" "MEDIUM" "dns managed-zones list" `
                    "Enable DNSSEC to prevent DNS spoofing/cache-poisoning of your public domains: 'gcloud dns managed-zones update NAME --dnssec-state=on'."
            }
        }
    }
}

function Invoke-BackupAndDr {
    Log-Info "[EXTENDED] Auditing backup & disaster-recovery posture (disks, GKE)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $disksOut = Join-Path $RawDir "disks_$proj.json"
        $disks = Get-GcloudJson -Description "disks list" -RawFile $disksOut -GcloudArgs @('compute','disks','list',"--project=$proj")
        foreach ($d in $disks) {
            $zoneOrRegion = if ($d.zone) { $d.zone } elseif ($d.region) { $d.region } else { 'unknown' }
            $zone = ($zoneOrRegion -split '/')[-1]
            $policyCount = (@($d.resourcePolicies)).Count
            if ($policyCount -eq 0) {
                Add-Finding "SECURITY" $proj "Persistent Disk" "$($d.name) ($zone)" "Security - Backup/DR" `
                    "No scheduled snapshot policy attached" "Disk $($d.name) has zero resource (snapshot schedule) policies attached" "HIGH" "compute disks list" `
                    "Attach a snapshot schedule so this disk is recoverable from ransomware/accidental-deletion/corruption: 'gcloud compute resource-policies create snapshot-schedule ...' then 'gcloud compute disks add-resource-policies NAME --resource-policies=POLICY'."
            }
        }

        $gkeOut = Join-Path $RawDir "gke_$proj.json"
        if (Test-Path $gkeOut) {
            $clusters = Get-Content $gkeOut -Raw | ConvertFrom-Json
            if (@($clusters).Count -gt 0) {
                $bkOut = Join-Path $RawDir "gke_backup_$proj.json"
                $plans = Get-GcloudJson -Description "gke backup-plans list" -RawFile $bkOut -GcloudArgs @('beta','container','backup-plans','list',"--project=$proj")
                if ($plans.Count -eq 0) {
                    Add-Finding "SECURITY" $proj "GKE" "project/$proj" "Security - Backup/DR" `
                        "No Backup for GKE plan configured" "Project $proj runs GKE clusters but has no Backup for GKE plan" "MEDIUM" "beta container backup-plans list" `
                        "Configure Backup for GKE to protect cluster state and workload data (PVs) against accidental deletion or cluster-level failure."
                }
            }
        }
    }
}

function Invoke-CicdAndRegistries {
    Log-Info "[EXTENDED] Auditing CI/CD (Cloud Build) and Artifact/Container Registry exposure..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }

        $projNumber = (Invoke-Gcloud -Description "project number" -GcloudArgs @('projects','describe',$proj,'--format=value(projectNumber)')) -replace '\s',''
        $cbSa = "$projNumber@cloudbuild.gserviceaccount.com"
        $iamOut = Join-Path $RawDir "project_iam_$proj.json"
        $iamPolicy = Get-GcloudJson -Description "project iam policy" -RawFile $iamOut -GcloudArgs @('projects','get-iam-policy',$proj)
        $iamObj = if ($iamPolicy.Count -gt 0) { $iamPolicy[0] } else { $null }
        if ($iamObj) {
            $editorBinding = @($iamObj.bindings) | Where-Object { $_.role -eq 'roles/editor' -and $_.members -contains "serviceAccount:$cbSa" }
            if ($editorBinding) {
                Add-Finding "IAM" $proj "Service Account" $cbSa "Security - CI/CD" `
                    "Cloud Build default SA still has project Editor" "The Cloud Build default service account holds roles/editor on $proj" "HIGH" "projects get-iam-policy" `
                    "Replace the default Cloud Build SA's Editor role with a custom least-privilege role scoped to exactly what your build/deploy pipeline needs (e.g. specific Cloud Run deploy, Artifact Registry push). A compromised build pipeline with Editor can pivot to the entire project."
            }
        }

        $triggersOut = Join-Path $RawDir "cb_triggers_$proj.json"
        $triggers = Get-GcloudJson -Description "build triggers list" -Long -RawFile $triggersOut -GcloudArgs @('builds','triggers','list',"--project=$proj")
        foreach ($t in $triggers) {
            $subsText = ($t.substitutions.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "`n"
            if (Test-SecretPattern $subsText) {
                Add-Finding "SERVICES" $proj "Cloud Build Trigger" $t.name "Security - CI/CD" `
                    "Possible hardcoded secret in build trigger substitutions" "Trigger $($t.name) has substitution variables matching a secret-like pattern (value redacted)" "CRITICAL" "builds triggers list (pattern-matched, not logged)" `
                    "Move this value to Secret Manager and reference it in cloudbuild.yaml via availableSecrets/secretEnv instead of a plaintext substitution variable. Rotate the exposed credential."
            }
        }

        $arOut = Join-Path $RawDir "artifact_repos_$proj.json"
        $repos = Get-GcloudJson -Description "artifact repos list" -Long -RawFile $arOut -GcloudArgs @('artifacts','repositories','list',"--project=$proj")
        foreach ($repo in $repos) {
            if (-not $repo.name) { continue }
            $repoShort = Split-Path $repo.name -Leaf
            $loc = ($repo.name -split '/')[3]
            $policyRaw = Invoke-Gcloud -Description "artifact repo iam" -GcloudArgs @('artifacts','repositories','get-iam-policy',$repoShort,"--location=$loc","--project=$proj",'--format=json')
            if ($policyRaw -match 'allUsers|allAuthenticatedUsers') {
                Add-Finding "SECURITY" $proj "Artifact Registry Repo" $repoShort "Security - CI/CD" `
                    "Publicly accessible artifact/container repository" "Repository $repoShort grants access to allUsers/allAuthenticatedUsers" "CRITICAL" "artifacts repositories get-iam-policy" `
                    "Remove public bindings unless this is an intentionally published public image/package repo. Otherwise restrict to specific service accounts/principals and enable vulnerability scanning (Container/Artifact Analysis) on all images."
            }
        }
    }
}

function Invoke-WorkloadIdentityFederation {
    Log-Info "[EXTENDED] Auditing Workload Identity Federation pools (keyless external auth)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $wifOut = Join-Path $RawDir "wif_pools_$proj.json"
        $pools = Get-GcloudJson -Description "wif pools list" -Long -RawFile $wifOut -GcloudArgs @('iam','workload-identity-pools','list',"--project=$proj",'--location=global')
        if ($pools.Count -eq 0) {
            Add-Finding "IAM" $proj "Project" $proj "IAM - Workload Identity" `
                "No Workload Identity Federation pools configured (informational)" "Project $proj has no WIF pools - external workloads (CI/CD, on-prem, other clouds) likely authenticate with static SA keys instead" "LOW" "iam workload-identity-pools list" `
                "For any external system (GitHub Actions, GitLab CI, AWS, on-prem) that currently authenticates to this project with a downloaded SA key, migrate to Workload Identity Federation for short-lived, keyless auth - it eliminates the long-lived-credential risk entirely."
        } else {
            foreach ($pool in $pools) {
                if (-not $pool.name) { continue }
                $poolShort = Split-Path $pool.name -Leaf
                $providersOut = Join-Path $RawDir "wif_providers_$poolShort.json"
                $providers = Get-GcloudJson -Description "wif providers list" -Long -RawFile $providersOut -GcloudArgs @('iam','workload-identity-pools','providers','list',"--project=$proj",'--location=global',"--workload-identity-pool=$poolShort")
                foreach ($p in $providers) {
                    if (-not $p.attributeCondition) {
                        Add-Finding "IAM" $proj "WIF Provider" $p.name "IAM - Workload Identity" `
                            "No attribute condition restricting WIF provider" "Provider $($p.name) has no attributeCondition set" "HIGH" "iam workload-identity-pools providers list" `
                            "Add an attributeCondition restricting which external identities (e.g. specific GitHub repo/branch, specific AWS role) can assume this pool's identity. Without it, any token issued by the external IdP that matches the audience can potentially impersonate into GCP."
                    }
                }
            }
        }
    }
}

function Invoke-OrgGovernanceExtras {
    Log-Info "[EXTENDED] Auditing org-level governance (Essential Contacts, billing budgets, liens)..."

    if ($OrgId) {
        $ecOut = Join-Path $RawDir 'essential_contacts.json'
        $contacts = Get-GcloudJson -Description "essential contacts" -RawFile $ecOut -GcloudArgs @('essential-contacts','list',"--organization=$OrgId")
        $hasSecurity = @($contacts) | Where-Object { $_.notificationCategorySubscriptions -contains 'SECURITY' }
        if (-not $hasSecurity) {
            Add-Finding "SECURITY" "organizations/$OrgId" "Essential Contacts" "organization" "Security - Governance" `
                "No Essential Contact subscribed to SECURITY notifications" "No essential contact at the org level is subscribed to the SECURITY notification category" "HIGH" "essential-contacts list" `
                "Add at least one (ideally a distribution list, not a single person) Essential Contact subscribed to SECURITY and LEGAL categories at the org level, so Google's direct security notifications (e.g. compromised credentials, abuse) reach your team immediately even if individual employees leave."
        }
    }

    if ($BillingAccountId) {
        $budgetsOut = Join-Path $RawDir 'billing_budgets.json'
        $budgets = Get-GcloudJson -Description "billing budgets list" -RawFile $budgetsOut -GcloudArgs @('billing','budgets','list',"--billing-account=$BillingAccountId")
        if ($budgets.Count -eq 0) {
            Add-Finding "SERVICES" "billingAccounts/$BillingAccountId" "Billing Account" $BillingAccountId "Services - Cost Governance" `
                "No billing budgets/alerts configured" "Billing account $BillingAccountId has zero budgets configured" "MEDIUM" "billing budgets list" `
                "Create at least one budget with alert thresholds (e.g. 50/90/100%) per project or for the whole billing account. This is also a security control - a sudden cost spike is often the first signal of a compromised account being used for crypto-mining or resource abuse."
        }
    } else {
        Log-Info "[EXTENDED] Skipping billing budget audit - set BILLING_ACCOUNT_ID to enable."
    }

    if ($OrgId) {
        $liensOut = Join-Path $RawDir 'liens.json'
        $liens = Get-GcloudJson -Description "resource manager liens" -RawFile $liensOut -GcloudArgs @('alpha','resource-manager','liens','list')
        Add-Finding "SECURITY" "organizations/$OrgId" "Resource Manager Liens" "organization" "Security - Governance" `
            "Resource Manager Lien inventory (informational)" "Found $($liens.Count) lien(s) protecting projects from accidental deletion" "LOW" "alpha resource-manager liens list" `
            "Add a deletion lien on business-critical projects (billing, security tooling, prod) so they cannot be deleted without first explicitly removing the lien: 'gcloud alpha resource-manager liens create --restrictions=resourcemanager.projects.delete --reason=...'."

        $denyOut = Join-Path $RawDir 'deny_policies.json'
        $encodedAttach = "cloudresourcemanager.googleapis.com%2Forganizations%2F$OrgId"
        $denyPolicies = Get-GcloudJson -Description "iam deny policies" -RawFile $denyOut -GcloudArgs @('iam','policies','list',"--attachment-point=$encodedAttach",'--kind=denypolicies')
        if ($denyPolicies.Count -eq 0) {
            Add-Finding "IAM" "organizations/$OrgId" "IAM Deny Policy" "organization" "IAM - Governance" `
                "No org-level IAM Deny policy configured (informational)" "No Deny policies found attached at the organization node" "LOW" "iam policies list --kind=denypolicies" `
                "Consider an org-level Deny policy as a hard backstop for your highest-risk permissions (e.g. deny iam.serviceAccountKeys.create for everyone except a tightly scoped break-glass group) - Deny policies override any Allow grant, including future misconfigurations."
        }
    }
}

function Invoke-ManualProcessChecklist {
    Log-Info "[EXTENDED] Adding non-scriptable governance/process items for manual review..."
    $scopeLabel = if ($script:AssetScope) { $script:AssetScope } elseif ($ProjectId) { $ProjectId } else { 'manual-review' }
    $items = @(
        @{ Title = "2FA/MFA enforcement for all human users (Cloud Identity 2-Step Verification, ideally phishing-resistant security keys for admins)"; Rec = "This cannot be verified via gcloud for most Cloud Identity/Workspace setups; check in Admin Console > Security > 2-Step Verification enrollment, and enforce org-wide." }
        @{ Title = "Break-glass / emergency-access process for IAM and production"; Rec = "Confirm a documented, tested break-glass procedure exists for when normal SSO/IAM access is unavailable, with post-use audit review." }
        @{ Title = "Third-party / vendor access review"; Rec = "Periodically review any external vendor service accounts, OAuth app grants (Cloud Identity > Security > API controls), and Marketplace-installed apps for scope creep." }
        @{ Title = "Incident response runbook + tabletop exercises"; Rec = "Confirm an IR runbook exists covering GCP-specific scenarios (compromised SA key, public bucket exposure, crypto-mining instance) and has been tested in the last 12 months." }
        @{ Title = "Penetration testing / red-team cadence"; Rec = "Confirm external or internal pentest covering both the GCP control plane (IAM/network) and the application layer has occurred within your compliance-required cadence." }
        @{ Title = "Data classification & DLP scanning"; Rec = "Confirm sensitive data (PII/PCI/PHI) locations are known and Cloud DLP (or equivalent) scanning/classification is applied to storage/BigQuery holding it." }
        @{ Title = "Change management / IaC drift detection"; Rec = "Confirm infrastructure changes go through IaC (Terraform/Deployment Manager) + review, and periodically diff live state vs IaC to catch manual console drift." }
        @{ Title = "Employee offboarding IAM cleanup SLA"; Rec = "Confirm a defined SLA (e.g. <24h) exists for revoking GCP access (IAM bindings, SA key ownership, OAuth tokens) after an employee/contractor offboards." }
    )
    foreach ($item in $items) {
        Add-Finding "PROCESS" $scopeLabel "Manual Review" "N/A" "Process - Governance (manual review)" `
            $item.Title "Not verifiable via gcloud API - requires manual confirmation with the responsible team" `
            "LOW" "manual checklist item (not derived from logs/API)" $item.Rec
    }
}

function Invoke-VpcServiceControls {
    if (-not $AccessPolicyId) {
        Log-Info "[EXTENDED] Skipping VPC Service Controls audit - set ACCESS_POLICY_ID to enable."
        return
    }
    Log-Info "[EXTENDED] Auditing VPC Service Controls perimeters..."
    $out = Join-Path $RawDir 'vpcsc_perimeters.json'
    $perimeters = Get-GcloudJson -Description "vpcsc perimeters list" -RawFile $out -GcloudArgs @('access-context-manager','perimeters','list',"--policy=$AccessPolicyId")
    if ($perimeters.Count -eq 0) {
        Add-Finding "SECURITY" "accessPolicies/$AccessPolicyId" "VPC Service Controls" "policy/$AccessPolicyId" "Security - Governance" `
            "No VPC Service Controls perimeters defined" "Access policy $AccessPolicyId has zero service perimeters configured" "MEDIUM" "access-context-manager perimeters list" `
            "For projects holding sensitive data (BigQuery/GCS with regulated data), define a VPC-SC perimeter to block data exfiltration via stolen credentials/misconfigured IAM - it's a network-layer control independent of IAM."
    }
}

function Invoke-ExtendedSection {
    if (-not $RunExtendedAudit) { Log-Info "[EXTENDED] Skipped (RUN_EXTENDED_AUDIT=false)"; return }
    Invoke-NetworkHardening
    Invoke-BackupAndDr
    Invoke-CicdAndRegistries
    Invoke-WorkloadIdentityFederation
    Invoke-OrgGovernanceExtras
    Invoke-VpcServiceControls
    Invoke-ManualProcessChecklist
}

###############################################################################
# 7C. SECTION E - STORAGE & DATABASE DEEP-DIVE
###############################################################################

function Invoke-GcsDeep {
    Log-Info "[STORAGE/DB] Deep-diving GCS buckets (PAP, retention lock, CMEK, access logging)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "buckets_$proj.json"
        $buckets = if (Test-Path $out) { Get-Content $out -Raw | ConvertFrom-Json } else { Get-GcloudJson -Description "storage buckets list" -RawFile $out -GcloudArgs @('storage','buckets','list',"--project=$proj") }
        foreach ($b in @($buckets)) {
            $pap = if ($b.iamConfiguration.publicAccessPrevention) { $b.iamConfiguration.publicAccessPrevention } else { 'inherited' }
            $retentionLocked = $b.retentionPolicy.isLocked
            $cmek = if ($b.encryption.defaultKmsKeyName) { $b.encryption.defaultKmsKeyName } else { 'google-managed' }
            $loggingEnabled = if ($b.logging.logBucket) { $b.logging.logBucket } else { 'none' }

            if ($pap -ne 'enforced') {
                Add-Finding "SECURITY" $proj "GCS Bucket" $b.name "Security - Storage Deep-Dive" `
                    "Public Access Prevention not enforced" "Bucket $($b.name) has publicAccessPrevention=$pap" "MEDIUM" "storage buckets list" `
                    "Set Public Access Prevention to 'enforced' so the bucket cannot be made public even by a future IAM/ACL mistake: 'gcloud storage buckets update gs://NAME --public-access-prevention'."
            }
            if ($cmek -eq 'google-managed') {
                Add-Finding "SERVICES" $proj "GCS Bucket" $b.name "Security - Storage Deep-Dive" `
                    "Bucket uses Google-managed encryption, not CMEK" "Bucket $($b.name) has no defaultKmsKeyName set" "LOW" "storage buckets list" `
                    "If this bucket holds regulated/sensitive data, switch to Customer-Managed Encryption Keys (CMEK) for direct control over key rotation/revocation: 'gcloud storage buckets update gs://NAME --default-encryption-key=KMS_KEY'."
            }
            if ($loggingEnabled -eq 'none') {
                Add-Finding "SECURITY" $proj "GCS Bucket" $b.name "Security - Storage Deep-Dive" `
                    "Bucket access logging not configured" "Bucket $($b.name) has no usage/storage logging sink configured" "LOW" "storage buckets list" `
                    "Enable bucket access logs (or rely on Data Access audit logs if enabled) so you have an evidence trail of who read/wrote objects, important for breach investigation and compliance."
            }
            if ($retentionLocked -ne $true) {
                Add-Finding "SERVICES" $proj "GCS Bucket" $b.name "Security - Storage Deep-Dive" `
                    "No locked retention policy (informational)" "Bucket $($b.name) has no locked retention policy" "LOW" "storage buckets list" `
                    "For compliance-relevant or backup buckets, set a retention policy and lock it ('gcloud storage buckets update gs://NAME --retention-period=Xs --lock-retention-policy') so not even a project Owner can shorten retention or delete data early - useful against both ransomware and insider risk."
            }
        }
    }
}

function Invoke-BigQueryDeep {
    Log-Info "[STORAGE/DB] Deep-diving BigQuery (CMEK, table expiration, authorized views, audit logging)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "bq_$proj.json"
        $datasets = if (Test-Path $out) { Get-Content $out -Raw | ConvertFrom-Json } else { Get-GcloudJson -Description "bq ls" -RawFile $out -GcloudArgs @('alpha','bq','datasets','list',"--project=$proj") }
        foreach ($ds in @($datasets)) {
            $dsId = $ds.datasetReference.datasetId
            if (-not $dsId) { continue }
            $detailRaw = Invoke-Gcloud -Description "bq dataset describe" -GcloudArgs @('alpha','bq','datasets','describe',$dsId,"--project=$proj",'--format=json')
            $detail = $null
            if ($detailRaw) { try { $detail = $detailRaw | ConvertFrom-Json } catch {} }
            $cmek = if ($detail.defaultEncryptionConfiguration.kmsKeyName) { $detail.defaultEncryptionConfiguration.kmsKeyName } else { 'google-managed' }
            $defaultExp = if ($detail.defaultTableExpirationMs) { $detail.defaultTableExpirationMs } else { 'none' }

            if ($cmek -eq 'google-managed') {
                Add-Finding "SERVICES" $proj "BigQuery Dataset" $dsId "Security - Storage Deep-Dive" `
                    "Dataset uses Google-managed encryption, not CMEK" "Dataset $dsId has no defaultEncryptionConfiguration" "LOW" "bq datasets describe" `
                    "For datasets holding sensitive/regulated data, set a default CMEK key so all tables inherit customer-managed encryption: 'bq update --default_kms_key=KMS_KEY project:dataset'."
            }
            if ($defaultExp -eq 'none') {
                Add-Finding "SERVICES" $proj "BigQuery Dataset" $dsId "Services - Storage Hygiene" `
                    "No default table expiration set (informational)" "Dataset $dsId has no defaultTableExpirationMs" "LOW" "bq datasets describe" `
                    "If this dataset is used for staging/ad-hoc/temp tables, set a default table expiration to auto-clean stale data and reduce both cost and the amount of sensitive data sitting around unnecessarily."
            }
        }

        $since = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "resource.type=`"bigquery_resource`" AND timestamp>=`"$since`""
        $bqLogCheck = Invoke-Gcloud -Description "bq audit log check" -GcloudArgs @('logging','read',$filter,"--project=$proj",'--limit=1','--format=value(timestamp)')
        if ([string]::IsNullOrWhiteSpace($bqLogCheck)) {
            Add-Finding "SECURITY" $proj "BigQuery" "project/$proj" "Security - Storage Deep-Dive" `
                "No recent BigQuery audit log activity found (informational)" "No bigquery_resource log entries found in the last 7 days for $proj - confirm whether BigQuery is actually unused here, or whether Data Access logs need enabling" "LOW" "logging read resource.type=bigquery_resource" `
                "If BigQuery is in active use, confirm Data Access audit logs are enabled (they are charged separately from Admin Activity logs) so query-level access is captured for forensics. If BigQuery truly isn't used, this is just confirmation - no action needed."
        }
    }
}

function Invoke-CloudSqlDeep {
    Log-Info "[STORAGE/DB] Deep-diving Cloud SQL (CMEK, deletion protection, HA, maintenance window)..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }
        $out = Join-Path $RawDir "sql_$proj.json"
        $instances = if (Test-Path $out) { Get-Content $out -Raw | ConvertFrom-Json } else { Get-GcloudJson -Description "sql instances list" -Long -RawFile $out -GcloudArgs @('sql','instances','list',"--project=$proj") }
        foreach ($inst in @($instances)) {
            $cmek = if ($inst.diskEncryptionConfiguration.kmsKeyName) { $inst.diskEncryptionConfiguration.kmsKeyName } else { 'google-managed' }
            $deletionProtection = $inst.settings.deletionProtectionEnabled
            $availability = if ($inst.settings.availabilityType) { $inst.settings.availabilityType } else { 'ZONAL' }

            if ($cmek -eq 'google-managed') {
                Add-Finding "SERVICES" $proj "Cloud SQL Instance" $inst.name "Security - Storage Deep-Dive" `
                    "Instance uses Google-managed encryption, not CMEK" "Instance $($inst.name) has no diskEncryptionConfiguration" "LOW" "sql instances list" `
                    "For regulated data, recreate/configure the instance with a CMEK key for direct control over key lifecycle."
            }
            if ($deletionProtection -ne $true) {
                Add-Finding "SECURITY" $proj "Cloud SQL Instance" $inst.name "Security - Storage Deep-Dive" `
                    "Deletion protection disabled" "Instance $($inst.name) can be deleted without an extra confirmation step" "MEDIUM" "sql instances list" `
                    "Enable deletion protection so this instance can't be deleted by a single mistaken/malicious command: 'gcloud sql instances patch NAME --deletion-protection'."
            }
            if ($availability -eq 'ZONAL') {
                Add-Finding "SERVICES" $proj "Cloud SQL Instance" $inst.name "Services - Storage Deep-Dive" `
                    "No High Availability configured (informational)" "Instance $($inst.name) is ZONAL (single zone, no automatic failover)" "LOW" "sql instances list" `
                    "If this is a production database, switch to REGIONAL availabilityType for automatic failover across zones - this is a resilience, not strictly security, recommendation but belongs in the same review."
            }
        }
    }
}

function Invoke-SpannerAndBigtable {
    Log-Info "[STORAGE/DB] Auditing Cloud Spanner and Bigtable instances for public IAM bindings..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }

        $spOut = Join-Path $RawDir "spanner_$proj.json"
        $spInstances = Get-GcloudJson -Description "spanner instances list" -Long -RawFile $spOut -GcloudArgs @('spanner','instances','list',"--project=$proj")
        foreach ($inst in $spInstances) {
            if (-not $inst.name) { continue }
            $instShort = Split-Path $inst.name -Leaf
            $policyRaw = Invoke-Gcloud -Description "spanner iam policy" -GcloudArgs @('spanner','instances','get-iam-policy',$instShort,"--project=$proj",'--format=json')
            if ($policyRaw -match 'allUsers|allAuthenticatedUsers') {
                Add-Finding "SECURITY" $proj "Cloud Spanner Instance" $instShort "Security - Storage Deep-Dive" `
                    "Publicly accessible Spanner instance" "Instance $instShort grants access to allUsers/allAuthenticatedUsers" "CRITICAL" "spanner instances get-iam-policy" `
                    "Remove the public binding immediately and restrict to named principals/service accounts. Spanner typically holds primary transactional data - public exposure here is a top-tier incident."
            } else {
                Add-Finding "SERVICES" $proj "Cloud Spanner Instance" $instShort "Services - Storage Deep-Dive" `
                    "Spanner instance in use (informational - review databases manually)" "Instance $instShort exists; review its databases individually for CMEK, IAM, and backup schedule, which this script does not enumerate at the database level" "LOW" "spanner instances list" `
                    "Run 'gcloud spanner databases list --instance=$instShort' and check each database's backup schedule and encryption config manually, or extend this script's spanner function to loop databases too."
            }
        }

        $btOut = Join-Path $RawDir "bigtable_$proj.json"
        $btInstances = Get-GcloudJson -Description "bigtable instances list" -Long -RawFile $btOut -GcloudArgs @('bigtable','instances','list',"--project=$proj")
        foreach ($inst in $btInstances) {
            if (-not $inst.name) { continue }
            $instShort = Split-Path $inst.name -Leaf
            $policyRaw = Invoke-Gcloud -Description "bigtable iam policy" -GcloudArgs @('bigtable','instances','get-iam-policy',$instShort,"--project=$proj",'--format=json')
            if ($policyRaw -match 'allUsers|allAuthenticatedUsers') {
                Add-Finding "SECURITY" $proj "Bigtable Instance" $instShort "Security - Storage Deep-Dive" `
                    "Publicly accessible Bigtable instance" "Instance $instShort grants access to allUsers/allAuthenticatedUsers" "CRITICAL" "bigtable instances get-iam-policy" `
                    "Remove the public binding immediately and restrict to named principals/service accounts."
            }
        }
    }
}

function Invoke-MemorystoreAndFilestore {
    Log-Info "[STORAGE/DB] Auditing Memorystore (Redis) and Filestore for auth/encryption/network exposure..."
    foreach ($proj in $script:Projects) {
        if (-not $proj) { continue }

        $redisOut = Join-Path $RawDir "redis_$proj.json"
        $redisInstances = Get-GcloudJson -Description "redis instances list" -Long -RawFile $redisOut -GcloudArgs @('redis','instances','list',"--project=$proj",'--region=-')
        foreach ($r in $redisInstances) {
            $name = Split-Path $r.name -Leaf
            if ($r.authEnabled -ne $true) {
                Add-Finding "SECURITY" $proj "Memorystore Redis" $name "Security - Storage Deep-Dive" `
                    "AUTH not enabled on Redis instance" "Instance $name does not require an AUTH token to connect" "HIGH" "redis instances list" `
                    "Enable AUTH so any client on the network path still needs a credential to connect: 'gcloud redis instances update NAME --auth-enabled --region=REGION'. Even though Memorystore is VPC-internal, defense in depth matters for lateral-movement scenarios."
            }
            $transitEnc = if ($r.transitEncryptionMode) { $r.transitEncryptionMode } else { 'DISABLED' }
            if ($transitEnc -eq 'DISABLED') {
                Add-Finding "SECURITY" $proj "Memorystore Redis" $name "Security - Storage Deep-Dive" `
                    "In-transit encryption disabled" "Instance $name does not encrypt traffic in transit" "MEDIUM" "redis instances list" `
                    "Enable in-transit encryption (TLS) if your client library supports it: 'gcloud redis instances update NAME --transit-encryption-mode=SERVER_AUTHENTICATION'."
            }
        }

        $fsOut = Join-Path $RawDir "filestore_$proj.json"
        $fsInstances = Get-GcloudJson -Description "filestore instances list" -Long -RawFile $fsOut -GcloudArgs @('filestore','instances','list',"--project=$proj")
        foreach ($f in $fsInstances) {
            $name = Split-Path $f.name -Leaf
            $netMode = if ($f.networks -and $f.networks[0].modes) { $f.networks[0].modes[0] } else { 'unknown' }
            Add-Finding "SERVICES" $proj "Filestore Instance" $name "Services - Storage Deep-Dive" `
                "Filestore instance in use (informational)" "Instance $name uses network mode $netMode - confirm it's reachable only from intended VPC/subnets, with NFS exports scoped to specific IP ranges, not 0.0.0.0/0" "LOW" "filestore instances list" `
                "Manually confirm the NFS export's ipRanges restrict access to only the client subnets that need it ('gcloud filestore instances describe NAME' -> fileShares[].nfsExportOptions)."
        }
    }
}

function Invoke-StorageDbDeepdiveSection {
    if (-not $RunStorageDbDeepdive) { Log-Info "[STORAGE/DB] Skipped (RUN_STORAGE_DB_DEEPDIVE=false)"; return }
    Invoke-GcsDeep
    Invoke-BigQueryDeep
    Invoke-CloudSqlDeep
    Invoke-SpannerAndBigtable
    Invoke-MemorystoreAndFilestore
}

###############################################################################
# 7D. SECTION F - BILLING/USAGE-DRIVEN SCOPE & COVERAGE-GAP DETECTION
###############################################################################

$script:CoveredAssetTypes = @(
    'compute.googleapis.com/Instance', 'compute.googleapis.com/Firewall', 'compute.googleapis.com/Disk',
    'compute.googleapis.com/Subnetwork', 'compute.googleapis.com/Network', 'storage.googleapis.com/Bucket',
    'sqladmin.googleapis.com/Instance', 'container.googleapis.com/Cluster', 'cloudkms.googleapis.com/CryptoKey',
    'run.googleapis.com/Service', 'cloudfunctions.googleapis.com/CloudFunction', 'bigquery.googleapis.com/Dataset',
    'artifactregistry.googleapis.com/Repository', 'iam.googleapis.com/ServiceAccount', 'dns.googleapis.com/ManagedZone',
    'spanner.googleapis.com/Instance', 'bigtableadmin.googleapis.com/Instance', 'redis.googleapis.com/Instance',
    'file.googleapis.com/Instance', 'cloudbuild.googleapis.com/Build'
)

function Invoke-BillingCostByService {
    if (-not $BillingExportTable) {
        Log-Info "[BILLING] Skipping cost-based prioritization - set BILLING_EXPORT_TABLE (BigQuery billing export) to enable."
        Add-Finding "SERVICES" $(if ($script:AssetScope) { $script:AssetScope } else { 'N/A' }) "Billing Export" "N/A" "Services - Cost Governance" `
            "BigQuery Billing Export not configured for this audit run" "BILLING_EXPORT_TABLE was not set, so cost-by-service prioritization could not run" "LOW" "n/a" `
            "Enable BigQuery Billing Export (Billing > Billing export > BigQuery export) and re-run this script with BILLING_EXPORT_TABLE set. This lets the audit prioritize by what you actually pay for, surfacing forgotten-but-running resources (e.g. an old Spanner instance nobody remembers) that asset inventory alone won't flag as 'important'."
        return
    }
    if (-not (Get-Command bq -ErrorAction SilentlyContinue)) {
        Log-Warn "[BILLING] 'bq' CLI not found; cannot query BILLING_EXPORT_TABLE. Install via: gcloud components install bq"
        return
    }

    Log-Info "[BILLING] Querying top $BillingTopNServices services by spend over last $BillingLookbackDays days..."
    $query = @"
SELECT service.description AS service, ROUND(SUM(cost),2) AS total_cost, currency
FROM ``$BillingExportTable``
WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL $BillingLookbackDays DAY)
GROUP BY service, currency
ORDER BY total_cost DESC
LIMIT $BillingTopNServices
"@
    $out = Join-Path $RawDir 'billing_top_services.json'
    $raw = Invoke-ExternalCommand -Description "bq billing query" -FilePath 'bq' -Arguments @('query','--use_legacy_sql=false','--format=json','--quiet',$query) -TimeoutSeconds $GcloudTimeoutLong
    if ($raw) { Set-Content -Path $out -Value $raw }
    if ([string]::IsNullOrWhiteSpace($raw)) { Log-Warn "[BILLING] Billing export query returned no rows - check BILLING_EXPORT_TABLE and permissions."; return }

    try { $rows = $raw | ConvertFrom-Json } catch { Log-Warn "[BILLING] Could not parse billing query output."; return }
    foreach ($row in @($rows)) {
        Add-Finding "SERVICES" $(if ($script:AssetScope) { $script:AssetScope } else { 'N/A' }) "Billed Service" $row.service "Services - Cost Governance" `
            "Active spend detected (informational, cost-prioritization signal)" "Service '$($row.service)' incurred $($row.total_cost) $($row.currency) over the last $BillingLookbackDays days" "LOW" "BigQuery billing export query" `
            "Cross-reference this against the rest of the report: any service here with real spend should have at least one finding above addressing its IAM/network/encryption posture. If it has zero other findings in this report, that's a coverage gap - review it manually or extend the script."
    }
}

function Invoke-UsageDrivenCoverageGaps {
    if (-not $script:AssetScope) { Log-Info "[BILLING] Skipping usage-driven coverage-gap check - no AssetScope."; return }
    Log-Info "[BILLING] Cross-checking actual deployed asset types against this script's audit coverage..."
    $out = Join-Path $RawDir 'all_resource_asset_types.json'
    $resources = Get-GcloudJson -Description "search-all-resources" -Long -RawFile $out -GcloudArgs @('asset','search-all-resources',"--scope=$script:AssetScope")
    if ($resources.Count -eq 0) { return }

    $grouped = $resources | Group-Object -Property assetType | Sort-Object Count -Descending
    foreach ($g in $grouped) {
        $atype = $g.Name
        if (-not $atype) { continue }
        if ($script:CoveredAssetTypes -contains $atype) { continue }
        Add-Finding "SERVICES" $script:AssetScope "Asset Type" $atype "Services - Coverage Gap" `
            "In-use resource type with no dedicated audit check" `
            "$($g.Count) resource(s) of type '$atype' exist in scope but this script has no dedicated security check for that type" `
            "MEDIUM" "asset search-all-resources (grouped by assetType)" `
            "This resource type is actually deployed (not just theoretically enabled) and currently has zero targeted coverage in this audit. At minimum, manually review its IAM bindings ('gcloud asset search-all-iam-policies --scope=$script:AssetScope --query=`"resource:$atype`"') and any public/network exposure. Consider adding a dedicated audit function for it (common candidates: Pub/Sub, Dataflow, Composer, Dataproc, Vertex AI, App Engine, Cloud Tasks, Cloud Scheduler, API Gateway, Cloud Interconnect/VPN)."
    }
}

function Invoke-BillingSection {
    if (-not $RunBillingDrivenAudit) { Log-Info "[BILLING] Skipped (RUN_BILLING_DRIVEN_AUDIT=false)"; return }
    Invoke-BillingCostByService
    Invoke-UsageDrivenCoverageGaps
}

###############################################################################
# 8. REPORT GENERATION
###############################################################################

function New-Reports {
    Log-Info "Writing CSV report..."
    $script:Findings | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

    Log-Info "Generating HTML report..."
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<html><head><meta charset='utf-8'><title>GCP Audit Report $Timestamp</title>")
    [void]$sb.AppendLine(@"
<style>
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
</style></head><body>
"@)
    [void]$sb.AppendLine("<h1>GCP Comprehensive Audit Report</h1>")
    [void]$sb.AppendLine("<div class='summary'>Generated: $Timestamp | Scope: $(if ($script:AssetScope) {$script:AssetScope} else {'N/A'}) | Projects: $($script:Projects.Count) | Total findings: $script:FindingsCount | Critical: $script:CriticalCount | High: $script:HighCount</div>")
    [void]$sb.AppendLine("<table><tr><th>Scope Type</th><th>Scope</th><th>Resource Type</th><th>Resource</th><th>Category</th><th>Check</th><th>Finding</th><th>Severity</th><th>Evidence</th><th>Recommendation</th></tr>")

    foreach ($f in $script:Findings) {
        $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
        $cells = "<td>$(& $enc $f.scope_type)</td><td>$(& $enc $f.scope_id)</td><td>$(& $enc $f.resource_type)</td><td>$(& $enc $f.resource_name)</td><td>$(& $enc $f.category)</td><td>$(& $enc $f.check)</td><td>$(& $enc $f.finding)</td><td>$(& $enc $f.severity)</td><td>$(& $enc $f.evidence)</td><td>$(& $enc $f.recommendation)</td>"
        [void]$sb.AppendLine("<tr class='$($f.severity)'>$cells</tr>")
    }
    [void]$sb.AppendLine("</table></body></html>")
    Set-Content -Path $HtmlFile -Value $sb.ToString() -Encoding UTF8
}

function Write-Summary {
    Write-Host ""
    Write-Host "==================================================================="
    Write-Host " GCP AUDIT COMPLETE"
    Write-Host "==================================================================="
    Write-Host " Scope:            $(if ($script:AssetScope) {$script:AssetScope} else {'N/A'})"
    Write-Host " Projects audited: $($script:Projects.Count)"
    Write-Host " Total findings:   $script:FindingsCount"
    Write-Host "   CRITICAL:       $script:CriticalCount"
    Write-Host "   HIGH:           $script:HighCount"
    Write-Host " CSV report:       $CsvFile"
    Write-Host " HTML report:      $HtmlFile"
    Write-Host " Raw evidence:     $RawDir\"
    Write-Host " Run log:          $LogFile"
    Write-Host "==================================================================="
}

###############################################################################
# 9. MAIN
###############################################################################

function Main {
    Test-Prerequisites
    Resolve-Scope
    Invoke-IamSection
    Invoke-SecuritySection
    Invoke-ServicesSection
    Invoke-ExtendedSection
    Invoke-StorageDbDeepdiveSection
    Invoke-BillingSection
    New-Reports
    Write-Summary
}

Main
