<#
.SYNOPSIS
    Runs a local, read-only Microsoft 365 security assessment from a wizard-generated run plan.

.DESCRIPTION
    Thin, security-constrained wrapper around M365-Assess. It:

      * accepts the run plan exported by the Identity Frontline assessment planner,
      * authenticates with Microsoft interactive sign-in ONLY,
      * verifies the scopes actually granted before collecting anything,
      * runs only the sections the plan selected, and
      * writes HTML, XLSX and CSV reports to a local folder.

    No tenant data, report, token or telemetry is sent to identityfrontline.com or anywhere
    else. Everything this script produces stays on the machine that ran it.

    Deliberate constraints:
      * Interactive delegated auth only. Client secrets, certificates, device code and
        managed identity are refused -- a local assessment run by an administrator does not
        need standing credentials, and refusing them keeps this package unable to run
        unattended if it is ever stolen.
      * Application (app-only) Graph permissions are never requested.
      * Only sections in the plan's profile are runnable.

.PARAMETER RunPlan
    Path to assessment-run-plan.json, exported from the planner.

.PARAMETER TenantId
    Tenant ID or *.onmicrosoft.com domain. Prompted for if omitted.

.PARAMETER OutputFolder
    Where reports are written. Defaults to .\M365-Assessment under the current directory.

.PARAMETER WhatIfPlan
    Validate the plan, show what would run and which scopes would be requested, then exit
    without signing in or contacting the tenant.

.EXAMPLE
    .\Invoke-IdentityFrontlineAssessment.ps1 -RunPlan .\assessment-run-plan.json -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Invoke-IdentityFrontlineAssessment.ps1 -RunPlan .\assessment-run-plan.json -WhatIfPlan

.NOTES
    Assessment engine: M365-Assess (c) Galvnyz, MIT licensed.
    https://github.com/Galvnyz/M365-Assess
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunPlan,
    [string]$TenantId,
    [string]$OutputFolder,
    [string]$CatalogPath,
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:PackageRoot = $PSScriptRoot
if (-not $CatalogPath) { $CatalogPath = Join-Path $PSScriptRoot 'catalog.json' }

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "    $Message" -ForegroundColor Yellow }

# ==========================================================================================
# 1. Load and validate the run plan against the catalog
# ==========================================================================================
Write-Step 'Validating run plan'

if (-not (Test-Path -LiteralPath $RunPlan)) { throw "Run plan not found: $RunPlan" }
if (-not (Test-Path -LiteralPath $CatalogPath)) { throw "Catalog not found: $CatalogPath" }

try { $plan = Get-Content -LiteralPath $RunPlan -Raw -Encoding UTF8 | ConvertFrom-Json }
catch { throw "Run plan is not valid JSON: $RunPlan" }

$catalog = Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($field in 'planVersion', 'profile', 'sections', 'frameworks', 'authentication') {
    if (-not $plan.PSObject.Properties.Name.Contains($field)) {
        throw "Run plan is missing required field '$field'. Re-export it from the planner."
    }
}

if ($plan.authentication -ne 'interactive-delegated') {
    throw "This package only runs interactive delegated assessments. Plan requests '$($plan.authentication)'."
}

if ($plan.profile -ne $catalog.profile.id) {
    throw "Run plan targets profile '$($plan.profile)' but this package ships '$($catalog.profile.id)'. Download the matching runner."
}

$planSections = @($plan.sections)
if (-not $planSections.Count) { throw 'Run plan selects no sections. Choose at least one area in the planner.' }

$allowed = @($catalog.profile.sections)
$outOfProfile = @($planSections | Where-Object { $allowed -notcontains $_ })
if ($outOfProfile.Count) {
    $why = foreach ($s in $outOfProfile) {
        if ($catalog.profile.excluded.PSObject.Properties.Name -contains $s) { "  - ${s}: $($catalog.profile.excluded.$s)" }
        else { "  - ${s}: not part of profile '$($catalog.profile.id)'" }
    }
    throw "Run plan selects sections this release cannot run:`n$($why -join "`n")"
}

# The plan carries a scope list, but it is advisory. Required scopes are always recomputed
# from the catalog so a hand-edited plan cannot widen what we ask for.
$required = @(
    $catalog.permissions |
        Where-Object { @($_.sections | Where-Object { $planSections -contains $_ }).Count -gt 0 } |
        ForEach-Object { $_.name }
) | Sort-Object -Unique

Write-Ok "Profile        : $($catalog.profile.id) (engine $($catalog.source.name) $($catalog.source.moduleVersion))"
Write-Ok "Sections       : $($planSections -join ', ')"
Write-Ok "Frameworks     : $(if (@($plan.frameworks).Count) { @($plan.frameworks) -join ', ' } else { '(all)' })"
Write-Ok "Delegated scopes: $($required.Count) (read-only)"
foreach ($s in $required) { Write-Host "      $s" -ForegroundColor DarkGray }

$ungranted = @(
    $catalog.permissions |
        Where-Object { $required -contains $_.name -and -not $_.grantedByUpstreamConsentHelper } |
        ForEach-Object { $_.name }
)
if ($ungranted.Count) {
    Write-Warn "Not covered by the standard consent grant: $($ungranted -join ', ')"
    Write-Warn 'Checks depending on these will report as Unknown until an administrator consents.'
}

if ($WhatIfPlan) {
    Write-Host ''
    Write-Host 'Plan is valid. No sign-in attempted and no tenant contacted (-WhatIfPlan).' -ForegroundColor Green
    return
}

# ==========================================================================================
# 2. Ensure the assessment engine is available at the pinned version
# ==========================================================================================
Write-Step 'Checking assessment engine'

$pinned = $catalog.source.moduleVersion
$installed = Get-Module -ListAvailable -Name 'M365-Assess' | Sort-Object Version -Descending | Select-Object -First 1

if (-not $installed) {
    Write-Warn "M365-Assess is not installed. Required version: $pinned"
    $answer = Read-Host "Install M365-Assess $pinned for the current user now? [y/N]"
    if ($answer -notmatch '^(y|yes)$') { throw 'Cannot continue without the assessment engine.' }
    Install-Module -Name 'M365-Assess' -RequiredVersion $pinned -Scope CurrentUser -Force -AllowClobber
    $installed = Get-Module -ListAvailable -Name 'M365-Assess' | Sort-Object Version -Descending | Select-Object -First 1
}
elseif ($installed.Version.ToString() -ne $pinned) {
    Write-Warn "Installed M365-Assess $($installed.Version) differs from the catalog's pinned $pinned."
    Write-Warn 'Check results and framework mappings may not match the planner preview.'
}

Import-Module -Name 'M365-Assess' -MinimumVersion $installed.Version -Force
Write-Ok "Engine ready: M365-Assess $($installed.Version)"

# ==========================================================================================
# 3. Interactive sign-in, then verify what was actually granted
# ==========================================================================================
Write-Step 'Signing in to Microsoft'

if (-not $TenantId) {
    $TenantId = Read-Host 'Tenant ID or domain (e.g. contoso.onmicrosoft.com)'
}
if ([string]::IsNullOrWhiteSpace($TenantId)) { throw 'A tenant is required.' }

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# NoWelcome keeps the banner (and any tenant identifiers in it) out of transcripts.
$connectArgs = @{
    TenantId    = $TenantId
    Scopes      = $required
    NoWelcome   = $true
    ErrorAction = 'Stop'
}

$attempt = 0
while ($true) {
    $attempt++
    try {
        Connect-MgGraph @connectArgs
        break
    }
    catch {
        # Retry only transient transport/throttling failures; never loop on a consent refusal.
        $transient = $_.Exception.Message -match 'throttl|too many requests|temporarily unavailable|timed out|503|429'
        if (-not $transient -or $attempt -ge 3) { throw }
        $wait = [math]::Pow(2, $attempt) * 5
        Write-Warn "Transient sign-in failure. Retrying in $wait seconds (attempt $attempt of 3)."
        Start-Sleep -Seconds $wait
    }
}

$ctx = Get-MgContext
if (-not $ctx) { throw 'Sign-in did not establish a Graph context.' }

if ($ctx.AuthType -ne 'Delegated') {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    throw "Refusing to continue: expected delegated auth, got '$($ctx.AuthType)'. This package does not run app-only assessments."
}

Write-Ok "Signed in as $($ctx.Account) on tenant $($ctx.TenantId)"

$granted = @($ctx.Scopes)
$missing = @($required | Where-Object { $granted -notcontains $_ })

if ($missing.Count) {
    Write-Warn "$($missing.Count) of $($required.Count) requested scopes were not granted:"
    foreach ($s in $missing) {
        $reason = ($catalog.permissions | Where-Object name -eq $s | Select-Object -First 1).reason
        Write-Host "      $s  -- $reason" -ForegroundColor Yellow
    }
    Write-Warn 'Checks needing these will report as Unknown and are excluded from the pass rate.'
    Write-Warn 'An administrator can grant them from Entra ID > Enterprise applications > Permissions.'

    $answer = Read-Host 'Continue with reduced coverage? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw 'Stopped at your request. No tenant data was collected.'
    }
}
else {
    Write-Ok "All $($required.Count) requested scopes granted."
}

# ==========================================================================================
# 4. Run the assessment
# ==========================================================================================
Write-Step 'Running assessment'

if (-not $OutputFolder) { $OutputFolder = Join-Path (Get-Location) 'M365-Assessment' }

$assessArgs = @{
    Section        = $planSections
    TenantId       = $TenantId
    OutputFolder   = $OutputFolder
    SkipConnection = $true   # we own the connection, and we verified it
    ErrorAction    = 'Stop'
}

$started = Get-Date
try {
    Invoke-M365Assessment @assessArgs
}
catch {
    # Surface the failure without echoing the exception's inner request/response payloads,
    # which can carry tenant object data.
    throw "Assessment failed: $($_.Exception.Message)"
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

$elapsed = (Get-Date) - $started

# ==========================================================================================
# 5. Done
# ==========================================================================================
Write-Step 'Complete'
Write-Ok ("Finished in {0:mm\:ss}" -f $elapsed)
Write-Ok "Reports: $OutputFolder"
Write-Host ''
Write-Host 'These reports contain usernames, role assignments, policy bodies and tenant' -ForegroundColor Yellow
Write-Host 'configuration. Treat them as confidential and do not upload them to public storage.' -ForegroundColor Yellow
Write-Host ''
Write-Host "Assessment engine: M365-Assess (c) Galvnyz, MIT licensed." -ForegroundColor DarkGray
