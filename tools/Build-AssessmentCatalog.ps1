<#
.SYNOPSIS
    Generates the versioned assessment catalog consumed by assessments.html and the local runner.

.DESCRIPTION
    Reads a pinned M365-Assess checkout and emits a single catalog.json describing sections,
    delegated Graph scopes, framework coverage and check counts.

    The catalog is the ONLY place the website and the runner may learn about frameworks,
    scopes or sections. Nothing may be hard-coded in the UI.

    Fails fast on upstream drift: an unrecognised registry collector, or a profile section
    that upstream no longer defines, stops the build rather than silently producing a wrong
    permission preview.

.EXAMPLE
    pwsh -File tools/Build-AssessmentCatalog.ps1 -SourcePath C:\src\M365-Assess

.NOTES
    Upstream: https://github.com/Galvnyz/M365-Assess (MIT, (c) Galvnyz)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [string]$OutputPath,
    [string]$SourceRef,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets/catalog/catalog.json'
}

# --- v1 profile: one auth surface (interactive Microsoft Graph delegated sign-in) -----------
# Deliberately excludes Email/Security (EXO RBAC role groups + Purview directory roles) and
# PowerBI (extra module). See docs/ASSESSMENT-CATALOG.md for the coverage rationale.
$ProfileId       = 'graph-delegated-v1'
$ProfileLabel    = 'Microsoft Graph (delegated)'
$ProfileSections = @('Tenant', 'Identity', 'Licensing', 'Intune', 'Collaboration', 'Hybrid')

# --- registry collector -> upstream section -------------------------------------------------
# Derived from src/M365-Assess/Common/Show-CheckProgress.ps1 ($script:CollectorSectionMap),
# extended with the collectors that map omits (verified against checkId prefixes).
$CollectorSection = @{
    'Entra'            = 'Identity'
    'CAEvaluator'      = 'Identity'
    'EntApp'           = 'Identity'
    'ExchangeOnline'   = 'Email'
    'DNS'              = 'Email'
    'Defender'         = 'Security'
    'Compliance'       = 'Security'
    'StrykerReadiness' = 'Security'
    'CriticalExposure' = 'Security'
    'PurviewRetention' = 'Security'
    'Intune'           = 'Intune'
    'SharePoint'       = 'Collaboration'
    'Teams'            = 'Collaboration'
    'Forms'            = 'Collaboration'
    'PowerBI'          = 'PowerBI'
}

# Known-but-unimplemented upstream collectors: present in registry.json with no collector
# script. Tracked upstream in src/M365-Assess/controls/sync-scope.json.
$UnimplementedCollectors = @('Backup')

$SectionCopy = @{
    'Tenant'        = 'Organisation profile, verified domains and security defaults.'
    'Identity'      = 'Users, MFA posture, admin roles, Conditional Access, app registrations, consent and password protection.'
    'Licensing'     = 'SKU allocation and assignment counts. Gates licence-dependent checks.'
    'Intune'        = 'Managed devices, compliance policies and configuration profiles.'
    'Collaboration' = 'SharePoint and OneDrive sharing, Teams access and meeting policy, Forms external access.'
    'Hybrid'        = 'Microsoft Entra Connect sync status and domain configuration.'
    'Email'         = 'Mailboxes, mail flow, anti-spam and anti-phishing, SPF/DKIM/DMARC.'
    'Security'      = 'Secure Score, Defender for Office 365, DLP and critical exposure checks.'
    'PowerBI'       = 'Power BI tenant settings: guest access, external sharing, publish to web.'
}

function Read-Json {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing required upstream file: $Path" }
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

# Returns the framework mapping keys on a check, or an empty array. Written the long way
# because StrictMode rejects .Properties.Name when a check carries an empty frameworks node.
function Get-FrameworkKey {
    param($Check)
    if ($null -eq $Check.frameworks) { return @() }
    @($Check.frameworks.PSObject.Properties | ForEach-Object { $_.Name })
}

# ------------------------------------------------------------------------------------------
# Load upstream sources
# ------------------------------------------------------------------------------------------
$moduleRoot = Join-Path $SourcePath 'src/M365-Assess'
if (-not (Test-Path -LiteralPath $moduleRoot)) { throw "Not an M365-Assess checkout: $SourcePath" }

$registry = Read-Json (Join-Path $moduleRoot 'controls/registry.json')
$manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $moduleRoot 'M365-Assess.psd1')

# Dot-source the upstream maps so the catalog tracks the code rather than a transcription.
. (Join-Path $moduleRoot 'Orchestrator/AssessmentMaps.ps1')
$maps = Get-AssessmentMaps
. (Join-Path $moduleRoot 'Setup/PermissionDefinitions.ps1')
$graphPerms = $script:RequiredGraphPermissions

if (-not $SourceRef) {
    $SourceRef = (& git -C $SourcePath rev-parse HEAD 2>$null)
    if (-not $SourceRef) { $SourceRef = 'unknown' }
}

# ------------------------------------------------------------------------------------------
# Guard: every registry collector must be accounted for
# ------------------------------------------------------------------------------------------
$seen = $registry.checks.collector | Sort-Object -Unique
$unknown = @($seen | Where-Object { $CollectorSection.Keys -notcontains $_ -and $UnimplementedCollectors -notcontains $_ })
if ($unknown.Count) {
    throw "Unrecognised registry collector(s): $($unknown -join ', '). Confirm which upstream section owns them, then update CollectorSection in this script."
}

$missingProfileSections = @($ProfileSections | Where-Object { $maps.SectionScopeMap.Keys -notcontains $_ })
if ($missingProfileSections.Count) {
    throw "Profile section(s) no longer defined upstream: $($missingProfileSections -join ', ')"
}

# ------------------------------------------------------------------------------------------
# Sections
# ------------------------------------------------------------------------------------------
$permReason = @{}
foreach ($p in $graphPerms) { $permReason[$p.Name] = $p.Reason }

$countsBySection = @{}
foreach ($c in $registry.checks) {
    if ($UnimplementedCollectors -contains $c.collector) { continue }
    $s = $CollectorSection[$c.collector]
    if (-not $countsBySection.ContainsKey($s)) { $countsBySection[$s] = 0 }
    $countsBySection[$s]++
}

$sections = @(foreach ($name in ($maps.SectionScopeMap.Keys | Sort-Object)) {
    [ordered]@{
        id         = $name
        label      = $name
        summary    = $(if ($SectionCopy.ContainsKey($name)) { $SectionCopy[$name] } else { $null })
        services   = @($maps.SectionServiceMap[$name])
        scopes     = @($maps.SectionScopeMap[$name])
        checkCount = $(if ($countsBySection.ContainsKey($name)) { $countsBySection[$name] } else { 0 })
        inProfile  = ($ProfileSections -contains $name)
    }
})

# ------------------------------------------------------------------------------------------
# Permission preview for the profile (exact union of delegated scopes)
# ------------------------------------------------------------------------------------------
$scopeSections = @{}
foreach ($name in $ProfileSections) {
    foreach ($s in @($maps.SectionScopeMap[$name])) {
        if (-not $scopeSections.ContainsKey($s)) {
            $scopeSections[$s] = [System.Collections.Generic.List[string]]::new()
        }
        $scopeSections[$s].Add($name)
    }
}

$undocumented = @()
$permissions = @(foreach ($s in ($scopeSections.Keys | Sort-Object)) {
    $documented = $permReason.ContainsKey($s)
    if (-not $documented) { $undocumented += $s }
    [ordered]@{
        name     = $s
        service  = 'Microsoft Graph'
        type     = 'Delegated'
        access   = 'Read-only'
        sections = @($scopeSections[$s])
        reason   = $(if ($documented) { $permReason[$s] } else { $null })
        # $false = requested at connect time but NOT granted by upstream Grant-M365AssessConsent.
        grantedByUpstreamConsentHelper = $documented
    }
})

if ($undocumented.Count) {
    Write-Warning "Scope(s) requested by AssessmentMaps but absent from PermissionDefinitions -- the upstream consent helper will not grant them: $($undocumented -join ', ')"
}

# ------------------------------------------------------------------------------------------
# Frameworks
# ------------------------------------------------------------------------------------------
$frameworkDir = Join-Path $moduleRoot 'controls/frameworks'
$profileCollectors = @($CollectorSection.GetEnumerator() |
    Where-Object { $ProfileSections -contains $_.Value } |
    ForEach-Object { $_.Key })

$frameworks = @(foreach ($file in (Get-ChildItem -LiteralPath $frameworkDir -Filter *.json | Sort-Object Name)) {
    $fw  = Read-Json $file.FullName
    $key = $fw.registryKey

    $mapped = @($registry.checks | Where-Object {
        $UnimplementedCollectors -notcontains $_.collector -and
        (Get-FrameworkKey $_) -contains $key -and
        @($_.frameworks.$key).Count -gt 0
    })
    $inProfile = @($mapped | Where-Object { $profileCollectors -contains $_.collector })

    [ordered]@{
        id            = $fw.frameworkId
        label         = $fw.label
        version       = $fw.version
        homepageUrl   = $fw.homepageUrl
        totalControls = $fw.totalControls
        mappedChecks  = $mapped.Count
        profileChecks = $inProfile.Count
        profilePct    = $(if ($mapped.Count) { [math]::Round(100 * $inProfile.Count / $mapped.Count) } else { 0 })
    }
})

# Framework keys present in registry mappings but shipping no catalog definition upstream.
$definedKeys = @($frameworks | ForEach-Object { $_.id })
$mappedKeys = [System.Collections.Generic.HashSet[string]]::new()
foreach ($c in $registry.checks) {
    foreach ($n in (Get-FrameworkKey $c)) { [void]$mappedKeys.Add($n) }
}
$unmappedOnly = @($mappedKeys | Where-Object { $definedKeys -notcontains $_ } | Sort-Object)

# ------------------------------------------------------------------------------------------
# Emit
# ------------------------------------------------------------------------------------------
$implemented = @($registry.checks | Where-Object { $UnimplementedCollectors -notcontains $_.collector }).Count
$profileChecks = ($ProfileSections |
    ForEach-Object { if ($countsBySection.ContainsKey($_)) { $countsBySection[$_] } else { 0 } } |
    Measure-Object -Sum).Sum

$catalog = [ordered]@{
    catalogVersion = '1.0.0'
    generatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    source = [ordered]@{
        name          = 'M365-Assess'
        repository    = 'https://github.com/Galvnyz/M365-Assess'
        ref           = $SourceRef
        moduleVersion = $manifest.ModuleVersion
        license       = 'MIT'
        attribution   = 'Assessment engine and control registry (c) Galvnyz, MIT licensed.'
    }

    registry = [ordered]@{
        schemaVersion     = $registry.schemaVersion
        dataVersion       = $registry.dataVersion
        totalChecks       = $registry.checks.Count
        implementedChecks = $implemented
        unimplemented     = @($UnimplementedCollectors)
    }

    profile = [ordered]@{
        id          = $ProfileId
        label       = $ProfileLabel
        authSurface = 'Microsoft Graph interactive sign-in (delegated, read-only)'
        sections    = @($ProfileSections)
        checkCount  = $profileChecks
        coveragePct = [math]::Round(100 * $profileChecks / $implemented)
        excluded    = [ordered]@{
            Email    = 'Requires the Exchange Online module and the View-Only Organization Management role group.'
            Security = 'Requires Exchange Online RBAC plus the Security Reader / Compliance Administrator directory roles.'
            PowerBI  = 'Requires the MicrosoftPowerBIMgmt module and Power BI tenant admin read access.'
        }
    }

    sections              = $sections
    permissions           = $permissions
    frameworks            = $frameworks
    unmappedFrameworkKeys = $unmappedOnly
}

$json = $catalog | ConvertTo-Json -Depth 12

if ($Check) {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        throw "Catalog missing at $OutputPath. Run without -Check to generate it."
    }
    $current = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8
    $pattern = '"generatedUtc":\s*"[^"]*"'
    if (($current -replace $pattern, '').Trim() -ne ($json -replace $pattern, '').Trim()) {
        throw "Catalog is out of date. Regenerate with: pwsh -File tools/Build-AssessmentCatalog.ps1 -SourcePath <path>"
    }
    Write-Host 'Catalog is up to date.' -ForegroundColor Green
    return
}

$dir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$json | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host "Catalog written to $OutputPath" -ForegroundColor Green
Write-Host ("  profile {0}: {1}/{2} checks ({3}%), {4} sections, {5} delegated scopes" -f
    $ProfileId, $profileChecks, $implemented, $catalog.profile.coveragePct,
    $ProfileSections.Count, $permissions.Count)
Write-Host ("  frameworks: {0} defined, {1} registry-only key(s) without a definition" -f
    $frameworks.Count, $unmappedOnly.Count)
