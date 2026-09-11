<#
.SYNOPSIS
    Emits metadata for the browser-implemented checks, from the M365-Assess control registry.

.DESCRIPTION
    assets/app/checks.js decides WHICH checks exist and HOW they are evaluated. This script
    supplies everything else about them — name, severity, rationale, remediation and the
    framework control mappings — read from the upstream registry so the mappings stay genuine
    rather than invented.

    The implemented check IDs are read out of checks.js, so the two can never silently drift:
    an ID with no registry entry fails the build.

.EXAMPLE
    pwsh -File tools/Build-CheckCatalog.ps1 -SourcePath ./M365-Assess

.NOTES
    Upstream: https://github.com/Galvnyz/M365-Assess (MIT, (c) Galvnyz)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [string]$ChecksJs,
    [string]$OutputPath,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $ChecksJs)    { $ChecksJs    = Join-Path $repoRoot 'assets/app/checks.js' }
if (-not $OutputPath)  { $OutputPath  = Join-Path $repoRoot 'assets/catalog/checks.json' }

$moduleRoot = Join-Path $SourcePath 'src/M365-Assess'
if (-not (Test-Path -LiteralPath $moduleRoot)) { throw "Not an M365-Assess checkout: $SourcePath" }
if (-not (Test-Path -LiteralPath $ChecksJs))   { throw "Check definitions not found: $ChecksJs" }

$registry = Get-Content -LiteralPath (Join-Path $moduleRoot 'controls/registry.json') -Raw -Encoding UTF8 | ConvertFrom-Json

# ------------------------------------------------------------------------------------------
# Which checks does the browser implement?
# ------------------------------------------------------------------------------------------
$js = Get-Content -LiteralPath $ChecksJs -Raw -Encoding UTF8
$ids = [regex]::Matches($js, "(?m)^\s*id:\s*'([A-Z0-9][A-Z0-9\-]*)'") |
    ForEach-Object { $_.Groups[1].Value }

if (-not $ids.Count) { throw "No check IDs found in $ChecksJs. Expected lines of the form: id: 'ENTRA-...'" }

$dupes = @($ids | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
if ($dupes.Count) { throw "Duplicate check IDs in checks.js: $($dupes -join ', ')" }

Write-Host "Implemented checks: $($ids.Count)" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------------
# Framework labels, for display alongside each mapping
# ------------------------------------------------------------------------------------------
$frameworkLabel = @{}
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'controls/frameworks') -Filter *.json) {
    $def = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $frameworkLabel[$def.registryKey] = $def.label
}

# ------------------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------------------
$byId = @{}
foreach ($c in $registry.checks) { $byId[$c.checkId] = $c }

$missing = @($ids | Where-Object { -not $byId.ContainsKey($_) })
if ($missing.Count) {
    throw "These implemented checks have no entry in the control registry:`n  $($missing -join "`n  ")`nEither the ID is wrong or upstream removed the check."
}

$checks = @(foreach ($id in ($ids | Sort-Object)) {
    $c = $byId[$id]

    $maps = [ordered]@{}
    foreach ($key in ($frameworkLabel.Keys | Sort-Object)) {
        $m = if ($c.frameworks -and ($c.frameworks.PSObject.Properties | ForEach-Object Name) -contains $key) { $c.frameworks.$key } else { $null }
        if ($null -ne $m -and $m.PSObject.Properties.Name -contains 'controlId' -and $m.controlId) {
            $maps[$key] = [ordered]@{
                label     = $frameworkLabel[$key]
                controlId = $m.controlId
            }
        }
    }

    $rem = [ordered]@{}
    if ($c.remediation) {
        if ($c.remediation.PSObject.Properties.Name -contains 'portal' -and $c.remediation.portal) {
            $rem['portal'] = $c.remediation.portal.path
        }
        if ($c.remediation.PSObject.Properties.Name -contains 'powershell' -and $c.remediation.powershell) {
            $rem['powershell'] = $c.remediation.powershell.command
        }
    }

    [ordered]@{
        id          = $c.checkId
        name        = $c.name
        category    = $c.category
        severity    = $(if ($c.impactRating) { $c.impactRating.severity } else { 'Unknown' })
        rationale   = $(if ($c.impactRating) { $c.impactRating.rationale } else { $null })
        licensing   = $(if ($c.licensing -and $c.licensing.PSObject.Properties.Name -contains 'minimum') { $c.licensing.minimum } else { $null })
        remediation = $rem
        frameworks  = $maps
    }
})

$sourceRef = (& git -C $SourcePath rev-parse HEAD 2>$null)
if (-not $sourceRef) { $sourceRef = 'unknown' }

$severityOrder = @('Critical', 'High', 'Medium', 'Low')
$bySeverity = [ordered]@{}
foreach ($s in $severityOrder) { $bySeverity[$s] = @($checks | Where-Object severity -eq $s).Count }

$out = [ordered]@{
    catalogVersion = '1.0.0'
    generatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    source = [ordered]@{
        name        = 'M365-Assess'
        repository  = 'https://github.com/Galvnyz/M365-Assess'
        ref         = $sourceRef
        license     = 'MIT'
        attribution = 'Control registry and framework mappings (c) Galvnyz, MIT licensed.'
        registry    = [ordered]@{
            schemaVersion = $registry.schemaVersion
            dataVersion   = $registry.dataVersion
        }
    }
    counts = [ordered]@{
        implemented   = $checks.Count
        registryTotal = $registry.checks.Count
        bySeverity    = $bySeverity
    }
    frameworks = [ordered]@{}
    checks     = $checks
}

# Per-framework coverage across the implemented set.
foreach ($key in ($frameworkLabel.Keys | Sort-Object)) {
    $n = @($checks | Where-Object { $_.frameworks.Contains($key) }).Count
    if ($n -gt 0) {
        $out.frameworks[$key] = [ordered]@{ label = $frameworkLabel[$key]; mappedChecks = $n }
    }
}

$json = $out | ConvertTo-Json -Depth 12

if ($Check) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { throw "Check catalog missing at $OutputPath." }
    $pattern = '"generatedUtc":\s*"[^"]*"'
    $current = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8
    if (($current -replace $pattern, '').Trim() -ne ($json -replace $pattern, '').Trim()) {
        throw "Check catalog is out of date. Regenerate with: pwsh -File tools/Build-CheckCatalog.ps1 -SourcePath <path>"
    }
    Write-Host 'Check catalog is up to date.' -ForegroundColor Green
    return
}

$dir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$json | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host "Check catalog written to $OutputPath" -ForegroundColor Green
Write-Host ("  {0} checks: {1}" -f $checks.Count, (($severityOrder | ForEach-Object { "$($bySeverity[$_]) $_" }) -join ', '))
Write-Host ("  mapped into {0} frameworks" -f $out.frameworks.Count)
