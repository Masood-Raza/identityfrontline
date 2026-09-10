<#
.SYNOPSIS
    Packages the local assessment runner and publishes a signed-hash download manifest.

.DESCRIPTION
    Produces a versioned ZIP under assets/runner/ and a manifest under assets/catalog/.

    The website only ever serves these two static artefacts. It receives no tenant data,
    no reports and no tokens -- the manifest exists so a user can verify that the package
    they downloaded is the one this repository built.

    Authenticode signing is applied when -CertificateThumbprint is supplied. The SHA256 in
    the manifest is published either way so the download can be verified without a
    code-signing certificate.

.EXAMPLE
    pwsh -File tools/Build-RunnerPackage.ps1 -Version 1.0.0

.EXAMPLE
    pwsh -File tools/Build-RunnerPackage.ps1 -Version 1.0.0 -CertificateThumbprint ABC123...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot   = Split-Path -Parent $PSScriptRoot
$runnerSrc  = Join-Path $repoRoot 'runner'
$catalogSrc = Join-Path $repoRoot 'assets/catalog/catalog.json'
$outDir     = Join-Path $repoRoot 'assets/runner'
$manifestOut= Join-Path $repoRoot 'assets/catalog/manifest.json'

foreach ($p in $runnerSrc, $catalogSrc) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing: $p. Build the catalog first." }
}

$catalog = Get-Content -LiteralPath $catalogSrc -Raw -Encoding UTF8 | ConvertFrom-Json

# ------------------------------------------------------------------------------------------
# Stage
# ------------------------------------------------------------------------------------------
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "iffl-runner-$Version-$(Get-Random)"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

try {
    Copy-Item -Path (Join-Path $runnerSrc '*') -Destination $stage -Recurse -Force
    # The runner reads the catalog beside itself, so the package is self-contained and the
    # permission preview the user approved is the one that runs.
    Copy-Item -LiteralPath $catalogSrc -Destination (Join-Path $stage 'catalog.json') -Force

    Set-Content -LiteralPath (Join-Path $stage 'VERSION') -Value $Version -Encoding UTF8

    $notice = @"
Identity Frontline local assessment runner $Version

This package bundles and invokes M365-Assess.

    M365-Assess
    Copyright (c) Galvnyz
    Licensed under the MIT License
    https://github.com/Galvnyz/M365-Assess

Pinned engine version : $($catalog.source.moduleVersion)
Control registry      : schema $($catalog.registry.schemaVersion), data $($catalog.registry.dataVersion)
Catalog source ref    : $($catalog.source.ref)

The MIT License permits use, copying, modification and distribution provided this
notice and the accompanying licence text are retained. See LICENSE-M365-Assess.txt.
"@
    Set-Content -LiteralPath (Join-Path $stage 'NOTICE.txt') -Value $notice -Encoding UTF8

    # ------------------------------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------------------------------
    $signed = $false
    if ($CertificateThumbprint) {
        $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) { $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue }
        if (-not $cert) { throw "Code-signing certificate $CertificateThumbprint not found." }

        foreach ($f in Get-ChildItem -LiteralPath $stage -Filter *.ps1 -Recurse) {
            $r = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -TimestampServer $TimestampServer -HashAlgorithm SHA256
            if ($r.Status -ne 'Valid') { throw "Signing failed for $($f.Name): $($r.StatusMessage)" }
        }
        $signed = $true
        Write-Host "Signed with $($cert.Subject)" -ForegroundColor Green
    }
    else {
        Write-Warning 'No -CertificateThumbprint supplied: the package is unsigned. Publish signed builds for production.'
    }

    # ------------------------------------------------------------------------------------------
    # Zip + hash
    # ------------------------------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    $zipName = "identityfrontline-assessment-runner-$Version.zip"
    $zipPath = Join-Path $outDir $zipName
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $zipPath).Length

    # ------------------------------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------------------------------
    $manifest = [ordered]@{
        manifestVersion = '1.0.0'
        generatedUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        runner = [ordered]@{
            version   = $Version
            file      = $zipName
            url       = "/assets/runner/$zipName"
            sha256    = $hash
            sizeBytes = $size
            signed    = $signed
            verify    = "Get-FileHash .\$zipName -Algorithm SHA256"
        }

        requires = [ordered]@{
            powerShell    = '7.0'
            modules       = @('M365-Assess', 'Microsoft.Graph.Authentication')
            engineVersion = $catalog.source.moduleVersion
        }

        assessment = [ordered]@{
            profile        = $catalog.profile.id
            authentication = 'interactive-delegated'
            sections       = @($catalog.profile.sections)
            checkCount     = $catalog.profile.checkCount
            scopeCount     = @($catalog.permissions).Count
            readOnly       = $true
        }

        catalog = [ordered]@{
            version       = $catalog.catalogVersion
            registryData  = $catalog.registry.dataVersion
            sourceRef     = $catalog.source.ref
        }

        privacy = [ordered]@{
            dataLeavesDevice = $false
            statement        = 'The website serves this manifest and the package only. No tenant data, report content or token is transmitted to identityfrontline.com.'
        }

        attribution = $catalog.source.attribution
    }

    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestOut -Encoding UTF8

    Write-Host "Package  : $zipPath" -ForegroundColor Green
    Write-Host ("  size   : {0:N0} bytes" -f $size)
    Write-Host "  sha256 : $hash"
    Write-Host "  signed : $signed"
    Write-Host "Manifest : $manifestOut" -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
