<#
.SYNOPSIS
    Serves the site locally so the assessment planner can be tested in a real browser.

.DESCRIPTION
    The planner loads ES modules and fetches assets/catalog/checks.json. Opening assessments.html straight
    from disk fails that fetch (file:// origins are opaque), so the page shows its catalog
    error banner. This serves the repo over http://localhost so the page behaves exactly as
    it does in production.

    Static files only, no dependencies, no admin rights needed. Ctrl+C to stop.

.EXAMPLE
    pwsh -File tools/Serve-Site.ps1

.EXAMPLE
    pwsh -File tools/Serve-Site.ps1 -Port 8080 -NoBrowser
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot

$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.js'   = 'text/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.png'  = 'image/png'
    '.jpg'  = 'image/jpeg'
    '.ico'  = 'image/x-icon'
    '.zip'  = 'application/zip'
    '.txt'  = 'text/plain; charset=utf-8'
    '.md'   = 'text/markdown; charset=utf-8'
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")

try { $listener.Start() }
catch { throw "Could not listen on port $Port. Try -Port with a different value. ($($_.Exception.Message))" }

$url = "http://localhost:$Port/assessments.html"
Write-Host ''
Write-Host "  Serving $root" -ForegroundColor DarkGray
Write-Host "  Planner: $url" -ForegroundColor Cyan
Write-Host '  Ctrl+C to stop.' -ForegroundColor DarkGray
Write-Host ''

if (-not $NoBrowser) { Start-Process $url | Out-Null }

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response

        $rel = [System.Uri]::UnescapeDataString($req.Url.AbsolutePath).TrimStart('/')
        if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'assessments.html' }

        # Contain every request inside the repo, whatever the path claims.
        $full = [System.IO.Path]::GetFullPath((Join-Path $root $rel))
        $inside = $full.StartsWith([System.IO.Path]::GetFullPath($root), [StringComparison]::OrdinalIgnoreCase)

        if (-not $inside -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {
            $res.StatusCode = 404
            $body = [System.Text.Encoding]::UTF8.GetBytes('404 not found')
            $res.OutputStream.Write($body, 0, $body.Length)
            Write-Host ("  404  /{0}" -f $rel) -ForegroundColor Yellow
        }
        else {
            $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
            $res.ContentType = $(if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' })
            # The catalog and manifest change as you rebuild them; never let the browser cache.
            $res.Headers.Add('Cache-Control', 'no-store')
            $bytes = [System.IO.File]::ReadAllBytes($full)
            $res.ContentLength64 = $bytes.Length
            $res.OutputStream.Write($bytes, 0, $bytes.Length)
            Write-Host ("  200  /{0}  ({1:N0} bytes)" -f $rel, $bytes.Length) -ForegroundColor DarkGray
        }

        $res.OutputStream.Close()
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host ''
    Write-Host '  Stopped.' -ForegroundColor DarkGray
}
