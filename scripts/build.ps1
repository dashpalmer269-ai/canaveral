#Requires -Version 5.1
<#
.SYNOPSIS
    Builds Canaveral.exe for windows/amd64.
.DESCRIPTION
    Pure-Go build (CGO_ENABLED=0) with -trimpath. No packers, no obfuscation,
    symbols kept (CLAUDE.md 1.3 and section 8). Prints the SHA-256 of the result.

    By default the requireAdministrator manifest (CLAUDE.md A8) is embedded,
    so every launch shows a UAC prompt. -NoManifest builds a test-only binary
    without it, for checking how the tool degrades when run as a standard user.
#>
[CmdletBinding()]
param(
    [string]$Version = "0.0.0-dev",
    [string]$Output = "",
    [switch]$NoManifest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

if (-not $Output) {
    $Output = if ($NoManifest) { "dist\Canaveral-nomanifest.exe" } else { "dist\Canaveral.exe" }
}
$syso = "cmd\canaveral\rsrc_windows_amd64.syso"
$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
try {
    go version
    if ($LASTEXITCODE -ne 0) { throw "go not found on PATH" }

    if (Test-Path $syso) { Remove-Item $syso }
    # gensyso runs on this machine, so it must not inherit a cross-compile target.
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    if (-not $NoManifest) {
        # Generated from the manifest by a tool in this repository; never committed.
        go run .\tools\gensyso -manifest cmd\canaveral\canaveral.manifest -o $syso
        if ($LASTEXITCODE -ne 0) { throw "gensyso failed with exit code $LASTEXITCODE" }
    }

    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    $outDir = Split-Path -Parent $Output
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir | Out-Null
    }

    go build -trimpath -ldflags "-X main.version=$Version" -o $Output .\cmd\canaveral
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

    $hash = (Get-FileHash -Path $Output -Algorithm SHA256).Hash
    $kind = if ($NoManifest) { "WITHOUT manifest (test build only)" } else { "with requireAdministrator manifest" }
    Write-Host "Built $Output (version $Version) $kind"
    Write-Host "SHA256 $hash"
}
finally {
    if (Test-Path $syso) { Remove-Item $syso }
    foreach ($k in $saved.Keys) {
        if ($null -eq $saved[$k]) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
        else { Set-Item "Env:$k" $saved[$k] }
    }
    Pop-Location
}
