#Requires -Version 5.1
<#
.SYNOPSIS
    Builds dist\Canaveral.exe for windows/amd64.
.DESCRIPTION
    Pure-Go build (CGO_ENABLED=0) with -trimpath. No packers, no obfuscation,
    symbols kept (CLAUDE.md 1.3 and section 8). Prints the SHA-256 of the result.
#>
[CmdletBinding()]
param(
    [string]$Version = "0.0.0-dev",
    [string]$Output = "dist\Canaveral.exe"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
try {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    $outDir = Split-Path -Parent $Output
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir | Out-Null
    }

    go version
    if ($LASTEXITCODE -ne 0) { throw "go not found on PATH" }

    go build -trimpath -ldflags "-X main.version=$Version" -o $Output .\cmd\canaveral
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

    $hash = (Get-FileHash -Path $Output -Algorithm SHA256).Hash
    Write-Host "Built $Output (version $Version)"
    Write-Host "SHA256 $hash"
}
finally {
    foreach ($k in $saved.Keys) {
        if ($null -eq $saved[$k]) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
        else { Set-Item "Env:$k" $saved[$k] }
    }
    Pop-Location
}
