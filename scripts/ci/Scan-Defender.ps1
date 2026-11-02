#Requires -Version 7
<#
.SYNOPSIS
    CI only: scans the built executables with Microsoft Defender and reports
    the result (CLAUDE.md A7). A detection is reported as a warning, not
    hidden. This is CI evidence; the owner's VM run is still required.
#>
param([Parameter(Mandatory)][string[]]$Files)
. "$PSScriptRoot\Common.ps1"

$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $status) {
    Write-Host "::warning::Defender status is unavailable on this runner; scan skipped"
    exit 0
}
Write-Host ("Defender: engine {0}, antivirus signatures {1} ({2}), real-time protection {3}" -f `
        $status.AMEngineVersion, $status.AntivirusSignatureVersion, $status.AntivirusSignatureLastUpdated, $status.RealTimeProtectionEnabled)

$mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
$detected = 0
foreach ($f in $Files) {
    $path = (Resolve-Path $f).Path
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash
    $out = & $mp -Scan -ScanType 3 -File $path -DisableRemediation 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host "---- $path (SHA256 $hash), MpCmdRun exit $code`n$out"
    # MpCmdRun exits with 2 when a threat is found.
    if (($code -eq 2) -or ($out -match 'found [1-9]\d* threat')) {
        $detected++
        Write-Host "::warning::Defender flagged $path. Record this in docs/STATUS.md and investigate; never work around it with evasion (CLAUDE.md 1.3)."
    }
}
Write-Host "Defender detections: $detected of $($Files.Count) files"
exit 0
