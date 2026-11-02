#Requires -Version 7
<#
.SYNOPSIS
    CI only: checks on real Windows that Canaveral never accepts the system
    drive as an output destination, however it is disguised, and that
    diag-output writes nothing.
#>
param([Parameter(Mandatory)][string]$Exe)
. "$PSScriptRoot\Common.ps1"

$Exe = (Resolve-Path $Exe).Path
$sysDrive = $env:SystemDrive # normally C:
$data = $null
foreach ($l in 'D', 'E', 'F') {
    $v = Get-Volume -DriveLetter $l -ErrorAction SilentlyContinue
    if ($v -and "${l}:" -ne $sysDrive -and $v.DriveType -eq 'Fixed') { $data = "${l}:"; break }
}
Write-Host "System drive $sysDrive, non-system data drive $data"

$mustNotExist = New-Object System.Collections.Generic.List[string]

function Expect-Refused([string]$Label, [string]$Path, [string]$Reason) {
    $r = Invoke-Canaveral $Exe @('diag-output', '--output', $Path)
    Write-Host "---- $Label ($Path), exit $($r.Code)`n$($r.Output)"
    Assert-True ($r.Code -eq 1 -and $r.Output -match 'Decision: REFUSED') "$Label is refused"
    if ($Reason) { Assert-True ($r.Output -match $Reason) "$Label refusal mentions /$Reason/" }
    $mustNotExist.Add($Path)
}

# 1. The system drive, named directly.
Expect-Refused "system drive" "$sysDrive\Canaveral_CI_Reports" 'system volume'

# 2. A SUBST drive letter that points into the system drive.
$substTarget = "$sysDrive\canaveral-ci-subst"
New-Item -ItemType Directory -Path $substTarget -Force | Out-Null
subst X: $substTarget
try {
    Expect-Refused "SUBST drive into the system drive" "X:\Reports" ''
    Assert-True (-not (Test-Path "$substTarget\Reports")) "nothing created behind the SUBST drive"
} finally {
    subst X: /D
}

if ($data) {
    # 3. An explicit non-system fixed drive is accepted, and nothing is written.
    $ok = Invoke-Canaveral $Exe @('diag-output', '--output', "$data\canaveral-ci-accepted")
    Write-Host "---- explicit non-system drive, exit $($ok.Code)`n$($ok.Output)"
    Assert-True ($ok.Code -eq 0 -and $ok.Output -match 'Decision: ACCEPTED' -and $ok.Output -match 'chosen explicitly') "explicit non-system fixed drive is accepted"
    $mustNotExist.Add("$data\canaveral-ci-accepted")

    # 4. A junction on the data drive that leads to the system drive.
    $junction = "$data\canaveral-ci-junction"
    New-Item -ItemType Junction -Path $junction -Target "$sysDrive\" | Out-Null
    try {
        Expect-Refused "junction to the system drive" "$junction\Reports" 'link, junction or mount point'
    } finally {
        Remove-Item $junction -Force
    }
    Assert-True (-not (Test-Path "$sysDrive\Reports")) "nothing created through the junction"
} else {
    Write-Host "::warning::No non-system fixed drive on this runner; explicit-destination and junction checks skipped"
}

# 5. The system drive's admin share mapped as a network drive.
net use Z: "\\localhost\$($sysDrive.TrimEnd(':'))`$" /persistent:no 2>&1 | Out-Host
if ($LASTEXITCODE -eq 0) {
    try {
        Expect-Refused "network drive" "Z:\Reports" 'network drive'
    } finally {
        net use Z: /delete /y | Out-Null
    }
} else {
    Write-Host "::warning::Could not map \\localhost admin share; network-drive check skipped"
}

# 6. A file-backed virtual disk: fixed, non-system, bus type FileBackedVirtual.
$vhd = Join-Path $env:RUNNER_TEMP "canaveral-ci.vhdx"
$dp = Join-Path $env:RUNNER_TEMP "canaveral-ci-diskpart.txt"
@"
create vdisk file="$vhd" maximum=64 type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=CANAVERAL
assign letter=V
"@ | Set-Content -Path $dp -Encoding ascii
diskpart /s $dp | Out-Host
if ($LASTEXITCODE -eq 0 -and (Test-Path 'V:\')) {
    try {
        Copy-Item $Exe 'V:\Canaveral.exe'
        $d = Invoke-Canaveral 'V:\Canaveral.exe' @('diag-output')
        Write-Host "---- default destination on a virtual disk, exit $($d.Code)`n$($d.Output)"
        Assert-True ($d.Code -eq 1 -and $d.Output -match 'FileBackedVirtual') "virtual disk is reported with its real bus type and refused as a default"
        $e = Invoke-Canaveral 'V:\Canaveral.exe' @('diag-output', '--output', 'V:\Reports')
        Assert-True ($e.Code -eq 0 -and $e.Output -match 'Decision: ACCEPTED') "virtual disk is accepted when chosen explicitly"
        $mustNotExist.Add('V:\Canaveral_Reports'); $mustNotExist.Add('V:\Reports')
        foreach ($p in 'V:\Canaveral_Reports', 'V:\Reports') { Assert-True (-not (Test-Path $p)) "diag-output created nothing at $p" }
    } finally {
        "select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content -Path $dp -Encoding ascii
        diskpart /s $dp | Out-Null
    }
} else {
    Write-Host "::warning::diskpart could not create a virtual disk; virtual-disk checks skipped"
}

foreach ($p in $mustNotExist) {
    if ($p -notmatch '^[XZV]:') { Assert-True (-not (Test-Path $p)) "diag-output wrote nothing at $p" }
}
Complete-Script
