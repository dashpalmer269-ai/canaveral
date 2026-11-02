#Requires -Version 7
<#
.SYNOPSIS
    CI only: runs Canaveral as a freshly created non-administrator account to
    check that it degrades gracefully (CLAUDE.md M3), and records what the
    requireAdministrator build does for such a user.
#>
param(
    [Parameter(Mandatory)][string]$NoManifestExe,
    [Parameter(Mandatory)][string]$ManifestExe
)
. "$PSScriptRoot\Common.ps1"

$dir = "$env:SystemDrive\canaveral-ci-user"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item $NoManifestExe "$dir\Canaveral-nomanifest.exe"
Copy-Item $ManifestExe "$dir\Canaveral.exe"

$name = "canaveralci"
$plain = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) + "!aZ1"
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -Group "Users" -Member $name
$cred = [pscredential]::new("$env:COMPUTERNAME\$name", $secure)
$isAdmin = (Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*\$name" }) -ne $null
Assert-True (-not $isAdmin) "test account is not an administrator"
$lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
Write-Host "UAC EnableLUA on this runner: $lua"

function Run-As([string]$File, [string]$Arguments) {
    $out = Join-Path $env:RUNNER_TEMP "canaveral-user-out.txt"
    $err = Join-Path $env:RUNNER_TEMP "canaveral-user-err.txt"
    try {
        $p = Start-Process -FilePath $File -ArgumentList $Arguments -Credential $cred -WorkingDirectory $dir `
            -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -Wait -PassThru
        return [pscustomobject]@{ Started = $true; Code = $p.ExitCode; Output = (Get-Content $out -Raw) + (Get-Content $err -Raw) }
    } catch {
        return [pscustomobject]@{ Started = $false; Code = $null; Output = $_.Exception.Message }
    }
}

try {
    $r = Run-As "$dir\Canaveral-nomanifest.exe" "diag-snapshot"
    Write-Host "---- diag-snapshot as standard user (started=$($r.Started), exit $($r.Code))"
    Write-Host $r.Output
    Assert-True ($r.Started -and $r.Code -eq 0) "diag-snapshot runs as a standard user and exits 0"
    Assert-True ($r.Output -match 'elevated=false') "elevation is reported as false"
    Assert-True ($r.Output -match 'Not elevated') "the operator is told what being unelevated means"
    Assert-True ($r.Output -match 'could not be fully read') "unreadable processes appear as coverage gaps"
    Assert-True ($r.Output -match 'Attribution: High [1-9]') "sockets are still attributed"

    # Informational: what the requireAdministrator build does for this user.
    $m = Run-As "$dir\Canaveral.exe" "diag-snapshot"
    Write-Host "---- requireAdministrator build as standard user (started=$($m.Started), exit $($m.Code))"
    Write-Host $m.Output
    if (-not $m.Started -and $m.Output -match 'elevation') {
        Write-Host "The manifest took effect: Windows refused to start the build without elevation."
    } else {
        Write-Host "::warning::The requireAdministrator build did not demand elevation for a standard user here (UAC EnableLUA=$lua). Record and re-check on the VM."
    }
} finally {
    Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
Complete-Script
