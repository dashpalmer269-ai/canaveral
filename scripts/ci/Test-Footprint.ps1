#Requires -Version 7
<#
.SYNOPSIS
    CI only: footprint audit of Canaveral's read-only diagnostics using
    Windows' built-in auditing (no downloaded tools).
.DESCRIPTION
    Turns on a global object-access audit policy for file and registry write
    access by any process, and Windows Filtering Platform connection auditing.
    A positive control (PowerShell writes a file and a registry value and
    opens a loopback connection) must be captured, proving the audit works.
    Then Canaveral runs diag-integrity over 500 System32 files, diag-snapshot
    and diag-output, and must produce no file-write, registry-write or
    network events at all.

    This complements, and does not replace, the Procmon and pktmon audit on
    the owner's VM (CLAUDE.md 7.2).
#>
param([Parameter(Mandatory)][string]$Exe)
. "$PSScriptRoot\Common.ps1"

# A uniquely named copy, so its events cannot be confused with anything else.
$dir = "$env:SystemDrive\canaveral-ci-audit"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$audited = Join-Path $dir "Canaveral-audit.exe"
Copy-Item $Exe $audited

# Audit policy. Subcategories by GUID, so the names' language does not matter.
$fileSystem = "{0CCE921D-69AE-11D9-BED3-505054503030}"
$registry = "{0CCE921E-69AE-11D9-BED3-505054503030}"
$wfpConnection = "{0CCE9226-69AE-11D9-BED3-505054503030}"
foreach ($g in $fileSystem, $registry, $wfpConnection) {
    auditpol /set /subcategory:$g /success:enable /failure:enable | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set $g failed" }
}
# Global SACLs: audit write access to every file and registry key, by everyone.
auditpol /resourceSACL /set /type:File /user:Everyone /success /failure /access:FW | Out-Host
if ($LASTEXITCODE -ne 0) { throw "file global SACL failed" }
auditpol /resourceSACL /set /type:Key /user:Everyone /success /failure /access:KW | Out-Host
if ($LASTEXITCODE -ne 0) { throw "registry global SACL failed" }
wevtutil sl Security /ms:1073741824

function Get-AuditEvents([datetime]$Since, [int[]]$Ids) {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Ids; StartTime = $Since } -ErrorAction SilentlyContinue |
        ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{ Id = $_.Id }
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            [pscustomobject]$d
        }
}
# The generic-write audit rules (FW, KW) also record READ_CONTROL and
# SYNCHRONIZE, which are not writes. An event counts as a write only if its
# access mask holds a real write right (or it is a value-modified or deleted
# event, which always are).
$fileWriteBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 # write/append data, EA, delete child, attributes, DELETE, WRITE_DAC, WRITE_OWNER
$keyWriteBits = 0x2 -bor 0x4 -bor 0x20 -bor 0x10000 -bor 0x40000 -bor 0x80000                      # set value, create subkey, create link, DELETE, WRITE_DAC, WRITE_OWNER
function Test-IsWrite($e) {
    if ($e.Id -in 4657, 4660) { return $true }
    if (-not $e.AccessMask) { return $true } # unknown access: count it, never assume a read
    $mask = [Convert]::ToInt64($e.AccessMask, 16)
    $bits = switch ($e.ObjectType) { 'File' { $fileWriteBits } 'Key' { $keyWriteBits } default { $fileWriteBits -bor $keyWriteBits } }
    return ($mask -band $bits) -ne 0
}
$fileIds = 4656, 4663, 4660, 4658
$regIds = 4656, 4657, 4663, 4660
$netIds = 5156, 5157, 5158, 5159

# Positive control.
$start = (Get-Date).AddSeconds(-1)
$controlFile = Join-Path $dir "audit-control.txt"
Set-Content -Path $controlFile -Value "control write"
New-Item -Path HKCU:\Software\CanaveralAuditControl -Force | Out-Null
New-ItemProperty -Path HKCU:\Software\CanaveralAuditControl -Name Control -Value 1 -Force | Out-Null
try { $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', 445); $c.Close() } catch { Write-Host "control connect: $_" }
Start-Sleep -Seconds 3
$events = @(Get-AuditEvents $start ($fileIds + $regIds + $netIds | Sort-Object -Unique))
$ctlFile = @($events | Where-Object { $_.ObjectName -like '*audit-control.txt' -and (Test-IsWrite $_) })
$ctlReg = @($events | Where-Object { $_.ObjectName -like '*CanaveralAuditControl*' -and (Test-IsWrite $_) })
$ctlNet = @($events | Where-Object { $_.Id -in $netIds -and $_.Application -like '*pwsh.exe' })
Write-Host "Positive control: $($ctlFile.Count) file, $($ctlReg.Count) registry, $($ctlNet.Count) network events"
Assert-True ($ctlFile.Count -gt 0) "the audit captures a file write and judges it a write (positive control)"
Assert-True ($ctlReg.Count -gt 0) "the audit captures a registry write and judges it a write (positive control)"
Assert-True ($ctlNet.Count -gt 0) "the audit captures a network connection (positive control)"
Remove-Item -Path HKCU:\Software\CanaveralAuditControl -Recurse -Force

# Canaveral under audit.
$start = (Get-Date).AddSeconds(-1)
$integrity = Invoke-Canaveral $audited @('diag-integrity', '--limit', '500')
$snapshot = Invoke-Canaveral $audited @('diag-snapshot')
$output = Invoke-Canaveral $audited @('diag-output')
Start-Sleep -Seconds 3
$end = Get-Date

Write-Host ($integrity.Output -split "`n" | Select-Object -First 40 | Out-String)
Assert-True ($integrity.Code -eq 0) "diag-integrity exits 0"
Assert-True ($integrity.Output -match 'Inspected (5\d\d) files') "diag-integrity inspected at least 500 files"
foreach ($k in 'svchost.exe', 'explorer.exe', 'lsass.exe') {
    $block = [regex]::Match($integrity.Output, "(?ms)^\s+\S*\\$([regex]::Escape($k))\r?\n\s+sha256:[^\n]*\n\s+signature: (\w+) via (\w+)")
    Assert-True ($block.Success -and $block.Groups[1].Value -eq 'Valid' -and $block.Groups[2].Value -in 'Catalog', 'Embedded') "$k verifies as Valid via Catalog or Embedded"
}
Assert-True ($snapshot.Code -eq 0) "diag-snapshot exits 0"

$events = @(Get-AuditEvents $start ($fileIds + $regIds + $netIds | Sort-Object -Unique))
$mine = @($events | Where-Object { $_.ProcessName -like '*\Canaveral-audit.exe' -or $_.Application -like '*canaveral-audit.exe' })
$mineNet = @($mine | Where-Object { $_.Id -in $netIds })
$mineObj = @($mine | Where-Object { $_.Id -notin $netIds })
$mineWrites = @($mineObj | Where-Object { Test-IsWrite $_ })
$mineReads = @($mineObj | Where-Object { -not (Test-IsWrite $_) })
Write-Host "Audit window $($start) to $($end): $($events.Count) audited events from all processes; from Canaveral: $($mineWrites.Count) write, $($mineReads.Count) read-type, $($mineNet.Count) network"
foreach ($e in ($mineWrites + $mineNet) | Select-Object -First 50) {
    Write-Host ("  VIOLATION event {0}: type {1} object {2} mask {3} app {4}" -f $e.Id, $e.ObjectType, $e.ObjectName, $e.AccessMask, $e.Application)
}
if ($mineReads.Count -gt 0) {
    Write-Host "Read-type access recorded by the generic-write rule (not writes):"
    $mineReads | Group-Object { "$($_.ObjectType) $($_.ObjectName) mask $($_.AccessMask)" } | Sort-Object Count -Descending |
        Select-Object -First 15 | ForEach-Object { Write-Host ("  {0,5} x {1}" -f $_.Count, $_.Name) }
}
Assert-True ($mineWrites.Count -eq 0) "Canaveral requested no file or registry write access ($($mineWrites.Count) events)"
Assert-True ($mineNet.Count -eq 0) "Canaveral made no network connections or binds ($($mineNet.Count) events)"

Complete-Script
