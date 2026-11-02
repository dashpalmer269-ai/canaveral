# Shared helpers for the CI-only scripts in this directory.
#
# These scripts change the machine they run on (they create local users,
# virtual disks, drive mappings and junctions). They exist only to test
# Canaveral on a disposable GitHub Actions runner and refuse to run anywhere
# else. NEVER run them on a customer machine.

$ErrorActionPreference = "Stop"

if ($env:GITHUB_ACTIONS -ne "true") {
    throw "This script is for disposable GitHub Actions runners only and modifies the machine. Refusing to run."
}

$script:Failures = New-Object System.Collections.Generic.List[string]

function Assert-True([bool]$Condition, [string]$Message) {
    if ($Condition) {
        Write-Host "PASS: $Message"
    } else {
        Write-Host "::error::FAIL: $Message"
        $script:Failures.Add($Message)
    }
}

# Invoke-Canaveral runs the exe and returns its exit code and combined output.
function Invoke-Canaveral([string]$Exe, [string[]]$Arguments) {
    $out = & $Exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
}

function Complete-Script {
    if ($script:Failures.Count -gt 0) {
        throw "$($script:Failures.Count) check(s) failed:`n  " + ($script:Failures -join "`n  ")
    }
    Write-Host "All checks passed."
    exit 0
}
