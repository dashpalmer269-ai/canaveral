#Requires -Version 7
<#
.SYNOPSIS
    CI only: builds a clean "invalid signature" test fixture from scratch.
.DESCRIPTION
    Writes a new, harmless PowerShell script and signs it with a throwaway
    self-signed code-signing certificate. Because that certificate's root is
    not trusted, Windows reports the signature as present but untrusted, which
    Canaveral must classify as Invalid. No existing signed file is modified.
    The certificate is removed after signing. Prints the fixture path.
#>
param([Parameter(Mandatory)][string]$OutDir)
. "$PSScriptRoot\Common.ps1"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$fixture = Join-Path $OutDir "canaveral-untrusted-fixture.ps1"
Set-Content -Path $fixture -Value "# Canaveral test fixture: signed with an untrusted certificate.`nWrite-Output 'fixture'" -Encoding utf8

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Canaveral CI Untrusted Test Signer" `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
try {
    $sig = Set-AuthenticodeSignature -FilePath $fixture -Certificate $cert
    Write-Host "Signed fixture: $($sig.Status) - $($sig.StatusMessage)"
} finally {
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
}
$check = Get-AuthenticodeSignature -FilePath $fixture
Write-Host "PowerShell's own check of the fixture: $($check.Status) ($($check.StatusMessage))"
Assert-True ($null -ne $check.SignerCertificate) "fixture carries a signature"
Assert-True ($check.Status -ne 'Valid') "fixture signature is not trusted by Windows"
Write-Output $fixture
if ($script:Failures.Count -gt 0) { Complete-Script }
