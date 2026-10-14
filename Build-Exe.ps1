<#
  Packages ThreatHuntPro.ps1 into a standalone console EXE with PS2EXE.
  Run in Windows PowerShell 5.1:  powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-Exe.ps1
  Optional code signing:          .\Build-Exe.ps1 -CertThumbprint <thumbprint in Cert:\CurrentUser\My>
#>
param([string]$CertThumbprint, [string]$Version = '1.0.0.0')
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable ps2exe)) {
    Write-Host 'Installing ps2exe module for the current user from PSGallery...'
    Install-Module ps2exe -Scope CurrentUser -Force
}
Import-Module ps2exe
$src = Join-Path $PSScriptRoot 'ThreatHuntPro.ps1'
$out = Join-Path $PSScriptRoot 'dist\ThreatHuntPro.exe'
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
# No -requireAdmin: the script elevates itself via UAC and can still run unelevated (-NoElevate).
Invoke-PS2EXE -inputFile $src -outputFile $out -title 'ThreatHunt Pro' -description 'Windows threat-hunting triage' `
    -product 'ThreatHunt Pro' -version $Version -x64
if ($CertThumbprint) {
    $cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint"
    Set-AuthenticodeSignature -FilePath $out -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' -HashAlgorithm SHA256 | Out-Null
}
Get-FileHash $out -Algorithm SHA256 | Format-List Path, Hash
