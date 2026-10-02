#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('5.1','7.4.13','7.6.6')][string]$Version,
    [Parameter(Mandatory)][ValidateSet('x86','x64')][string]$Architecture,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'The runtime matrix requires Windows.' }
if ($Version -eq '5.1') {
    $directory = if ($Architecture -eq 'x86') { 'SysWOW64' } elseif ([Environment]::Is64BitProcess) { 'System32' } else { 'Sysnative' }
    $path = Join-Path $env:WINDIR "$directory/WindowsPowerShell/v1.0/powershell.exe"
} else {
    $pins = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'dependencies.psd1')
    [void][IO.Directory]::CreateDirectory($Destination)
    $archive = Join-Path $Destination "PowerShell-$Version-win-$Architecture.zip"
    if (-not (Test-Path -LiteralPath $archive)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/PowerShell/PowerShell/releases/download/v$Version/PowerShell-$Version-win-$Architecture.zip" -OutFile $archive -TimeoutSec 180
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pins.PowerShell[$Version][$Architecture]) { throw 'Runtime checksum mismatch.' }
    $directory = Join-Path $Destination "$Version-$Architecture"
    # Re-extract the verified archive; do not trust an existing extracted executable.
    Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
    $path = Join-Path $directory 'pwsh.exe'
}
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing runtime: $Version $Architecture" }
$probe = @(& $path -NoLogo -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString(); [Environment]::Is64BitProcess')
if ($LASTEXITCODE -ne 0 -or $probe.Count -ne 2) { throw 'Runtime probe failed.' }
$versionMatches = if ($Version -eq '5.1') { [string]$probe[0] -match '^5\.1\.' } else { [string]$probe[0] -eq $Version }
if (-not $versionMatches -or ([string]$probe[1] -eq 'True') -ne ($Architecture -eq 'x64')) { throw 'Runtime version/bitness mismatch.' }
$path
