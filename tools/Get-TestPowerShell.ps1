#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('x86','x64')][string]$Architecture='x86',
    [string]$DestinationDirectory=(Join-Path $PSScriptRoot '../TestResults/runtimes')
)
$ErrorActionPreference='Stop'
# Portable test dependency, pinned to the official release and its SHA256.
# https://github.com/PowerShell/PowerShell/releases/tag/v7.6.5
$version='7.6.5'
$hashes=@{x86='6444ECB222A6B51C8D10FFE9BDA99B83EAEEFE90160DE90DEEA6B638914C4A25';x64='32EB8F6CDCE08F86E987D625A2733E54AC3E289AE7E1621B14C0B5BCEC2434EA'}
$root=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationDirectory)
[void][IO.Directory]::CreateDirectory($root)
$name="PowerShell-$version-win-$Architecture.zip"
$archive=Join-Path $root $name
if(-not(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/PowerShell/PowerShell/releases/download/v$version/$name" -OutFile $archive -TimeoutSec 120
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $hashes[$Architecture]) { throw 'PowerShell archive checksum does not match the pinned official release.' }
$directory=Join-Path $root "PowerShell-$version-$Architecture"
if(-not(Test-Path -LiteralPath (Join-Path $directory 'pwsh.exe'))) {
    Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
}
Join-Path $directory 'pwsh.exe'
