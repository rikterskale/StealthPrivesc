#requires -Version 5.1
[CmdletBinding()]
param(
    [int[]]$CheckId,
    [string[]]$Category,
    [switch]$ListChecks,
    [switch]$IncludeNetwork,
    [switch]$IncludeDomain,
    [switch]$IncludeSensitive,
    [ValidateRange(10,100000)][int]$MaxItems = 500,
    [ValidateRange(1024,10485760)][int]$MaxFileBytes = 1048576,
    [ValidateRange(1,300)][int]$CommandTimeoutSeconds = 15,
    [string[]]$SearchRoot,
    [string]$DriverDatabasePath,
    [string]$VulnerabilityDatabasePath,
    [string]$OutputDirectory,
    [switch]$PassThru
)
Import-Module (Join-Path $PSScriptRoot 'src/StealthPrivesc.psd1') -Force -ErrorAction Stop
$options = @{}
foreach ($key in $PSBoundParameters.Keys) { $options[$key] = $PSBoundParameters[$key] }
Invoke-StealthPrivesc @options
