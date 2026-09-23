#requires -Version 5.1
<#
.SYNOPSIS
Runs all checks or a selected subset of the StealthPrivesc assessment.

.DESCRIPTION
With no -CheckId or -Category selector, runs the full catalog. -Category accepts
one or more catalog categories and runs their combined checks. -CheckId accepts
one or more numeric IDs. When both are provided, a check must match both
selectors. Use -ListChecks to list the checks selected by the same selectors.

Some checks are gated by opt-in switches. Domain checks may need -IncludeDomain,
network checks may need -IncludeNetwork, and sensitive checks may need
-IncludeSensitive. Without the required switch, those checks are reported as
skipped rather than silently omitted.

.PARAMETER CheckId
Run only the specified check IDs. See -ListChecks for IDs and descriptions.

.PARAMETER Category
Run checks from the specified catalog categories. Valid values are
AccessControl, CredentialExposure, DomainCloud, Hardening, Identity, Inventory,
Services, SystemRisk, and TasksStartup. Multiple values are combined.

.PARAMETER ListChecks
List matching checks without running them. Can be combined with -Category and
-CheckId to inspect a proposed selection.

.PARAMETER IncludeNetwork
Enable checks that make network connections, including external metadata or
advisory queries.

.PARAMETER IncludeDomain
Enable checks that query domain resources and directory services.

.PARAMETER IncludeSensitive
Enable checks that inspect credential or browser/activity exposure. Reported
values remain redacted.

.PARAMETER OutputDirectory
Save timestamped JSON and HTML reports and a troubleshooting log. The log is
updated during the scan and includes explanations, suggested fixes and safe
technical details. Use -Verbose to also display all diagnostics and check timing.

.PARAMETER PassThru
Return the report object, including Checks.Diagnostics and run-level Diagnostics.
Warnings are written separately from the returned object.

.EXAMPLE
.\Invoke-StealthPrivesc.ps1 -Category Identity
Runs the 10 identity checks.

.EXAMPLE
.\Invoke-StealthPrivesc.ps1 -Category Services,TasksStartup
Runs checks from both categories.

.EXAMPLE
.\Invoke-StealthPrivesc.ps1 -Category DomainCloud -IncludeDomain
Runs domain/cloud checks and enables domain-scoped checks. Network-scoped checks
still require -IncludeNetwork.

.EXAMPLE
.\Invoke-StealthPrivesc.ps1 -CheckId 12,13,16 -ListChecks
Lists only checks 12, 13, and 16 without running them.

.EXAMPLE
.\Invoke-StealthPrivesc.ps1 -Category Services -CheckId 12,13,16
Runs only the specified IDs that are also in the Services category.

.LINK
README.md
#>
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
try {
    Import-Module (Join-Path $PSScriptRoot 'src/StealthPrivesc.psd1') -Force -ErrorAction Stop
} catch {
    $message = "StealthPrivesc could not load its module ($($_.Exception.GetType().Name)). Verify that src/StealthPrivesc.psd1 and all src/Private and src/Checks files are present and readable. Use PowerShell 5.1 or later and your approved script execution process. No scan or report was created."
    $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($message), 'StealthPrivesc.ModuleLoadFailed', [System.Management.Automation.ErrorCategory]::ResourceUnavailable, $null))
}
$options = @{}
foreach ($key in $PSBoundParameters.Keys) { $options[$key] = $PSBoundParameters[$key] }
Invoke-StealthPrivesc @options
