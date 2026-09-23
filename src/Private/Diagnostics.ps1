# Diagnostics deliberately use exception metadata, never exception messages,
# command arguments, source text, target objects, or raw subprocess output.
$script:DiagnosticLogPath = $null
$script:RunDiagnostics = New-Object 'System.Collections.Generic.List[object]'

function New-AssessmentDiagnostic {
    param(
        [string]$Reason,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateSet('Information','Warning','Error')][string]$Level = 'Warning',
        [string]$Phase = 'Check',
        [object]$CheckId = $null,
        [string]$CheckTitle = '',
        [ValidateSet('','ScopeNotEnabled','DomainNotJoined','ActiveDirectoryModuleMissing','UnsupportedPlatform','UnsupportedCheck','PrerequisiteMissing')][string]$SkipReason = '',
        [ValidateSet('','IncludeDomain','IncludeNetwork','IncludeSensitive')][string]$RequiredSwitch = '',
        [string[]]$EnabledSwitches = @()
    )
    $exceptionTypes = @()
    $nativeCode = $null; $hresult = $null; $exitCode = $null; $timeout = $null
    $errorCategory = $null; $source = $null; $line = $null
    if ($ErrorRecord) {
        $errorCategory = [string]$ErrorRecord.CategoryInfo.Category
        $exception = $ErrorRecord.Exception
        for ($depth = 0; $exception -and $depth -lt 8; $depth++) {
            $exceptionTypes += $exception.GetType().FullName
            $hresult = '0x{0:X8}' -f $exception.HResult
            if ($exception -is [ComponentModel.Win32Exception]) { $nativeCode = $exception.NativeErrorCode }
            # Only our numeric metadata is carried across a subprocess boundary.
            if ($exception.Data['StealthPrivesc.ExitCode'] -is [int]) { $exitCode = $exception.Data['StealthPrivesc.ExitCode'] }
            if ($exception.Data['StealthPrivesc.TimeoutSeconds'] -is [int]) { $timeout = $exception.Data['StealthPrivesc.TimeoutSeconds'] }
            $exception = $exception.InnerException
        }
        $invocation = $ErrorRecord.InvocationInfo
        if ($invocation -and $invocation.ScriptName) {
            $root = [IO.Path]::GetFullPath($script:ModuleRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
            $path = [IO.Path]::GetFullPath($invocation.ScriptName)
            if ($path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                $source = 'src/' + $path.Substring($root.Length).Replace('\','/')
                $line = $invocation.ScriptLineNumber
            }
        }
    }
    $types = $exceptionTypes -join ' '
    # Native collectors also report numeric results without throwing exceptions.
    if ($null -eq $nativeCode -and $Reason -match '\(Win32 (\d+)\)') { $nativeCode = [int]$Matches[1] }
    $code = 'CollectionIncomplete'
    $explanation = 'The collector could not obtain all of the requested information. The exact cause is not known.'
    $steps = @('Review the affected resource and technical details below. Retry only the affected check after verifying that the resource is available.', 'If it repeats, share the check ID, diagnostic code, source location and tool/PowerShell versions with the project maintainer.')
    if ($types -match 'UnauthorizedAccessException|SecurityException' -or $errorCategory -eq 'PermissionDenied' -or $nativeCode -in @(5,1314) -or $hresult -in @('0x80070005','0x80041003')) {
        $code = 'AccessDenied'
        $explanation = 'The account running this scan does not have permission to read the requested resource, or a security policy blocked the operation.'
        $steps = @('Verify which account is running PowerShell and whether it should have read access to this resource.', 'If administrative inventory is intended, use an approved elevated PowerShell session. Elevation changes the identity/access being assessed; keep a separate run for the original user.', 'If access is intentionally restricted, retain this result as incomplete coverage; do not loosen permissions just to make the check pass.')
    } elseif ($types -match 'TimeoutException' -or $nativeCode -eq 1460 -or $timeout) {
        $code = 'CommandTimeout'
        $explanation = 'A helper process did not finish within the configured time limit.'
        $steps = @('Check whether the queried service or resource is responding.', 'Retry this check with -CommandTimeoutSeconds 60 (allowed range: 1-300). This setting applies to helper processes, not every collector.')
    } elseif ($types -match 'CommandNotFoundException|DllNotFoundException|TypeLoadException|PlatformNotSupportedException' -or $errorCategory -eq 'NotInstalled' -or $hresult -in @('0x8004100E','0x80041010')) {
        $code = 'DependencyUnavailable'
        $explanation = 'A command, library, or Windows feature required by this check is unavailable in this PowerShell session.'
        $steps = @('Use 64-bit Windows PowerShell 5.1 or PowerShell 7 on a supported Windows version.', 'Use the source location to identify the missing dependency. Verify its installation and module availability with Get-Module -ListAvailable; install or enable it through your normal management process.', 'For domain checks, verify the ActiveDirectory module/RSAT is available. An optional feature that is not installed may legitimately remain unavailable.')
    } elseif ($types -match 'FileNotFoundException|DirectoryNotFoundException|ItemNotFoundException|DriveNotFoundException' -or $nativeCode -in @(2,3)) {
        $code = 'ResourceNotFound'
        $explanation = 'A required file, directory, drive, or other resource could not be found.'
        $steps = @('Check the resource path and confirm the relevant software or feature is installed.', 'Verify custom -SearchRoot, -DriverDatabasePath and -VulnerabilityDatabasePath values if used. Restore missing project files from a trusted checkout.')
    } elseif ($nativeCode -in @(32,33)) {
        $code = 'ResourceBusy'
        $explanation = 'Another process has locked the resource needed by this check.'
        $steps = @('Retry when the application is idle, or close it normally if appropriate. Do not force-close system services or modify the resource.')
    } elseif ($types -match 'WebException|HttpRequestException|SocketException' -or $errorCategory -eq 'ConnectionError' -or $nativeCode -in @(53,64,67,121,1231,1722)) {
        $code = 'ConnectionFailed'
        $explanation = 'A required network or service connection failed.'
        $steps = @('Check network/VPN connectivity, DNS resolution, and the availability of the destination service.', 'Verify applicable proxy/firewall policy and the required -IncludeNetwork or -IncludeDomain scope. If the service rate-limits requests, wait before retrying.')
    } elseif ($types -match 'JsonReaderException|XmlException|FormatException|InvalidDataException' -or $errorCategory -eq 'ParserError') {
        $code = 'InvalidData'
        $explanation = 'The input could not be read in the format this collector expects.'
        $steps = @('Check that the input is complete, readable, and supported by this collector.', 'For reference databases, run tools/Update-ReferenceData.ps1 or select a validated reference file. For application data, use a supported format; keep the original unchanged.')
    } elseif ($null -ne $exitCode) {
        $code = 'CommandFailed'
        $explanation = "A helper process exited unsuccessfully (exit code $exitCode)."
        $steps = @('Use the check and source location to identify the helper. Verify its required feature, permissions, and input are available.', 'If needed, reproduce the read-only query in a local PowerShell session to inspect its own error output. Review that output for secrets before sharing it.')
    } elseif ($Reason -match 'Requires? -(IncludeDomain|IncludeNetwork|IncludeSensitive)|use -(IncludeDomain|IncludeNetwork|IncludeSensitive)') {
        $code = 'ScopeNotEnabled'
        $explanation = 'This part of the assessment was intentionally excluded by the selected scope.'
        $steps = @('If this scope is intended, rerun the affected check with the opt-in switch named above. Otherwise no repair is needed; this area was not assessed.')
    } elseif ($Reason -match 'MaxFileBytes|file.*(?:size|exceed)|decompress.*limit') {
        $code = 'FileSizeLimit'
        $explanation = 'A file or decoded content exceeded a collector size limit.'
        $steps = @('For a MaxFileBytes limit, retry with -MaxFileBytes 2097152 (maximum 10485760). Larger limits increase resource use.', 'Some parser/decompression limits are fixed and cannot be changed with MaxFileBytes; retain those as incomplete coverage.')
    } elseif ($Reason -match 'MaxItems|item limit|finding limit|truncat|enumeration.*limit|item/time budget') {
        $code = 'ItemLimit'
        $explanation = 'The collector stopped at an item limit, so some results were omitted.'
        $steps = @('Retry only the affected check with -MaxItems 2000 (maximum 100000), or narrow applicable file searches with -SearchRoot.', 'Some collectors have additional fixed limits; increasing MaxItems does not remove those limits.')
    } elseif ($Reason -match 'reference data|reference.*(?:missing|invalid)|snapshot') {
        $code = 'ReferenceData'
        $explanation = 'The reference database may be missing, outdated, invalid, or lack rules for this system.'
        $steps = @('Run tools/Update-ReferenceData.ps1 to refresh the reference data, or supply a validated -DriverDatabasePath / -VulnerabilityDatabasePath.', 'Check the database coverage and retrieval date. A missing product rule cannot establish whether the system is patched.')
    } elseif ($Reason -match 'access|permission|inaccessible|Cannot (?:read|enumerate|assess|inspect)|could not be (?:read|queried)') {
        $code = 'ResourceUnavailable'
        $explanation = 'The resource could not be inspected. It may be restricted, busy, absent, or unsupported; this message alone does not establish the cause.'
        $steps = @('Confirm that the resource exists and is available to the account being assessed.', 'Check the required Windows feature and read permissions. Use the technical details, when available, to distinguish a permission failure from an unsupported resource.')
    } elseif ($Reason -match 'unsupported|not supported|not implemented|not decoded|not domain joined|only |not .*validated|no .*included') {
        $code = 'CoverageLimit'
        $explanation = "This environment or data is outside the collector's supported coverage."
        $steps = @('Review the stated coverage limitation. A local configuration change may not resolve it; use a supported environment or another approved assessment method for the missing coverage.')
    }
    if ($Phase -eq 'Selection') {
        $code = 'InvalidSelection'; $explanation = 'The check selection or check catalog could not be loaded.'
        $steps = @('Use -ListChecks without selectors to list valid IDs and categories, then correct -CheckId or -Category.', 'If listing also fails, verify data/checks.json is present and valid in this checkout.')
    } elseif ($Phase -eq 'Export' -or $Phase -eq 'Logging') {
        if ($code -eq 'CollectionIncomplete') { $code = 'OutputFailed'; $explanation = 'Saving output did not complete. This may be a problem with the output location or an internal formatting error; the technical details help distinguish them.' }
        $steps = @('Check that -OutputDirectory is a writable local directory and that the drive has free space.', 'Check for a file occupying the directory path, a disconnected drive, or a report file held open by another program.', 'Choose another writable output directory. If a report object is available, retain it before retrying export.', 'If the directory is writable and the error persists, share the diagnostic code, exception types and source location with the project maintainer.')
    } elseif ($Phase -eq 'Initialization') {
        $steps += 'Verify the src/*.cs files are present and that Windows policy permits Add-Type compilation. Use an approved script execution process if policy blocks the scanner.'
    }
    $verification = $null
    if ($SkipReason) {
        $code = $SkipReason
        switch ($SkipReason) {
            'ScopeNotEnabled' {
                $scopeDescription = switch ($RequiredSwitch) {
                    'IncludeDomain' { 'queries Active Directory or domain resources' }
                    'IncludeNetwork' { 'makes network connections' }
                    'IncludeSensitive' { 'inspects credential or activity exposure, with reported values redacted' }
                    default { 'requires an explicit opt-in' }
                }
                $explanation = "This check did not run because it $scopeDescription and that scope was not enabled."
                $steps = @("Rerun this check with -$RequiredSwitch to enable the required scope.", 'Other requirements, such as a reachable domain or an installed module, may become visible on the next run; address those if reported.')
            }
            'DomainNotJoined' {
                $RequiredSwitch = 'IncludeDomain'
                $explanation = 'This check needs an Active Directory domain, but this computer is not joined to one. Adding a scan switch alone cannot fix this.'
                $steps = @('Run the check from an existing domain-joined Windows computer for the domain you intend to assess.', 'Connect that computer to the corporate network or VPN and use an account that can read the required domain information.', 'Use -IncludeDomain when rerunning. A workgroup-only computer cannot run this domain check; keep it marked as skipped there.')
            }
            'ActiveDirectoryModuleMissing' {
                $RequiredSwitch = 'IncludeDomain'
                $explanation = 'The Windows ActiveDirectory PowerShell module is missing, so the scanner cannot query the domain.'
                $steps = @('Ask your administrator to install or enable the Active Directory PowerShell tools from Windows RSAT on the domain-joined assessment computer.', 'Open a new PowerShell session and run: Get-Module -ListAvailable ActiveDirectory. It should list the module. Then run: Import-Module ActiveDirectory -ErrorAction Stop.', 'Connect to the domain network or VPN, then rerun the check with -IncludeDomain.')
            }
            'UnsupportedPlatform' {
                $explanation = 'This version of Windows does not provide the API required by this check.'
                $steps = @('Run the assessment on a Windows version supported by the project and satisfying the minimum version named in the skip reason.', 'No scan switch can add this API to an older OS. Keep this check marked as skipped on that system.')
            }
            'UnsupportedCheck' {
                $explanation = 'This version of the scanner does not implement this check. Changing permissions or scan switches will not make it run.'
                $steps = @('Check whether a newer project version implements this check, or use another approved assessment method.', 'Keep the unsupported result visible until that coverage is available.')
            }
            default {
                $explanation = 'This check did not run because a prerequisite was not met.'
                $steps = @('Resolve the prerequisite described in the skip reason, then retry this check. If the requirement cannot be met on this computer, retain the skipped result.')
            }
        }
        $verification = 'After rerunning, confirm this check has Status = Completed. Partial means coverage is still incomplete; follow its diagnostics. Error means it ran but failed. Skipped means another prerequisite still needs attention.'
        if ($SkipReason -eq 'UnsupportedCheck') { $verification = 'Confirm that the replacement version or assessment method actually implements and completes this check. Unsupported is not a successful result.' }
    }
    if ($code -eq 'ScopeNotEnabled' -and -not $RequiredSwitch -and $Reason -match '-(IncludeDomain|IncludeNetwork|IncludeSensitive)') { $RequiredSwitch = $Matches[1] }
    $switches = @('IncludeDomain','IncludeNetwork','IncludeSensitive' | Where-Object { $_ -eq $RequiredSwitch -or $_ -in $EnabledSwitches })
    $retry = if ($null -ne $CheckId -and $SkipReason -ne 'UnsupportedCheck') {
        $arguments = @('-CheckId', [string]$CheckId) + @($switches | ForEach-Object { "-$_" }) + @('-Verbose')
        '.\Invoke-StealthPrivesc.ps1 ' + ($arguments -join ' ')
    } else { $null }
    [pscustomobject][ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o'); Level = $Level; Phase = $Phase
        CheckId = $CheckId; CheckTitle = $CheckTitle; Code = $code
        Summary = $Reason; Explanation = $explanation; SuggestedActions = @($steps); RetryCommand = $retry
        SkipReason = $SkipReason; RequiredSwitch = $RequiredSwitch; Verification = $verification
        TechnicalDetails = [pscustomobject]@{
            ExceptionTypes = @($exceptionTypes); ErrorCategory = $errorCategory; HResult = $hresult
            NativeErrorCode = $nativeCode; ExitCode = $exitCode; TimeoutSeconds = $timeout
            Source = $source; Line = $line
        }
    }
}

function Format-AssessmentDiagnostic {
    param([object]$Diagnostic)
    $label = if ($null -ne $Diagnostic.CheckId) { "Check $($Diagnostic.CheckId) ($($Diagnostic.CheckTitle))" } else { $Diagnostic.Phase }
    $outcome = if ($Diagnostic.SkipReason -eq 'UnsupportedCheck') { 'Unsupported' } elseif ($Diagnostic.SkipReason) { 'Skipped' } else { $Diagnostic.Level }
    $lines = @("[$outcome] $label - $($Diagnostic.Code)", $Diagnostic.Summary, "What this means: $($Diagnostic.Explanation)")
    foreach ($action in $Diagnostic.SuggestedActions) { $lines += "Next step: $action" }
    if ($Diagnostic.RetryCommand) { $lines += "Retry selector: $($Diagnostic.RetryCommand) (keep your original scope, paths and output options; apply the suggested limit changes if relevant)." }
    if ($Diagnostic.Verification) { $lines += "Verify: $($Diagnostic.Verification)" }
    $details = $Diagnostic.TechnicalDetails
    $metadata = @(foreach ($name in @('ExceptionTypes','ErrorCategory','HResult','NativeErrorCode','ExitCode','TimeoutSeconds','Source','Line')) {
        if ($null -ne $details.$name -and [string]($details.$name -join ', ')) { "$name=$($details.$name -join ', ')" }
    })
    if ($metadata.Count) { $lines += 'Technical details: ' + ($metadata -join '; ') }
    $lines -join [Environment]::NewLine
}

function Write-DiagnosticLog {
    param([object]$Diagnostic)
    if (-not $script:DiagnosticLogPath) { return }
    try {
        $text = "[$($Diagnostic.TimestampUtc)] " + (Format-AssessmentDiagnostic $Diagnostic) + [Environment]::NewLine + [Environment]::NewLine
        [IO.File]::AppendAllText($script:DiagnosticLogPath, $text, [Text.UTF8Encoding]::new($false))
    } catch {
        $script:DiagnosticLogPath = $null
        $failure = New-AssessmentDiagnostic -Reason 'The troubleshooting log could not be updated. Diagnostics remain in memory and will be included in the final reports if export succeeds.' -ErrorRecord $_ -Level Error -Phase Logging
        $script:RunDiagnostics.Add($failure)
        Write-Warning (Format-AssessmentDiagnostic $failure) -WarningAction Continue
    }
}

function Add-CheckDiagnostic {
    param([string]$Reason, [System.Management.Automation.ErrorRecord]$ErrorRecord, [string]$Level = 'Warning', [string]$SkipReason = '', [string]$RequiredSwitch = '')
    if (-not $script:Current.Contains('Diagnostics')) { $script:Current['Diagnostics'] = New-Object 'System.Collections.Generic.List[object]' }
    $id = if ($script:Current.Contains('Id')) { $script:Current.Id } else { $null }
    $title = if ($script:Current.Contains('Title')) { $script:Current.Title } else { '' }
    $enabledSwitches = @()
    $contextVariable = Get-Variable -Name Context -Scope Script -ErrorAction SilentlyContinue
    if ($contextVariable -and $contextVariable.Value) {
        $enabledSwitches = @('IncludeDomain','IncludeNetwork','IncludeSensitive' | Where-Object { $contextVariable.Value[$_] })
    }
    $diagnostic = New-AssessmentDiagnostic -Reason $Reason -ErrorRecord $ErrorRecord -Level $Level -CheckId $id -CheckTitle $title -SkipReason $SkipReason -RequiredSwitch $RequiredSwitch -EnabledSwitches $enabledSwitches
    $duplicate = @($script:Current.Diagnostics | Where-Object { $_.Summary -eq $Reason -and $_.Code -eq $diagnostic.Code -and $_.TechnicalDetails.Source -eq $diagnostic.TechnicalDetails.Source -and $_.TechnicalDetails.Line -eq $diagnostic.TechnicalDetails.Line })
    if ($duplicate.Count) { return }
    $script:Current.Diagnostics.Add($diagnostic)
    Write-DiagnosticLog $diagnostic
    Write-Verbose (Format-AssessmentDiagnostic $diagnostic)
}

function Write-CheckDiagnostics {
    param([object]$Check)
    foreach ($diagnostic in $Check.Diagnostics | Where-Object { $_.SkipReason }) { Write-Warning (Format-AssessmentDiagnostic $diagnostic) -WarningAction Continue }
    $issues = @($Check.Diagnostics | Where-Object { $_.Level -ne 'Information' -and -not $_.SkipReason })
    foreach ($diagnostic in $issues | Select-Object -First 3) { Write-Warning (Format-AssessmentDiagnostic $diagnostic) -WarningAction Continue }
    if ($issues.Count -gt 3) {
        Write-Warning "Check $($Check.Id) has $($issues.Count - 3) additional diagnostics. See the saved reports/log, inspect Checks.Diagnostics with -PassThru, or use -Verbose for every diagnostic." -WarningAction Continue
    }
}

function Initialize-AssessmentOutput {
    param([string]$Directory)
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory)
    [void][IO.Directory]::CreateDirectory($path)
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6)
    $paths = @{ Json = (Join-Path $path "assessment-$stamp.json"); Html = (Join-Path $path "assessment-$stamp.html"); Log = (Join-Path $path "assessment-$stamp.log") }
    [IO.File]::WriteAllText($paths.Log, "StealthPrivesc troubleshooting log`r`nStarted UTC: $([DateTime]::UtcNow.ToString('o'))`r`nPowerShell: $($PSVersionTable.PSVersion); 64-bit process: $([Environment]::Is64BitProcess)`r`nRaw exception messages, command arguments and subprocess output are omitted to protect sensitive data.`r`n`r`n", [Text.UTF8Encoding]::new($false))
    $script:DiagnosticLogPath = $paths.Log
    $paths
}

function ConvertTo-DiagnosticHtml {
    param([object[]]$Diagnostics)
    foreach ($diagnostic in $Diagnostics) {
        $encode = [Net.WebUtility]
        '<section class="diagnostic"><h3>' + $encode::HtmlEncode("$($diagnostic.Level): $($diagnostic.Code)") + '</h3><p>' + $encode::HtmlEncode($diagnostic.Summary) + '</p><p><strong>What this means:</strong> ' + $encode::HtmlEncode($diagnostic.Explanation) + '</p><p><strong>Suggested next steps</strong></p><ul>'
        foreach ($action in $diagnostic.SuggestedActions) { '<li>' + $encode::HtmlEncode($action) + '</li>' }
        '</ul>'
        if ($diagnostic.RetryCommand) { '<p><strong>Retry selector:</strong> <code>' + $encode::HtmlEncode($diagnostic.RetryCommand) + '</code> (keep your original scope, paths and output options; apply suggested limit changes if relevant).</p>' }
        if ($diagnostic.Verification) { '<p><strong>Verify:</strong> ' + $encode::HtmlEncode($diagnostic.Verification) + '</p>' }
        '<details><summary>Technical details</summary><pre>' + $encode::HtmlEncode(($diagnostic.TechnicalDetails | ConvertTo-Json -Depth 4)) + '</pre></details></section>'
    }
}

function Get-SkippedCheckSummary {
    param([object[]]$Checks)
    foreach ($check in $Checks | Where-Object Status -eq 'Skipped') {
        $diagnostic = $check.Diagnostics | Where-Object { $_.SkipReason } | Select-Object -Last 1
        if ($diagnostic) {
            [pscustomobject]@{
                CheckId=$check.Id; Title=$check.Title; Reason=$diagnostic.Summary; ReasonCode=$diagnostic.Code
                Explanation=$diagnostic.Explanation; SuggestedActions=$diagnostic.SuggestedActions
                RetryCommand=$diagnostic.RetryCommand; Verification=$diagnostic.Verification
            }
        }
    }
}
