Set-StrictMode -Version 2.0
$script:ModuleRoot = $PSScriptRoot
foreach ($file in @(Get-ChildItem (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }
foreach ($file in @(Get-ChildItem (Join-Path $PSScriptRoot 'Checks') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }

function Get-StealthPrivescCheck {
    [CmdletBinding()]
    param([int[]]$CheckId, [string[]]$Category)
    $catalog = @(Get-Content (Join-Path $script:ModuleRoot '../data/checks.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop | ForEach-Object { $_ })
    $allCategories = @($catalog | Select-Object -ExpandProperty Category -Unique)
    if ($CheckId) {
        $unknown = @($CheckId | Where-Object { $_ -notin $catalog.Id })
        if ($unknown.Count) { throw "Unknown check ID(s): $($unknown -join ', ')" }
        $catalog = @($catalog | Where-Object { $_.Id -in $CheckId })
    }
    if ($Category) {
        $unknown = @($Category | Where-Object { $_ -notin $allCategories })
        if ($unknown.Count) { throw "Unknown category: $($unknown -join ', '). Valid: $($allCategories -join ', ')" }
        $catalog = @($catalog | Where-Object { $_.Category -in $Category })
    }
    $catalog
}

function Invoke-StealthPrivesc {
    [CmdletBinding()]
    param(
        [int[]]$CheckId, [string[]]$Category, [switch]$ListChecks,
        [switch]$IncludeNetwork, [switch]$IncludeDomain, [switch]$IncludeSensitive,
        [ValidateRange(10,100000)][int]$MaxItems = 500,
        [ValidateRange(1024,10485760)][int]$MaxFileBytes = 1048576,
        [ValidateRange(1,300)][int]$CommandTimeoutSeconds = 15,
        [string[]]$SearchRoot, [string]$OutputDirectory, [switch]$PassThru,
        [string]$DriverDatabasePath=(Join-Path $script:ModuleRoot '../data/reference/drivers.json'),
        [string]$VulnerabilityDatabasePath=(Join-Path $script:ModuleRoot '../data/reference/windows-updates.json')
    )
    $ErrorActionPreference = 'Stop'
    $script:DiagnosticLogPath = $null
    $script:RunDiagnostics = New-Object 'System.Collections.Generic.List[object]'
    $identity = $null; $paths = $null; $failure = $null; $phase = 'Selection'
    $report = [ordered]@{
        SchemaVersion = '1.4'; ToolVersion = '0.2.0'; StartedUtc = [DateTime]::UtcNow.ToString('o')
        RunStatus = 'Running'; Computer = $env:COMPUTERNAME; User = $null; UserSid = $null
        Elevated = $null; ProcessArchitecture = $(if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' })
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Scope = [ordered]@{ Network = [bool]$IncludeNetwork; Domain = [bool]$IncludeDomain; Sensitive = [bool]$IncludeSensitive; MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes; CommandTimeoutSeconds = $CommandTimeoutSeconds }
        Notice = 'Evidence is redacted. Findings are candidates unless explicitly stated; access tests use the current token. Missing evidence is not a clean bill of health.'
        Checks = New-Object 'System.Collections.Generic.List[object]'
        Diagnostics = $script:RunDiagnostics
    }
    try {
        $catalog = @(Get-StealthPrivescCheck -CheckId $CheckId -Category $Category)
        if ($ListChecks) { return $catalog }
        if ($OutputDirectory) {
            $phase = 'Logging'
            $paths = Initialize-AssessmentOutput -Directory $OutputDirectory
            Write-Host "Troubleshooting log: $($paths.Log)"
        }
        $phase = 'Initialization'
        if ($env:OS -ne 'Windows_NT') { throw [PlatformNotSupportedException]::new('Scanning requires Windows. -ListChecks can be used on other platforms.') }
        foreach ($nativeType in @('Native','NativeInspection','NativeObjects')) {
            if (-not ("StealthPrivesc.$nativeType" -as [type])) {
                Write-Verbose "Loading native support: $nativeType"
                Add-Type -Path (Join-Path $script:ModuleRoot "$nativeType.cs") -ErrorAction Stop
            }
        }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $script:Context = @{
            MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes; CommandTimeoutSeconds = $CommandTimeoutSeconds
            IncludeNetwork = [bool]$IncludeNetwork; IncludeDomain = [bool]$IncludeDomain; IncludeSensitive = [bool]$IncludeSensitive
            SearchRoot = @($SearchRoot); Cache = @{}; Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            DriverDatabasePath=$DriverDatabasePath;VulnerabilityDatabasePath=$VulnerabilityDatabasePath
        }
        $report.User = $identity.Name; $report.UserSid = $identity.User.Value; $report.Elevated = $script:Context.Elevated
        $phase = 'Assessment'
        foreach ($check in $catalog) {
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $script:Current = [ordered]@{ Id = $check.Id; Title = $check.Title; Category = $check.Category; Coverage = $check.Coverage; Status = 'Completed'; Limitations = New-Object 'System.Collections.Generic.List[string]'; Findings = New-Object 'System.Collections.Generic.List[object]'; Diagnostics = New-Object 'System.Collections.Generic.List[object]'; DurationMs = 0 }
            $script:Current.Verification = New-CheckVerification -Id $check.Id
            $script:RegistryVisited = 0
            if ($check.Coverage -ne 'Implemented') { $script:Current.Status = 'Partial' }
            if ($check.Limitation) { $script:Current.Limitations.Add($check.Limitation) }
            Write-Verbose "Starting check $($check.Id): $($check.Title)"
            Write-Progress -Activity 'Windows exposure assessment' -Status "$($check.Id): $($check.Title)" -PercentComplete (($report.Checks.Count / [Math]::Max(1,$catalog.Count)) * 100)
            try {
                if ($check.Coverage -eq 'Unsupported') {
                    $script:Current.Status = 'Unsupported'
                    Add-CheckDiagnostic -Reason 'This check is not implemented in this version of the scanner.' -SkipReason UnsupportedCheck
                }
                elseif ($check.Scope -eq 'Domain' -and -not $IncludeDomain) { Set-CheckSkipped 'Requires -IncludeDomain (queries the joined domain).' -SkipReason ScopeNotEnabled -RequiredSwitch IncludeDomain }
                elseif ($check.Scope -eq 'Network' -and -not $IncludeNetwork) { Set-CheckSkipped 'Requires -IncludeNetwork.' -SkipReason ScopeNotEnabled -RequiredSwitch IncludeNetwork }
                elseif ($check.Scope -eq 'Sensitive' -and -not $IncludeSensitive) { Set-CheckSkipped 'Requires -IncludeSensitive; values remain redacted.' -SkipReason ScopeNotEnabled -RequiredSwitch IncludeSensitive }
                else { Invoke-Check -Id $check.Id }
            } catch {
                $script:Current.Status = 'Error'
                $reason = 'This check could not finish. Any findings already collected are retained; other checks will continue.'
                $script:Current.Limitations.Add($reason)
                Add-CheckDiagnostic -Reason $reason -ErrorRecord $_ -Level Error
            }
            $script:Current.DurationMs = $timer.ElapsedMilliseconds
            $report.Checks.Add([pscustomobject]$script:Current)
            Write-CheckDiagnostics -Check ([pscustomobject]$script:Current)
            Write-Verbose "Finished check $($check.Id): $($script:Current.Status), $($script:Current.Findings.Count) findings, $($script:Current.DurationMs) ms."
        }
        $report.RunStatus = 'Completed'
    } catch {
        $failure = New-AssessmentDiagnostic -Reason "The assessment could not complete the $phase stage." -ErrorRecord $_ -Level Error -Phase $phase
        $script:RunDiagnostics.Add($failure)
        Write-DiagnosticLog $failure
        Write-Warning (Format-AssessmentDiagnostic $failure) -WarningAction Continue
        $report.RunStatus = 'Failed'
    } finally {
        if ($identity) { $identity.Dispose() }
        Write-Progress -Activity 'Windows exposure assessment' -Completed
    }
    try {
        $report.AttackPathAnalysis = Get-StealthPrivescAttackPathAnalysis -Report $report
    } catch {
        # Correlation failure must not discard collected findings or prevent export.
        $diagnostic = New-AssessmentDiagnostic -Reason 'Post-scan attack-path analysis failed. Original findings are retained; review them directly.' -ErrorRecord $_ -Level Warning -Phase Analysis
        $script:RunDiagnostics.Add($diagnostic)
        Write-DiagnosticLog $diagnostic
        Write-Warning (Format-AssessmentDiagnostic $diagnostic) -WarningAction Continue
        $report.AttackPathAnalysis = [pscustomobject]@{EngineVersion='1.0';Status='Error';Paths=@();TotalCandidates=0;OmittedPaths=0;RuleCoverage=@();Limitations=@('Correlation failed; no conclusion can be drawn from the empty path list. Original findings remain available.')}
    }
    $report.FinishedUtc = [DateTime]::UtcNow.ToString('o')
    $report.Summary = [ordered]@{}
    foreach ($status in @('Completed','Partial','Skipped','Unsupported','Error')) { $report.Summary[$status] = @($report.Checks | Where-Object Status -eq $status).Count }
    $report.SkippedChecks = @(Get-SkippedCheckSummary -Checks @($report.Checks | ForEach-Object { $_ }))
    if ($paths) {
        try { Export-Assessment -Report $report -Directory $OutputDirectory -Paths $paths }
        catch {
            $failure = New-AssessmentDiagnostic -Reason 'The assessment report could not be completely saved. A JSON report or troubleshooting log may already exist in the output directory.' -ErrorRecord $_ -Level Error -Phase Export
            $script:RunDiagnostics.Add($failure)
            Write-DiagnosticLog $failure
            Write-Warning (Format-AssessmentDiagnostic $failure) -WarningAction Continue
            $report.RunStatus = 'Failed'
        }
    }
    $script:DiagnosticLogPath = $null
    if ($failure) {
        # No inner exception: PowerShell may otherwise print raw provider messages.
        $exception = [InvalidOperationException]::new((Format-AssessmentDiagnostic $failure))
        $exception.Data['AssessmentReport'] = [pscustomobject]$report
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($exception, 'StealthPrivesc.RunFailed', [System.Management.Automation.ErrorCategory]::OperationStopped, $null))
    }
    Write-Host "Skipped checks: $($report.Summary.Skipped) of $($report.Checks.Count) selected. Unsupported: $($report.Summary.Unsupported). Review Partial and Error results for checks that ran incompletely."
    Write-Host "Attack path candidates: $($report.AttackPathAnalysis.Paths.Count). Analysis: $($report.AttackPathAnalysis.Status). See supporting evidence and unresolved prerequisites in the report."
    if ($PassThru) { return [pscustomobject]$report }
    $report.Checks | Select-Object Id, Category, Status, @{n='Findings';e={$_.Findings.Count}}, Title | Format-Table -AutoSize
    Write-Host ('Completed: {0}; Partial: {1}; Skipped: {2}; Unsupported: {3}; Errors: {4}' -f $report.Summary.Completed,$report.Summary.Partial,$report.Summary.Skipped,$report.Summary.Unsupported,$report.Summary.Error)
}
Export-ModuleMember -Function Invoke-StealthPrivesc, Get-StealthPrivescCheck, Get-StealthPrivescAttackPathAnalysis
