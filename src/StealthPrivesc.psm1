Set-StrictMode -Version 2.0
$script:ModuleRoot = $PSScriptRoot
foreach ($file in @(Get-ChildItem (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }
foreach ($file in @(Get-ChildItem (Join-Path $PSScriptRoot 'Checks') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }

function Get-StealthPrivescCheck {
    [CmdletBinding()]
    param([int[]]$CheckId, [string[]]$Category)
    $catalog = @(Get-Content (Join-Path $script:ModuleRoot '../data/checks.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop | ForEach-Object { $_ })
    $allCategories = @($catalog | Select-Object -ExpandProperty Category -Unique)
    if ($null -ne $CheckId -and $CheckId.Count -gt 0) {
        $unknown = @($CheckId | Where-Object { $_ -notin $catalog.Id })
        if ($unknown.Count) { throw "Unknown check ID(s): $($unknown -join ', ')" }
        $catalog = @($catalog | Where-Object { $_.Id -in $CheckId })
    }
    if ($null -ne $Category -and $Category.Count -gt 0) {
        $unknown = @($Category | Where-Object { $_ -notin $allCategories })
        if ($unknown.Count) { throw "Unknown category: $($unknown -join ', '). Valid: $($allCategories -join ', ')" }
        $catalog = @($catalog | Where-Object { $_.Category -in $Category })
    }
    $catalog
}

function Invoke-StealthPrivesc {
    [CmdletBinding()]
    param(
        [int[]]$CheckId, [string[]]$Category, [switch]$ListChecks, [switch]$Plan,
        [switch]$IncludeNetwork, [switch]$IncludeDomain, [switch]$IncludeSensitive,
        [ValidateRange(10,100000)][int]$MaxItems = 500,
        [ValidateRange(1024,10485760)][int]$MaxFileBytes = 1048576,
        [ValidateRange(1,300)][int]$CommandTimeoutSeconds = 15,
        [ValidateRange(1,3600)][int]$CollectorTimeoutSeconds = 60,
        [ValidateRange(1024,8388608)][int]$MaxCollectorOutputCharacters = 8388608,
        [string]$NativeAssemblyDirectory,
        [string[]]$SearchRoot, [string]$OutputDirectory, [switch]$PassThru,
        [string]$DriverDatabasePath=(Join-Path $script:ModuleRoot '../data/reference/drivers.json'),
        [string]$VulnerabilityDatabasePath=(Join-Path $script:ModuleRoot '../data/reference/windows-updates.json')
    )
    $ErrorActionPreference = 'Stop'
    $script:DiagnosticLogPath = $null
    $script:RunDiagnostics = New-Object 'System.Collections.Generic.List[object]'
    $script:Current = $null
    Initialize-AssessmentFootprint
    $identity = $null; $paths = $null; $failure = $null; $phase = 'Selection'
    $report = [ordered]@{
        SchemaVersion = '1.5'; ToolVersion = '0.2.1'; StartedUtc = [DateTime]::UtcNow.ToString('o')
        RunStatus = 'Running'; Computer = $env:COMPUTERNAME; User = $null; UserSid = $null
        Elevated = $null; ProcessArchitecture = $(if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' })
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OperatingSystemArchitecture = $(if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' })
        CollectionView = $(if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'WOW64: registry and filesystem redirection apply; use x64 PowerShell for native system coverage.' } else { 'Native process registry and filesystem view.' })
        Scope = [ordered]@{ Network = [bool]$IncludeNetwork; Domain = [bool]$IncludeDomain; Sensitive = [bool]$IncludeSensitive; MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes; CommandTimeoutSeconds = $CommandTimeoutSeconds; CollectorTimeoutSeconds=$CollectorTimeoutSeconds; MaxCollectorOutputCharacters=$MaxCollectorOutputCharacters }
        Notice = 'Evidence is redacted. Findings are candidates unless explicitly stated; access tests use the current token. Missing evidence is not a clean bill of health.'
        Checks = New-Object 'System.Collections.Generic.List[object]'
        Diagnostics = $script:RunDiagnostics
    }
    try {
        $catalog = @(Get-StealthPrivescCheck -CheckId $CheckId -Category $Category)
        if ($ListChecks) { return $catalog }
        $assessmentPlan = Get-AssessmentPlan -CheckId $CheckId -Category $Category -IncludeNetwork:$IncludeNetwork -IncludeDomain:$IncludeDomain -IncludeSensitive:$IncludeSensitive
        if ($Plan) { return $assessmentPlan }
        $report.AssessmentPlan = $assessmentPlan
        if ($OutputDirectory) {
            $phase = 'Logging'
            $paths = Initialize-AssessmentOutput -Directory $OutputDirectory
            Write-Host "Troubleshooting log: $($paths.Log)"
        }
        $phase = 'Initialization'
        if ($env:OS -ne 'Windows_NT') { throw [PlatformNotSupportedException]::new('Scanning requires Windows. -ListChecks can be used on other platforms.') }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $script:Context = @{
            MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes; CommandTimeoutSeconds = $CommandTimeoutSeconds
            CollectorTimeoutSeconds=$CollectorTimeoutSeconds; MaxCollectorOutputCharacters=$MaxCollectorOutputCharacters
            NativeAssemblyDirectory=$NativeAssemblyDirectory; CheckPlans=@{}
            IncludeNetwork = [bool]$IncludeNetwork; IncludeDomain = [bool]$IncludeDomain; IncludeSensitive = [bool]$IncludeSensitive
            SearchRoot = @($SearchRoot); Cache = @{}; Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            DriverDatabasePath=$DriverDatabasePath;VulnerabilityDatabasePath=$VulnerabilityDatabasePath
        }
        foreach ($plannedCheck in $assessmentPlan.Checks) { $script:Context.CheckPlans[[int]$plannedCheck.Id] = $plannedCheck }
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
                else { Invoke-BudgetedCollector -Collector { Invoke-Check -Id $check.Id } -TimeoutSeconds $CollectorTimeoutSeconds -MaximumOutputCharacters $MaxCollectorOutputCharacters }
            } catch {
                $budgetFailure = Test-CollectorBudgetException $_.Exception
                $script:Current.Status = if ($budgetFailure) { 'Partial' } else { 'Error' }
                $reason = if ($budgetFailure) { 'This check reached a collection time, output or read budget. Collected findings are retained; review the configured limits.' } else { 'This check could not finish. Any findings already collected are retained; other checks will continue.' }
                $script:Current.Limitations.Add($reason)
                Add-CheckDiagnostic -Reason $reason -ErrorRecord $_ -Level $(if ($budgetFailure) { 'Warning' } else { 'Error' })
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
        $report.AttackPathAnalysis = [pscustomobject]@{EngineVersion='1.1';Status='Error';Paths=@();TotalCandidates=0;OmittedPaths=0;RuleCoverage=@();Limitations=@('Correlation failed; no conclusion can be drawn from the empty path list. Original findings remain available.')}
    }
    $report.FinishedUtc = [DateTime]::UtcNow.ToString('o')
    $report.Summary = [ordered]@{}
    foreach ($status in @('Completed','Partial','Skipped','Unsupported','Error')) { $report.Summary[$status] = @($report.Checks | Where-Object Status -eq $status).Count }
    $report.SkippedChecks = @(Get-SkippedCheckSummary -Checks @($report.Checks | ForEach-Object { $_ }))
    $script:Current = $null
    $report.Footprint = Measure-AssessmentFootprint
    if ($paths) {
        try { Export-Assessment -Report $report -Directory $OutputDirectory -Paths $paths }
        catch {
            $failure = New-AssessmentDiagnostic -Reason 'The assessment report could not be completely saved. A JSON report or troubleshooting log may already exist in the output directory.' -ErrorRecord $_ -Level Error -Phase Export
            $script:RunDiagnostics.Add($failure)
            Write-DiagnosticLog $failure
            Write-Warning (Format-AssessmentDiagnostic $failure) -WarningAction Continue
            $report.RunStatus = 'Failed'
            # HTML may fail after JSON was saved. Persist the final failure state
            # without trying the failing HTML renderer again.
            try { Save-AssessmentJson -Report $report -Path $paths.Json }
            catch {
                $recovery = New-AssessmentDiagnostic -Reason 'The failed report could not be saved to JSON. Existing report files may predate this export failure; retain AssessmentReport from the terminating exception.' -ErrorRecord $_ -Level Error -Phase Export
                $script:RunDiagnostics.Add($recovery)
                Write-DiagnosticLog $recovery
                Write-Warning (Format-AssessmentDiagnostic $recovery) -WarningAction Continue
            }
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
Export-ModuleMember -Function Invoke-StealthPrivesc, Get-StealthPrivescCheck, Get-StealthPrivescAttackPathAnalysis, Get-AssessmentPlan, Measure-AssessmentFootprint
