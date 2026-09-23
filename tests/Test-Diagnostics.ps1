#requires -Version 5.1
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'NOT RUN: Test-Diagnostics requires Windows to exercise the scanner. Run tools/Test-Project.ps1 on 64-bit Windows with PowerShell 5.1 and 7. This suite did not pass.'
    exit 2
}
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
& (Get-Module StealthPrivesc) {
    $script:DiagnosticAssertions = 0
    function Assert-Diagnostic([bool]$Value, [string]$Message) {
        if (-not $Value) { throw "FAIL: $Message" }
        $script:DiagnosticAssertions++
    }
    function Reset-DiagnosticCheck([int]$Id = 1) {
        $script:Current = [ordered]@{ Id=$Id; Title='Fixture'; Status='Completed'; Findings=New-Object 'System.Collections.Generic.List[object]'; Limitations=New-Object 'System.Collections.Generic.List[string]' }
    }
    function Invoke-DiagnosticTestProcess([string]$Arguments) {
        # Use process streams so nested Windows PowerShell does not interleave
        # serialized host/information records with this suite's own output.
        $process = New-Object Diagnostics.Process
        $process.StartInfo = New-Object Diagnostics.ProcessStartInfo
        $process.StartInfo.FileName = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $process.StartInfo.Arguments = $Arguments
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        try {
            [void]$process.Start()
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Test fixture subprocess timed out.' }
            [pscustomobject]@{ ExitCode=$process.ExitCode; Output=$stdout.GetAwaiter().GetResult(); ErrorOutput=$stderr.GetAwaiter().GetResult() }
        } finally { $process.Dispose() }
    }
    $script:Context = @{ Cache=@{}; MaxItems=10; MaxFileBytes=1024; CommandTimeoutSeconds=1 }
    $script:DiagnosticLogPath = $null
    $canary = 'NEVER_DISCLOSE_DIAGNOSTIC_SECRET_7391'
    $record = [System.Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new($canary), $canary, [System.Management.Automation.ErrorCategory]::PermissionDenied, $canary)
    $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($canary)
    $denied = New-AssessmentDiagnostic -Reason 'Fixture resource could not be read.' -ErrorRecord $record -CheckId 1
    Assert-Diagnostic ($denied.Code -eq 'AccessDenied' -and $denied.SuggestedActions.Count -gt 1) 'Access errors have actionable permission guidance.'
    Assert-Diagnostic (($denied | ConvertTo-Json -Depth 8) -notmatch $canary) 'Raw messages, IDs, details and targets must not enter diagnostics.'
    Assert-Diagnostic ((Format-AssessmentDiagnostic $denied) -notmatch $canary) 'Console/log formatting must not disclose exception secrets.'
    Assert-Diagnostic ($denied.RetryCommand -match '-CheckId 1 -Verbose') 'Diagnostics identify how to retry the affected check.'

    try { throw [InvalidOperationException]::new($canary, [ComponentModel.Win32Exception]::new(5, $canary)) }
    catch { $wrapped = New-AssessmentDiagnostic -Reason 'Native fixture failed.' -ErrorRecord $_ }
    Assert-Diagnostic ($wrapped.Code -eq 'AccessDenied' -and $wrapped.TechnicalDetails.NativeErrorCode -eq 5) 'Wrapped native errors preserve their numeric root cause.'
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'AccessCheck failed (Win32 5).').Code -eq 'AccessDenied') 'Nonthrowing native errors also receive guidance.'
    foreach ($fixture in @(
        @{ Exception=[System.Management.Automation.CommandNotFoundException]::new($canary); Expected='DependencyUnavailable' },
        @{ Exception=[IO.FileNotFoundException]::new($canary); Expected='ResourceNotFound' },
        @{ Exception=[FormatException]::new($canary); Expected='InvalidData' },
        @{ Exception=[Net.WebException]::new($canary); Expected='ConnectionFailed' },
        @{ Exception=[ComponentModel.Win32Exception]::new(32, $canary); Expected='ResourceBusy' }
    )) {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($fixture.Exception, $canary, [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        $diagnostic = New-AssessmentDiagnostic -Reason 'Fixture failed.' -ErrorRecord $errorRecord
        Assert-Diagnostic ($diagnostic.Code -eq $fixture.Expected) "Classify $($fixture.Expected)."
    }
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'Finding limit reached; results are truncated.').Code -eq 'ItemLimit') 'Item limits suggest bounded reruns.'
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'File exceeds MaxFileBytes.').Code -eq 'FileSizeLimit') 'File-size limits have separate guidance.'
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'Requires -IncludeDomain.').Code -eq 'ScopeNotEnabled') 'Opt-in exclusions are not permission failures.'
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'Online package advisory lookup requires -IncludeNetwork.' -CheckId 58).RetryCommand -match '-IncludeNetwork') 'Partial scope omissions also get a selector with the missing opt-in.'
    Assert-Diagnostic ((New-AssessmentDiagnostic -Reason 'Event log inaccessible or no matching events.').Code -eq 'ResourceUnavailable') 'Ambiguous limitations do not claim a certain root cause.'

    Reset-DiagnosticCheck
    Get-Cached 'fixture' { Set-CheckPartial 'Fixture resource could not be read.' -ErrorRecord $record; 42 } | Out-Null
    Set-CheckPartial 'Fixture resource could not be read.' -ErrorRecord $record
    Assert-Diagnostic ($script:Current.Diagnostics.Count -eq 1) 'Repeated diagnoses are deduplicated.'
    Reset-DiagnosticCheck 2
    Get-Cached 'fixture' { throw 'Cache should be reused.' } | Out-Null
    Assert-Diagnostic ($script:Current.Status -eq 'Partial' -and $script:Current.Diagnostics[0].Code -eq 'AccessDenied') 'Cached inventory replays technical diagnostics.'
    Assert-Diagnostic ($script:Current.Diagnostics[0].CheckId -eq 2 -and $script:Current.Diagnostics[0].RetryCommand -match '-CheckId 2 ') 'Cached diagnostics refer to the current check.'

    $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $command = "[Console]::Error.WriteLine('$canary'); exit 7"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $script:Context.CommandTimeoutSeconds = 15
    $helper = $null
    try { Invoke-ReadOnlyCommand $hostPath "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded" | Out-Null }
    catch { $helper = New-AssessmentDiagnostic -Reason 'Helper fixture failed.' -ErrorRecord $_ }
    Assert-Diagnostic ($helper -and $helper.Code -eq 'CommandFailed' -and $helper.TechnicalDetails.ExitCode -eq 7) 'Real subprocess failures preserve the exit code.'
    Assert-Diagnostic (($helper | ConvertTo-Json -Depth 8) -notmatch $canary) 'Subprocess stderr is not leaked.'
    Assert-Diagnostic ($helper.TechnicalDetails.Source -eq 'src/Private/Core.ps1' -and $helper.TechnicalDetails.Line -gt 0) 'Source locations contain file and line, without source text.'
    $script:Context.CommandTimeoutSeconds = 1
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 10'))
    $timedOut = $null
    try { Invoke-ReadOnlyCommand $hostPath "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded" | Out-Null }
    catch { $timedOut = New-AssessmentDiagnostic -Reason 'Helper fixture timed out.' -ErrorRecord $_ }
    Assert-Diagnostic ($timedOut -and $timedOut.Code -eq 'CommandTimeout' -and $timedOut.TechnicalDetails.TimeoutSeconds -eq 1) 'Real helper timeouts retain the configured limit.'

    $testRoot = Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-diagnostics-' + [Guid]::NewGuid().ToString('N'))
    try {
        $paths = Initialize-AssessmentOutput $testRoot
        Write-DiagnosticLog $denied
        $log = [IO.File]::ReadAllText($paths.Log)
        Assert-Diagnostic ($log -match 'Next step:' -and $log -match 'AccessDenied' -and $log -notmatch $canary) 'Troubleshooting is saved immediately, before report export.'
        $hostile = New-AssessmentDiagnostic -Reason '<script>alert(1)</script>' -CheckId 1
        $report = [ordered]@{ Notice='fixture'; Computer='fixture'; User='fixture'; Elevated=$false; StartedUtc='fixture'; Diagnostics=@($denied); Summary=@{Error=1}; Checks=@([pscustomobject]@{Id=1;Title='Fixture';Status='Error';Coverage='Implemented';Limitations=@();Findings=@();Diagnostics=@($hostile,$denied)}) }
        Export-Assessment $report $testRoot -Paths $paths
        $json = [IO.File]::ReadAllText($paths.Json)
        $html = [IO.File]::ReadAllText($paths.Html)
        Assert-Diagnostic ($html -match 'Suggested next steps' -and $html -match 'Technical details' -and $html -match 'Run troubleshooting') 'HTML exposes guidance and technical details at both levels.'
        Assert-Diagnostic ($html -notmatch '<script>' -and $html -match '&lt;script&gt;') 'Diagnostic HTML safely encodes external resource names.'
        Assert-Diagnostic ($json -notmatch $canary -and $html -notmatch $canary) 'Report exporters retain the redaction boundary.'
        $decoded = $json | ConvertFrom-Json
        Assert-Diagnostic ($decoded.Checks[0].Diagnostics[1].Code -eq 'AccessDenied') 'JSON retains structured diagnostics.'

        # Use a directory where a file is required to force a portable write failure.
        $script:DiagnosticLogPath = $testRoot
        $script:RunDiagnostics.Clear()
        Write-DiagnosticLog $denied 3>$null
        Assert-Diagnostic (-not $script:DiagnosticLogPath -and $script:RunDiagnostics.Count -eq 1 -and $script:RunDiagnostics[0].Phase -eq 'Logging') 'Log write failure is reported once and does not stop collection.'

        # Stub collectors only; exercise the real runner, console, and report exporters.
        function Invoke-Check {
            param([int]$Id)
            if ($Id -eq 1) { throw [UnauthorizedAccessException]::new('NEVER_DISCLOSE_DIAGNOSTIC_SECRET_7391') }
            Add-Evidence 'fixture' 'Collector after the failure still ran.'
        }
        $runOutput = Join-Path $testRoot 'run'
        $run = Invoke-StealthPrivesc -CheckId 1,2 -PassThru -OutputDirectory $runOutput -WarningVariable warnings 3>$null
        Assert-Diagnostic ($run.Checks.Count -eq 2 -and $run.Checks[0].Status -eq 'Error' -and $run.Checks[1].Status -eq 'Completed') 'A failed check does not stop later checks.'
        Assert-Diagnostic ($run.Checks[0].Diagnostics[0].Code -eq 'AccessDenied' -and $run.Summary.Error -eq 1) 'Runner failures include useful diagnoses and error counts.'
        Assert-Diagnostic (($warnings | Out-String) -match 'Next step:' -and ($warnings | Out-String) -notmatch $canary) 'Default warnings contain safe, actionable explanations.'
        Assert-Diagnostic ($run -is [pscustomobject]) 'PassThru still returns a report, not diagnostic pipeline objects.'
        $badDirectory = Join-Path $testRoot 'occupied'
        [IO.File]::WriteAllText($badDirectory, 'fixture')
        $fatal = $null
        try { Invoke-StealthPrivesc -CheckId 1 -OutputDirectory $badDirectory -PassThru 3>$null }
        catch { $fatal = $_ }
        Assert-Diagnostic ($fatal -and $fatal.FullyQualifiedErrorId -match 'StealthPrivesc.RunFailed') 'Output initialization errors are friendly terminating failures.'
        Assert-Diagnostic ($fatal.Exception.Data['AssessmentReport'].RunStatus -eq 'Failed' -and $fatal.Exception.Message -match 'writable local directory') 'A failed run preserves its report object and recovery guidance.'
        $fatal = $null
        try { Invoke-StealthPrivesc -CheckId 9999 3>$null }
        catch { $fatal = $_ }
        Assert-Diagnostic ($fatal -and $fatal.Exception.Message -match 'InvalidSelection' -and $fatal.Exception.Message -match '-ListChecks') 'Invalid selectors explain how to find valid values.'
        $originalOS = $env:OS
        try {
            $env:OS = 'FixtureUnsupportedPlatform'
            $fatal = $null
            $startupOutput = Join-Path $testRoot 'startup'
            try { Invoke-StealthPrivesc -CheckId 1 -OutputDirectory $startupOutput 3>$null }
            catch { $fatal = $_ }
            Assert-Diagnostic ($fatal -and $fatal.Exception.Data['AssessmentReport'].Diagnostics[0].Phase -eq 'Initialization') 'Initialization failures retain the failing stage.'
            $startupReport = Get-Content (Get-ChildItem $startupOutput -Filter '*.json').FullName -Raw | ConvertFrom-Json
            Assert-Diagnostic ($startupReport.RunStatus -eq 'Failed' -and $startupReport.Checks.Count -eq 0) 'Initialized output saves a failed-startup report.'
            foreach ($relativePath in @('../tools/Test-Project.ps1','../tests/Test-Sources.ps1','../tests/Test-StealthPrivesc.ps1','../tests/Test-ExtendedChecks.ps1','../tests/Test-Diagnostics.ps1','../tests/Test-Verification.ps1','../tests/Test-AttackPaths.ps1')) {
                $guardPath = Join-Path $script:ModuleRoot $relativePath
                $guard = Invoke-DiagnosticTestProcess ('-NoLogo -NoProfile -NonInteractive -OutputFormat Text -File "' + $guardPath + '"')
                Assert-Diagnostic ($guard.ExitCode -eq 2 -and $guard.Output -match 'NOT RUN:' -and $guard.Output -match 'tools/Test-Project.ps1') "Unsupported-platform test invocation reports its omission and rerun action: $relativePath."
            }
        } finally { $env:OS = $originalOS }

        # Simulate missing runtimes in a child process only; no installed files or
        # parent environment variables are changed, and no test suite is launched.
        $missingRoot = (Join-Path $testRoot 'missing-runtime').Replace("'", "''")
        $runnerPath = (Join-Path $script:ModuleRoot '../tools/Test-Project.ps1').Replace("'", "''")
        $missingResults = Join-Path $testRoot 'missing-results'
        $missingRuntimeCode = '$env:PATH=""; $env:ProgramFiles=''' + $missingRoot + '''; $env:ProgramW6432=''' + $missingRoot + '''; $env:WINDIR=''' + $missingRoot + '''; & ''' + $runnerPath + ''' -ResultsDirectory ''' + $missingResults.Replace("'", "''") + ''''
        $encodedMissingRuntime = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($missingRuntimeCode))
        $missingRuntime = Invoke-DiagnosticTestProcess "-NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $encodedMissingRuntime"
        Assert-Diagnostic ($missingRuntime.ExitCode -eq 1 -and $missingRuntime.Output -match 'Test suites not run: 12 of 12') 'Missing runtimes report every unrun suite and fail validation.'
        Assert-Diagnostic ($missingRuntime.Output -match 'Next action: Install or enable 64-bit' -and $missingRuntime.Output -notmatch 'Validation passed:') 'Missing-runtime output provides a fix instead of a misleading pass.'
        $missingSummary = Get-Content -LiteralPath (Join-Path $missingResults 'validation.json') -Raw | ConvertFrom-Json
        Assert-Diagnostic ($missingSummary.Expected -eq 12 -and $missingSummary.NotRun -eq 12 -and $missingSummary.Passed -eq 0 -and $missingSummary.Results.Count -eq 12) 'Machine-readable CI results count every missing runtime/suite combination.'
        Assert-Diagnostic (@($missingSummary.Results | Where-Object { $_.Status -ne 'NOT RUN' -or $_.Command }).Count -eq 0) 'Missing runtimes never claim an executed command or a passing result.'

        $verboseStream = @(Invoke-StealthPrivesc -CheckId 1,2 -PassThru -Verbose 4>&1 3>$null)
        $verboseText = ($verboseStream | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }) | Out-String
        Assert-Diagnostic ($verboseText -match 'Starting check 1' -and $verboseText -match 'Finished check 2' -and $verboseText -match 'AccessDenied' -and $verboseText -notmatch $canary) 'Verbose mode includes safe diagnostic details and check progress.'
        Assert-Diagnostic (@($verboseStream | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }).Count -eq 1) 'Diagnostic output does not pollute the success stream.'

        & {
            $script:SkipFixtureInvoked = New-Object 'System.Collections.Generic.List[int]'
            function Invoke-Check { param([int]$Id) $script:SkipFixtureInvoked.Add($Id) }
            $skipOutput = Join-Path $testRoot 'skips'
            $skipped = Invoke-StealthPrivesc -CheckId 67,70,132 -PassThru -OutputDirectory $skipOutput -WarningVariable skipWarnings 3>$null
            Assert-Diagnostic ($skipped.Summary.Skipped -eq 3 -and $skipped.SkippedChecks.Count -eq 3 -and $script:SkipFixtureInvoked.Count -eq 0) 'All gated checks are counted, explained, and actually excluded from collection.'
            foreach ($fixture in @(@{Id=67;Flag='IncludeSensitive'},@{Id=70;Flag='IncludeDomain'},@{Id=132;Flag='IncludeNetwork'})) {
                $entry = $skipped.SkippedChecks | Where-Object CheckId -eq $fixture.Id
                Assert-Diagnostic ($entry.ReasonCode -eq 'ScopeNotEnabled' -and $entry.RetryCommand -match "-$($fixture.Flag)" -and $entry.Explanation -match 'did not run') "Skip $($fixture.Id) has the exact missing opt-in and a simple explanation."
                Assert-Diagnostic ($entry.Verification -match 'Status = Completed') "Skip $($fixture.Id) explains how to verify a successful rerun."
            }
            $warningsText = $skipWarnings | Out-String
            Assert-Diagnostic ($warningsText -match '\[Skipped\] Check 67' -and $warningsText -match '\[Skipped\] Check 70' -and $warningsText -match '\[Skipped\] Check 132') 'Every skipped check is visible without Verbose, including PassThru runs.'
            $skipHtml = Get-Content (Get-ChildItem $skipOutput -Filter '*.html').FullName -Raw
            Assert-Diagnostic ($skipHtml -match 'id="skipped-checks">Skipped checks: 3' -and $skipHtml -match 'Why it did not run:' -and $skipHtml -match '-CheckId 132 -IncludeNetwork -Verbose') 'HTML puts skipped counts, reasons and corrected selectors together.'
            $skipJson = Get-Content (Get-ChildItem $skipOutput -Filter '*.json').FullName -Raw | ConvertFrom-Json
            Assert-Diagnostic ($skipJson.SkippedChecks.Count -eq 3 -and $skipJson.Checks[0].Diagnostics[0].SkipReason -eq 'ScopeNotEnabled') 'JSON retains both skip summary and structured per-check reasons.'
            $skipLog = Get-Content (Get-ChildItem $skipOutput -Filter '*.log').FullName -Raw
            Assert-Diagnostic ($skipLog -match '\[Skipped\] Check 67' -and $skipLog -match '-CheckId 67 -IncludeSensitive -Verbose') 'Incremental logs include skipped checks and usable retry selectors.'
            $enabled = Invoke-StealthPrivesc -CheckId 67,70,132 -IncludeDomain -IncludeNetwork -IncludeSensitive -PassThru -OutputDirectory (Join-Path $testRoot 'no-skips') 3>$null
            Assert-Diagnostic ($enabled.Summary.Skipped -eq 0 -and $enabled.SkippedChecks.Count -eq 0 -and $script:SkipFixtureInvoked.Count -eq 3) 'With prerequisites enabled, gated fixture collectors really run.'
            $noSkipHtml = Get-Content (Get-ChildItem (Join-Path $testRoot 'no-skips') -Filter '*.html').FullName -Raw
            Assert-Diagnostic ($noSkipHtml -match 'id="skipped-checks">Skipped checks: 0') 'Zero skipped checks is explicitly reported.'
            $single = Invoke-StealthPrivesc -CheckId 67 -IncludeDomain -PassThru 3>$null
            Assert-Diagnostic ($single.SkippedChecks.Count -eq 1 -and $single.SkippedChecks[0].RetryCommand -match '-IncludeDomain -IncludeSensitive' -and $single.SkippedChecks[0].RetryCommand -notmatch '-IncludeNetwork') 'Retry selectors preserve enabled scope and add only the required opt-in.'

            & {
                function Get-StealthPrivescCheck { [pscustomobject]@{Id=1;Title='Fixture unsupported';Category='Identity';Scope='Local';Coverage='Unsupported';Limitation='Fixture not implemented.'} }
                $unsupported = Invoke-StealthPrivesc -PassThru -WarningVariable unsupportedWarnings 3>$null
                Assert-Diagnostic ($unsupported.Summary.Unsupported -eq 1 -and $unsupported.Summary.Skipped -eq 0 -and $unsupported.Checks[0].Diagnostics[0].Code -eq 'UnsupportedCheck') 'Unsupported implementations are distinguished from fixable prerequisites.'
                $unsupportedWarningText = ($unsupportedWarnings | ForEach-Object { $_.Message }) -join ' '
                Assert-Diagnostic (-not $unsupported.Checks[0].Diagnostics[0].RetryCommand -and $unsupportedWarningText -match 'will not make it run') 'Unsupported checks do not offer a misleading rerun command.'
            }
        }
        & {
            $script:Context = @{Cache=@{}; IncludeDomain=$true}
            function Get-CimInstance { [pscustomobject]@{PartOfDomain=$false} }
            Reset-DiagnosticCheck 141
            Invoke-DomainCheck 141
            $domainSkip = $script:Current.Diagnostics[0]
            Assert-Diagnostic ($script:Current.Status -eq 'Skipped' -and $domainSkip.Code -eq 'DomainNotJoined' -and $domainSkip.Explanation -match 'switch alone cannot fix') 'Actual domain collector explains why a standalone computer cannot run the check.'
            Assert-Diagnostic ($domainSkip.RetryCommand -match '-IncludeDomain' -and ($domainSkip.SuggestedActions -join ' ') -match 'existing domain-joined') 'Domain skip actions identify the required environment.'
            function Get-CimInstance { [pscustomobject]@{PartOfDomain=$true} }
            function Get-Module { return $null }
            Reset-DiagnosticCheck 141
            Invoke-DomainCheck 141
            $moduleSkip = $script:Current.Diagnostics[0]
            Assert-Diagnostic ($moduleSkip.Code -eq 'ActiveDirectoryModuleMissing' -and ($moduleSkip.SuggestedActions -join ' ') -match 'Get-Module -ListAvailable ActiveDirectory') 'Missing RSAT gets installation and verification steps from the real collector.'
            Reset-DiagnosticCheck 73
            Set-CheckSkipped 'Vault collector requires Windows 8 / Server 2012 or newer.' -SkipReason UnsupportedPlatform
            Assert-Diagnostic ($script:Current.Diagnostics[0].Code -eq 'UnsupportedPlatform' -and ($script:Current.Diagnostics[0].SuggestedActions -join ' ') -match 'No scan switch') 'Unsupported OS guidance does not promise a flag can fix it.'
            Reset-DiagnosticCheck 70
            1..4 | ForEach-Object { Set-CheckPartial "Earlier limitation $_" }
            Set-CheckSkipped 'Computer is not domain joined.' -SkipReason DomainNotJoined
            $visible = @(Write-CheckDiagnostics ([pscustomobject]$script:Current) 3>&1) | Out-String
            Assert-Diagnostic ($visible -match '\[Skipped\] Check 70') 'Skip reasons cannot be hidden behind the three-warning display limit.'
        }

        function Export-Assessment { throw [IO.IOException]::new('NEVER_DISCLOSE_DIAGNOSTIC_SECRET_7391') }
        $fatal = $null
        try { Invoke-StealthPrivesc -CheckId 1,2 -OutputDirectory (Join-Path $testRoot 'export-failure') -PassThru 3>$null }
        catch { $fatal = $_ }
        Assert-Diagnostic ($fatal -and $fatal.Exception.Data['AssessmentReport'].Checks.Count -eq 2 -and $fatal.Exception.Data['AssessmentReport'].RunStatus -eq 'Failed') 'Export failure preserves all collected results for recovery.'
        Assert-Diagnostic ($fatal.Exception.Message -match 'Export' -and $fatal.Exception.Message -notmatch $canary) 'Export failure messages stay actionable and redacted.'
    } finally {
        $script:DiagnosticLogPath = $null
        $resolved = [IO.Path]::GetFullPath($testRoot)
        $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^StealthPrivesc-diagnostics-[a-f0-9]{32}$') { throw 'Unsafe test cleanup target.' }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
    Write-Host "PASS: $script:DiagnosticAssertions diagnostic assertions; skipped test groups: 0."
}
