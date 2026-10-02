#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ModulesDirectory,
    [Parameter(Mandatory)][string]$ResultsDirectory,
    [Parameter(Mandatory)][string]$Cell,
    [Parameter(Mandatory)][ValidateSet('5.1','7.4.13','7.6.6')][string]$ExpectedVersion,
    [Parameter(Mandatory)][ValidateSet('x86','x64')][string]$ExpectedArchitecture
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$results=[IO.Path]::GetFullPath($ResultsDirectory)
[void][IO.Directory]::CreateDirectory($results)
$summary=[ordered]@{
    Cell=$Cell;Commit=$env:GITHUB_SHA;Result='NotRun';Total=0;Passed=0;Failed=0;Skipped=0;NotRun=1
    StartedUtc=[DateTime]::UtcNow.ToString('o');FinishedUtc=$null
    Version=$PSVersionTable.PSVersion.ToString();Architecture=$(if([Environment]::Is64BitProcess){'x64'}else{'x86'})
    OperatingSystem=[Environment]::OSVersion.VersionString;RunnerImage=$env:ImageOS;RunnerImageVersion=$env:ImageVersion
    CoveragePercent=0;CoverageTarget=80;MinimumExpectedTests=250;NonTestFailures=@()
    Command="Invoke-Validation.ps1 -Cell $Cell -ExpectedVersion $ExpectedVersion -ExpectedArchitecture $ExpectedArchitecture"
}
$summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $results 'validation.json') -Encoding UTF8
$originalResults=$env:SP_CI_RESULTS
try {
    $versionMatches=if($ExpectedVersion -eq '5.1'){$summary.Version -match '^5\.1\.'}else{$summary.Version -eq $ExpectedVersion}
    if(-not $versionMatches -or $summary.Architecture -ne $ExpectedArchitecture){throw 'Actual runtime does not match the matrix cell.'}
    $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop
    $summary.Platform=[ordered]@{Caption=$os.Caption;Build=$os.BuildNumber;ProductType=$os.ProductType;OSArchitecture=$os.OSArchitecture}
    $build=if($Cell.StartsWith('windows-2022-')){20348}elseif($Cell.StartsWith('windows-2025-')){26100}else{0}
    if($build -and ([int]$os.BuildNumber -ne $build -or [int]$os.ProductType -eq 1)){throw 'Hosted runner OS does not match the requested matrix cell.'}
    $hostPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $arguments=@('-ModulesDirectory',$ModulesDirectory,'-ResultsDirectory',$results,'-Cell',$Cell,'-ExpectedVersion',$ExpectedVersion,'-ExpectedArchitecture',$ExpectedArchitecture)
    $quoted=@($arguments | ForEach-Object { "'"+$_.Replace("'","''")+"'" })
    $summary.Command="& '"+$hostPath.Replace("'","''")+"' -NoLogo -NoProfile -NonInteractive -File '"+(Join-Path $PSScriptRoot 'Invoke-Validation.ps1').Replace("'","''")+"' "+($quoted -join ' ')
    $pins=Import-PowerShellDataFile (Join-Path $PSScriptRoot 'dependencies.psd1')
    Import-Module (Join-Path $ModulesDirectory "Pester/$($pins.Pester)/Pester.psd1") -Force -ErrorAction Stop
    foreach($suite in @('Sources','Offline','ReferenceData','Reports','Assessment')) {
        if(-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "suites/$suite.Tests.ps1"))){throw "Missing required suite $suite."}
    }
    $env:SP_CI_RESULTS=$results
    $configuration=New-PesterConfiguration
    $configuration.Run.Path=Join-Path $PSScriptRoot 'suites'
    $configuration.Run.PassThru=$true
    $configuration.Run.Exit=$false
    $configuration.Output.Verbosity='Normal'
    $configuration.TestResult.Enabled=$true
    $configuration.TestResult.OutputFormat='JUnitXml'
    $configuration.TestResult.OutputPath=Join-Path $results 'tests.xml'
    $configuration.CodeCoverage.Enabled=$true
    $configuration.CodeCoverage.Path=@((Join-Path $root 'src/Private/ReferenceData.ps1'),(Join-Path $root 'src/Private/Verification.ps1'))
    $configuration.CodeCoverage.OutputPath=Join-Path $results 'coverage.xml'
    $configuration.CodeCoverage.OutputFormat='JaCoCo'
    $configuration.CodeCoverage.CoveragePercentTarget=$summary.CoverageTarget
    $testResult=Invoke-Pester -Configuration $configuration
    $summary.Total=$testResult.TotalCount; $summary.Passed=$testResult.PassedCount; $summary.Failed=$testResult.FailedCount
    $summary.Skipped=$testResult.SkippedCount+$testResult.InconclusiveCount
    $summary.NotRun=$testResult.NotRunCount
    $summary.CoveragePercent=$testResult.CodeCoverage.CoveragePercent
    if($testResult.Result -ne 'Passed' -or $summary.Total -lt $summary.MinimumExpectedTests -or $summary.Skipped -or $summary.NotRun -or $summary.CoveragePercent -lt $summary.CoverageTarget){
        $summary.NonTestFailures+= 'Tests, discovery, skips, or scoped code coverage did not meet the required contract.'
    }
    Import-Module (Join-Path $ModulesDirectory "PSScriptAnalyzer/$($pins.PSScriptAnalyzer)/PSScriptAnalyzer.psd1") -Force -ErrorAction Stop
    $issues=@(
        Invoke-ScriptAnalyzer -Path (Join-Path $root 'Invoke-StealthPrivesc.ps1') -Settings (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1')
        foreach($directory in @('src/Private','src/Checks','.github/ci')) {
            Invoke-ScriptAnalyzer -Path (Join-Path $root $directory) -Recurse -Settings (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1')
        }
    )
    $issues | Select-Object RuleName,Severity,ScriptName,Line,Message | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $results 'analysis.json') -Encoding UTF8
    if($issues.Count){$summary.NonTestFailures+="PSScriptAnalyzer reported $($issues.Count) required-rule violations."; $issues | Format-Table RuleName,ScriptName,Line,Message -Wrap}
    $catalog=@(Get-Content (Join-Path $root 'data/checks.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    # Structural/source-reference coverage is deliberately distinguished from
    # collector behavior. No catalog-wide behavioral completeness is claimed.
    @(foreach($check in $catalog){[ordered]@{Id=$check.Id;Category=$check.Category;DispatchAndSourceReference='Tested';CollectorBehavior='NotRun';Reason='Live integration requires the read-only contract and a representative environment.'}}) |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $results 'check-coverage.json') -Encoding UTF8
    $summary.Result=if($summary.NonTestFailures.Count -eq 0){'Passed'}else{'Failed'}
} catch {
    $summary.Result='Failed'; $summary.NonTestFailures+=$_.Exception.Message
    Write-Error $_ -ErrorAction Continue
} finally {
    $env:SP_CI_RESULTS=$originalResults
    $summary.FinishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $results 'validation.json') -Encoding UTF8
    $summary | ConvertTo-Json -Depth 5 | Write-Output
}
if($summary.Result -ne 'Passed'){exit 1}
