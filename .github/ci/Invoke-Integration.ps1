#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResultsDirectory,
    [ValidateSet('Hosted','Windows11','Server2019','DomainLab')][string]$Platform='Hosted',
    [ValidateSet('Any','Standard','Elevated')][string]$Context='Any'
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
[void][IO.Directory]::CreateDirectory($ResultsDirectory)
$resultPath=Join-Path $ResultsDirectory 'integration.json'
$state=[ordered]@{Status='NotRun';Platform=$Platform;ExpectedContext=$Context;Commit=$env:GITHUB_SHA;Reason='Integration has not started.'}
$state | ConvertTo-Json | Set-Content $resultPath -Encoding UTF8
try {
    # This guard precedes ALL scanner execution. Runtime validation must never
    # execute security-control tampering or process-memory patching.
    $mutators='\b(WriteProcessMemory|VirtualProtect(?:Ex)?|CreateRemoteThread|AdjustTokenPrivileges|ChangeServiceConfig\w*|StartService\w*|ControlService|RegSetValue\w*|SetSecurityInfo)\s*\('
    foreach($file in Get-ChildItem (Join-Path $root 'src') -Filter '*.cs') {
        if((Get-Content $file.FullName -Raw) -match $mutators){throw "Read-only contract failed in $($file.Name); scan integration was not executed."}
    }
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $state.OSCaption=$os.Caption; $state.OSBuild=$os.BuildNumber
    if($Platform -eq 'Windows11' -and ([int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000)){throw 'Runner is not Windows 11.'}
    if($Platform -eq 'Server2019' -and ([int]$os.ProductType -eq 1 -or [int]$os.BuildNumber -ne 17763)){throw 'Runner is not Server 2019.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} finally {$identity.Dispose()}
    $state.Elevated=$admin
    if(($Context -eq 'Standard' -and $admin) -or ($Context -eq 'Elevated' -and -not $admin)){throw 'Runner token does not match the requested assessment context.'}
    $options=@{PassThru=$true;MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=30;OutputDirectory=$ResultsDirectory}
    if($Platform -eq 'DomainLab') {
        if(-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'Domain lab runner is not domain joined.'}
        if(-not (Get-Module -ListAvailable ActiveDirectory)){throw 'Domain lab runner lacks RSAT ActiveDirectory.'}
        $options.IncludeDomain=$true
        $options.Category='DomainCloud'
    }
    $report=& (Join-Path $root 'Invoke-StealthPrivesc.ps1') @options
    if($null -eq $report -or $report.RunStatus -ne 'Completed' -or $report.Summary.Error -ne 0 -or $report.AttackPathAnalysis.Status -eq 'Error'){throw 'Runner, collector, or analysis errors were observed.'}
    Import-Module (Join-Path $root 'src/StealthPrivesc.psd1') -Force
    $selectors=@{}
    if($Platform -eq 'DomainLab'){$selectors.Category='DomainCloud'}
    $expected=@(Get-StealthPrivescCheck @selectors)
    if(@(Compare-Object @($expected.Id) @($report.Checks.Id)).Count -or $report.Checks.Count -ne $expected.Count){throw 'The report did not cover exactly the selected catalog.'}
    foreach($check in $report.Checks) {
        $entry=$expected | Where-Object Id -eq $check.Id
        $gated=($entry.Scope -eq 'Sensitive') -or ($entry.Scope -eq 'Network') -or ($entry.Scope -eq 'Domain' -and $Platform -ne 'DomainLab')
        if($gated -and ($check.Status -ne 'Skipped' -or $check.Verification.CollectorStarted)){throw "Scope gate failed for check $($check.Id)."}
        if(-not $gated -and $check.Status -in @('Error','Unsupported')){throw "Unexpected status for check $($check.Id)."}
    }
    foreach($extension in @('json','html','log')) {
        if(-not @(Get-ChildItem $ResultsDirectory -Filter "assessment-*.$extension").Count){throw "Missing $extension output."}
    }
    $state.Status='Passed'; $state.Reason='Selected IDs, gates, runner state, collector errors, and artifacts validated.'
    $state.CheckCount=$report.Checks.Count; $state.Summary=$report.Summary
} catch {
    $state.Status='Failed'; $state.Reason=$_.Exception.Message
    Write-Error $_ -ErrorAction Continue
} finally {
    $state | ConvertTo-Json -Depth 8 | Set-Content $resultPath -Encoding UTF8
}
if($state.Status -ne 'Passed'){exit 1}
