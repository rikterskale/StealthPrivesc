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
    $catalog = @(Get-StealthPrivescCheck -CheckId $CheckId -Category $Category)
    if ($ListChecks) { return $catalog }
    if ($env:OS -ne 'Windows_NT') { throw 'Scanning requires Windows. -ListChecks can be used on other platforms.' }
    if (-not ('StealthPrivesc.Native' -as [type])) {
        Add-Type -Path (Join-Path $script:ModuleRoot 'Native.cs') -ErrorAction Stop
    }
    if (-not ('StealthPrivesc.NativeInspection' -as [type])) {
        Add-Type -Path (Join-Path $script:ModuleRoot 'NativeInspection.cs') -ErrorAction Stop
    }
    if (-not ('StealthPrivesc.NativeObjects' -as [type])) {
        Add-Type -Path (Join-Path $script:ModuleRoot 'NativeObjects.cs') -ErrorAction Stop
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $script:Context = @{
        MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes; CommandTimeoutSeconds = $CommandTimeoutSeconds
        IncludeNetwork = [bool]$IncludeNetwork; IncludeDomain = [bool]$IncludeDomain; IncludeSensitive = [bool]$IncludeSensitive
        SearchRoot = @($SearchRoot); Cache = @{}; Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        DriverDatabasePath=$DriverDatabasePath;VulnerabilityDatabasePath=$VulnerabilityDatabasePath
    }
    $report = [ordered]@{
        SchemaVersion = '1.0'; ToolVersion = '0.2.0'; StartedUtc = [DateTime]::UtcNow.ToString('o')
        Computer = $env:COMPUTERNAME; User = $identity.Name; UserSid = $identity.User.Value
        Elevated = $script:Context.Elevated; ProcessArchitecture = $(if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' })
        Scope = [ordered]@{ Network = [bool]$IncludeNetwork; Domain = [bool]$IncludeDomain; Sensitive = [bool]$IncludeSensitive; MaxItems = $MaxItems; MaxFileBytes = $MaxFileBytes }
        Notice = 'Evidence is redacted. Findings are candidates unless explicitly stated; access tests use the current token. Missing evidence is not a clean bill of health.'
        Checks = New-Object 'System.Collections.Generic.List[object]'
    }
    try {
        foreach ($check in $catalog) {
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $script:Current = [ordered]@{ Id = $check.Id; Title = $check.Title; Category = $check.Category; Coverage = $check.Coverage; Status = 'Completed'; Limitations = New-Object 'System.Collections.Generic.List[string]'; Findings = New-Object 'System.Collections.Generic.List[object]'; DurationMs = 0 }
            $script:RegistryVisited = 0
            if ($check.Coverage -ne 'Implemented') { $script:Current.Status = 'Partial' }
            if ($check.Limitation) { $script:Current.Limitations.Add($check.Limitation) }
            Write-Progress -Activity 'Windows exposure assessment' -Status "$($check.Id): $($check.Title)" -PercentComplete (($report.Checks.Count / [Math]::Max(1,$catalog.Count)) * 100)
            try {
                if ($check.Coverage -eq 'Unsupported') { $script:Current.Status = 'Unsupported' }
                elseif ($check.Scope -eq 'Domain' -and -not $IncludeDomain) { Set-CheckSkipped 'Requires -IncludeDomain (queries the joined domain).' }
                elseif ($check.Scope -eq 'Network' -and -not $IncludeNetwork) { Set-CheckSkipped 'Requires -IncludeNetwork.' }
                elseif ($check.Scope -eq 'Sensitive' -and -not $IncludeSensitive) { Set-CheckSkipped 'Requires -IncludeSensitive; values remain redacted.' }
                else { Invoke-Check -Id $check.Id }
            } catch {
                $script:Current.Status = 'Error'
                # Do not serialize exception messages: providers can embed secret data in them.
                $script:Current.Limitations.Add("Collector failed: $($_.Exception.GetType().Name); error ID: $($_.FullyQualifiedErrorId.Split(',')[0]).")
            }
            $script:Current.DurationMs = $timer.ElapsedMilliseconds
            $report.Checks.Add([pscustomobject]$script:Current)
        }
    } finally { $identity.Dispose(); Write-Progress -Activity 'Windows exposure assessment' -Completed }
    $report.FinishedUtc = [DateTime]::UtcNow.ToString('o')
    $report.Summary = [ordered]@{}
    foreach ($status in @('Completed','Partial','Skipped','Unsupported','Error')) { $report.Summary[$status] = @($report.Checks | Where-Object Status -eq $status).Count }
    if ($OutputDirectory) { Export-Assessment -Report $report -Directory $OutputDirectory }
    if ($PassThru) { return [pscustomobject]$report }
    $report.Checks | Select-Object Id, Category, Status, @{n='Findings';e={$_.Findings.Count}}, Title | Format-Table -AutoSize
    Write-Host ('Completed: {0}; Partial: {1}; Skipped: {2}; Unsupported: {3}; Errors: {4}' -f $report.Summary.Completed,$report.Summary.Partial,$report.Summary.Skipped,$report.Summary.Unsupported,$report.Summary.Error)
}
Export-ModuleMember -Function Invoke-StealthPrivesc, Get-StealthPrivescCheck
