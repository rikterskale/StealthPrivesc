#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ResultsDirectory,
    [ValidateSet('x86','x64')][string[]]$Architecture=@('x64','x86'),
    [string]$PowerShell7X86Path,
    [string]$PowerShell7X64Path,
    [ValidateRange(10,1800)][int]$SuiteTimeoutSeconds=300,
    [ValidateSet('Any','Windows11','Server2019')][string]$ExpectedPlatform='Any'
)

$ErrorActionPreference = 'Stop'
$testNames = @('Test-Sources.ps1', 'Test-StealthPrivesc.ps1', 'Test-ExtendedChecks.ps1', 'Test-Diagnostics.ps1', 'Test-Verification.ps1', 'Test-AttackPaths.ps1', 'Test-Platform.ps1')
$startedUtc = [DateTime]::UtcNow.ToString('o')
$Architecture = @($Architecture | Select-Object -Unique)
$expected = ($testNames.Count * 2 + 1) * $Architecture.Count

if ($env:OS -ne 'Windows_NT') {
    Write-Host "NOT RUN: all $expected test-suite/runtime combinations. These tests require Windows APIs and Windows PowerShell 5.1."
    Write-Host 'Next action: run tools/Test-Project.ps1 on 64-bit Windows with Windows PowerShell 5.1 and PowerShell 7 installed. This is incomplete validation, not a pass.'
    exit 2
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$results = New-Object 'System.Collections.Generic.List[object]'
$runtimes = New-Object 'System.Collections.Generic.List[object]'
try { $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop }
catch {
    # Reading OS metadata must not require access to the CIM service.
    $versionKey=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $os=[pscustomobject]@{Caption=$versionKey.ProductName;BuildNumber=$versionKey.CurrentBuildNumber;ProductType=$(if($versionKey.InstallationType -eq 'Client'){1}else{3});OSArchitecture=$(if([Environment]::Is64BitOperatingSystem){'64-bit'}else{'32-bit'})}
}
$platformMatches=($ExpectedPlatform -eq 'Any') -or ($ExpectedPlatform -eq 'Windows11' -and [int]$os.ProductType -eq 1 -and [int]$os.BuildNumber -ge 22000) -or ($ExpectedPlatform -eq 'Server2019' -and [int]$os.ProductType -ne 1 -and [int]$os.BuildNumber -eq 17763)
if(-not $platformMatches){throw "Expected $ExpectedPlatform, found $($os.Caption) build $($os.BuildNumber). No platform coverage is credited."}

function Add-Runtime {
    param(
        [string]$Name,
        [string]$Path,
        [string]$ExpectedVersion,
        [ValidateSet('x86','x64')][string]$ExpectedArchitecture
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Host "MISSING: $Name was not found."
        foreach ($testName in @($testNames + $(if($ExpectedVersion -eq '7'){@('Test-ReferenceUpdate.ps1')}else{@()}))) {
            $results.Add([pscustomobject]@{ Runtime = $Name; Architecture=$ExpectedArchitecture; Test = $testName; Status = 'NOT RUN'; Detail = 'Required runtime is missing.'; Action = "Install or provide $ExpectedArchitecture $Name, then rerun tools/Test-Project.ps1. Portable PowerShell 7 can be obtained with tools/Get-TestPowerShell.ps1." })
        }
        return
    }

    $probeCommand = 'Write-Output ("VERSION=" + $PSVersionTable.PSVersion.ToString()); Write-Output ("IS64BIT=" + [Environment]::Is64BitProcess)'
    $encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeCommand))
    try {
        $probeOutput = @(& $Path -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedProbe 2>&1)
        $probeExitCode = $LASTEXITCODE
    }
    catch {
        $probeOutput = @($_.Exception.Message)
        $probeExitCode = 1
    }

    $versionLine = @($probeOutput | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '^VERSION=' } | Select-Object -First 1)
    $bitnessLine = @($probeOutput | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '^IS64BIT=' } | Select-Object -First 1)
    $version = if ($versionLine.Count) { $versionLine[0].Substring(8) } else { 'unknown' }
    $is64Bit = $bitnessLine.Count -and $bitnessLine[0] -eq 'IS64BIT=True'
    $versionMatches = if ($ExpectedVersion -eq '7') { $version -match '^7\.' } else { $version -match '^5\.1(\.|$)' }

    if ($probeExitCode -ne 0 -or -not $versionMatches -or ($is64Bit -ne ($ExpectedArchitecture -eq 'x64'))) {
        Write-Host "INVALID: $Name resolved to version $version, 64-bit=$is64Bit. Expected PowerShell $ExpectedVersion, $ExpectedArchitecture."
        foreach ($testName in @($testNames + $(if($ExpectedVersion -eq '7'){@('Test-ReferenceUpdate.ps1')}else{@()}))) {
            $results.Add([pscustomobject]@{ Runtime = $Name; Architecture=$ExpectedArchitecture; Test = $testName; Status = 'NOT RUN'; Detail = 'Runtime could not start or its version/architecture did not match.'; Action = "Verify $Name starts normally and is the expected $ExpectedArchitecture version. Correct its installation/PATH, then rerun tools/Test-Project.ps1." })
        }
        return
    }

    $runtimes.Add([pscustomobject]@{ Name = $Name; Path = $Path; Version = $version; Architecture=$ExpectedArchitecture })
    Write-Host "READY: $Name $version ($ExpectedArchitecture)"
}

$pwshCommand = Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$pwshPath = if ($pwshCommand) { $pwshCommand.Source } else { $null }
if (-not $pwshPath) {
    $programFilesRoots = @($env:ProgramW6432, $env:ProgramFiles) | Where-Object { $_ } | Select-Object -Unique
    foreach ($programFilesRoot in $programFilesRoots) {
        $candidatePath = Join-Path $programFilesRoot 'PowerShell/7/pwsh.exe'
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            $pwshPath = $candidatePath
            break
        }
    }
}

$windowsPowerShellPath = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
if (-not [Environment]::Is64BitProcess) {
    $sysnativePath = Join-Path $env:WINDIR 'Sysnative/WindowsPowerShell/v1.0/powershell.exe'
    if (Test-Path -LiteralPath $sysnativePath -PathType Leaf) { $windowsPowerShellPath = $sysnativePath }
}

if('x64' -in $Architecture) {
    if($PowerShell7X64Path){$pwshPath=$PowerShell7X64Path}
    Add-Runtime -Name 'PowerShell 7 x64' -Path $pwshPath -ExpectedVersion '7' -ExpectedArchitecture x64
    Add-Runtime -Name 'Windows PowerShell 5.1 x64' -Path $windowsPowerShellPath -ExpectedVersion '5.1' -ExpectedArchitecture x64
}
if('x86' -in $Architecture) {
    if(-not $PowerShell7X86Path){$PowerShell7X86Path=Join-Path ${env:ProgramFiles(x86)} 'PowerShell/7/pwsh.exe'}
    $x86WindowsPowerShellPath=Join-Path $env:WINDIR 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
    Add-Runtime -Name 'PowerShell 7 x86' -Path $PowerShell7X86Path -ExpectedVersion '7' -ExpectedArchitecture x86
    Add-Runtime -Name 'Windows PowerShell 5.1 x86' -Path $x86WindowsPowerShellPath -ExpectedVersion '5.1' -ExpectedArchitecture x86
}

$scratchRoot = Join-Path $repoRoot ('.validation-temp-' + [Guid]::NewGuid().ToString('N'))
$resolvedRepoRoot = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$resolvedScratchRoot = [IO.Path]::GetFullPath($scratchRoot)
if (-not $resolvedScratchRoot.StartsWith($resolvedRepoRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolvedScratchRoot) -notmatch '^\.validation-temp-[a-f0-9]{32}$') {
    throw 'Unsafe validation scratch path.'
}

$originalTemp = $env:TEMP
$originalTmp = $env:TMP
try {
    [void][IO.Directory]::CreateDirectory($resolvedScratchRoot)
    $env:TEMP = $resolvedScratchRoot
    $env:TMP = $resolvedScratchRoot

    foreach ($runtime in $runtimes) {
        foreach ($testName in @($testNames + $(if($runtime.Version -match '^7\.'){@('Test-ReferenceUpdate.ps1')}else{@()}))) {
            $testPath = Join-Path $PSScriptRoot "../tests/$testName"
            Write-Host "RUN: $($runtime.Name) $testName"
            $timer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $process=New-Object Diagnostics.Process
                $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
                $process.StartInfo.FileName=$runtime.Path
                $process.StartInfo.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$testPath+'"'
                $process.StartInfo.UseShellExecute=$false
                $process.StartInfo.CreateNoWindow=$true
                $process.StartInfo.RedirectStandardOutput=$true
                $process.StartInfo.RedirectStandardError=$true
                if($runtime.Version -match '^5\.1') {
                    # ProcessStartInfo does not perform PowerShell 7's usual
                    # module-path adjustment when launching Windows PowerShell.
                    $nativeModules=Join-Path (Split-Path -Parent $runtime.Path) 'Modules'
                    $process.StartInfo.EnvironmentVariables['PSModulePath']=$nativeModules+[IO.Path]::PathSeparator+$env:PSModulePath
                }
                try {
                    [void]$process.Start()
                    $stdout=$process.StandardOutput.ReadToEndAsync()
                    $stderr=$process.StandardError.ReadToEndAsync()
                    if(-not $process.WaitForExit($SuiteTimeoutSeconds*1000)){
                        try{$process.Kill()}catch [InvalidOperationException]{}
                        throw [TimeoutException]::new("Suite exceeded $SuiteTimeoutSeconds seconds; remaining assertions did not run.")
                    }
                    if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Suite output streams did not close.'}
                    Write-Output ($stdout.GetAwaiter().GetResult())
                    Write-Output ($stderr.GetAwaiter().GetResult())
                    $exitCode=$process.ExitCode
                } finally { $process.Dispose() }
                if ($exitCode -eq 0) {
                    $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'PASS'; Detail = 'Process exited 0.'; Action = '' })
                    Write-Host "PASS: $($runtime.Name) $testName"
                }
                else {
                    $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'FAIL'; Detail = "Process exited $exitCode; later assertions in this suite may not have run."; Action = 'Resolve the first reported error, then rerun tools/Test-Project.ps1. DPAPI/profile errors require a normal logged-in Windows session with the user profile loaded.' })
                    Write-Host "FAIL: $($runtime.Name) $testName (exit $exitCode)"
                }
            }
            catch {
                $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'FAIL'; Detail = $_.Exception.Message; Action = 'Verify the test script and runtime are readable and can execute, then rerun tools/Test-Project.ps1.' })
                Write-Host "FAIL: $($runtime.Name) $testName ($($_.Exception.GetType().Name))"
            }
            finally {
                $timer.Stop()
                $results[$results.Count - 1] | Add-Member -NotePropertyName DurationSeconds -NotePropertyValue ([Math]::Round($timer.Elapsed.TotalSeconds, 3))
                $results[$results.Count - 1] | Add-Member -NotePropertyName Architecture -NotePropertyValue $runtime.Architecture
            }
        }
    }
}
finally {
    $env:TEMP = $originalTemp
    $env:TMP = $originalTmp
    if (Test-Path -LiteralPath $resolvedScratchRoot) {
        Remove-Item -LiteralPath $resolvedScratchRoot -Recurse -Force
    }
}

Write-Host ''
Write-Host 'Validation summary:'
$results | Format-Table Runtime, Test, Status, Detail -AutoSize -Wrap | Out-Host
$notRun = @($results | Where-Object Status -eq 'NOT RUN')
Write-Host "Test suites not run: $($notRun.Count) of $($results.Count) required runtime/suite combinations."
$failures = @($results | Where-Object Status -ne 'PASS')
if ($ResultsDirectory) {
    [void][IO.Directory]::CreateDirectory($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ResultsDirectory))
    foreach ($result in $results) {
        $runtime = $runtimes | Where-Object Name -eq $result.Runtime | Select-Object -First 1
        $command = if ($runtime) {
            "& '" + $runtime.Path.Replace("'", "''") + "' -NoLogo -NoProfile -NonInteractive -File '" + (Join-Path $repoRoot "tests/$($result.Test)").Replace("'", "''") + "'"
        } else { $null }
        $result | Add-Member -NotePropertyName Command -NotePropertyValue $command
    }
    $summary = [ordered]@{
        SchemaVersion = '1.1'
        StartedUtc = $startedUtc
        FinishedUtc = [DateTime]::UtcNow.ToString('o')
        OperatingSystem = [Environment]::OSVersion.VersionString
        Platform = [ordered]@{Caption=$os.Caption;Build=$os.BuildNumber;ProductType=[int]$os.ProductType;OSArchitecture=$os.OSArchitecture;Expected=$ExpectedPlatform}
        Architectures = $Architecture
        SuiteTimeoutSeconds = $SuiteTimeoutSeconds
        Expected = $expected
        Passed = @($results | Where-Object Status -eq 'PASS').Count
        Failed = @($results | Where-Object Status -eq 'FAIL').Count
        NotRun = $notRun.Count
        Runtimes = @($runtimes.ToArray())
        Results = @($results.ToArray())
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'validation.json') -Encoding UTF8
}
if ($failures.Count) {
    foreach ($result in $failures) { Write-Host "$($result.Status): $($result.Runtime) / $($result.Test). $($result.Detail) Next action: $($result.Action)" }
    Write-Host "Validation failed: $($failures.Count) required check(s) did not pass."
    exit 1
}

Write-Host 'Validation passed: all required test scripts passed under both supported PowerShell editions; no test groups were skipped.'
exit 0
