#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    Write-Host 'Project validation requires Windows because the supported test matrix includes Windows PowerShell 5.1 and Windows native checks.'
    exit 2
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$testNames = @('Test-StealthPrivesc.ps1', 'Test-ExtendedChecks.ps1')
$results = New-Object 'System.Collections.Generic.List[object]'
$runtimes = New-Object 'System.Collections.Generic.List[object]'

function Add-Runtime {
    param(
        [string]$Name,
        [string]$Path,
        [string]$ExpectedVersion
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Host "MISSING: $Name was not found."
        foreach ($testName in $testNames) {
            $results.Add([pscustomobject]@{ Runtime = $Name; Test = $testName; Status = 'FAIL'; Detail = 'Required runtime is missing.' })
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

    if ($probeExitCode -ne 0 -or -not $versionMatches -or -not $is64Bit) {
        Write-Host "INVALID: $Name resolved to version $version, 64-bit=$is64Bit. Expected PowerShell $ExpectedVersion, 64-bit."
        foreach ($testName in $testNames) {
            $results.Add([pscustomobject]@{ Runtime = $Name; Test = $testName; Status = 'FAIL'; Detail = 'Runtime version or architecture did not match the supported matrix.' })
        }
        return
    }

    $runtimes.Add([pscustomobject]@{ Name = $Name; Path = $Path; Version = $version })
    Write-Host "READY: $Name $version (64-bit)"
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

Add-Runtime -Name 'PowerShell 7' -Path $pwshPath -ExpectedVersion '7'
Add-Runtime -Name 'Windows PowerShell 5.1' -Path $windowsPowerShellPath -ExpectedVersion '5.1'

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
        foreach ($testName in $testNames) {
            $testPath = Join-Path $PSScriptRoot "../tests/$testName"
            Write-Host "RUN: $($runtime.Name) $testName"
            try {
                & $runtime.Path -NoLogo -NoProfile -NonInteractive -File $testPath
                $exitCode = $LASTEXITCODE
                if ($exitCode -eq 0) {
                    $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'PASS'; Detail = 'Process exited 0.' })
                    Write-Host "PASS: $($runtime.Name) $testName"
                }
                else {
                    $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'FAIL'; Detail = "Process exited $exitCode." })
                    Write-Host "FAIL: $($runtime.Name) $testName (exit $exitCode)"
                }
            }
            catch {
                $results.Add([pscustomobject]@{ Runtime = $runtime.Name; Test = $testName; Status = 'FAIL'; Detail = $_.Exception.Message })
                Write-Host "FAIL: $($runtime.Name) $testName ($($_.Exception.GetType().Name))"
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
$results | Format-Table Runtime, Test, Status, Detail -AutoSize | Out-Host
$failures = @($results | Where-Object Status -ne 'PASS')
if ($failures.Count) {
    Write-Host "Validation failed: $($failures.Count) required check(s) did not pass."
    exit 1
}

Write-Host 'Validation passed: all required test scripts passed under both supported PowerShell editions.'
exit 0
