#requires -Version 5.1
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){Write-Host 'NOT RUN: Test-Platform requires Windows. Run tools/Test-Project.ps1 on the intended Windows platform.';exit 2}
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
& (Get-Module StealthPrivesc) {
    $script:PlatformAssertions=0
    function Assert-Platform([bool]$Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:PlatformAssertions++}
    $root=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-platform-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    try {
        $nativeHost=Get-WindowsPowerShellPath x64
        Assert-Platform (Test-Path -LiteralPath $nativeHost) 'Native Windows PowerShell is reachable from this process architecture.'
        Assert-Platform (Test-Path -LiteralPath (Get-WindowsPowerShellPath x86)) '32-bit Windows PowerShell is reachable.'
        if(-not [Environment]::Is64BitProcess){Assert-Platform ($nativeHost -match 'Sysnative') 'WOW64 helpers reach the native system directory.'}
        foreach($fixture in @(@{Machine=0x14c;Architecture='x86'},@{Machine=0x8664;Architecture='x64'})) {
            $bytes=New-Object byte[] 128;$bytes[0]=0x4d;$bytes[1]=0x5a;$bytes[60]=64;$bytes[64]=0x50;$bytes[65]=0x45
            [Array]::Copy([BitConverter]::GetBytes([uint16]$fixture.Machine),0,$bytes,68,2)
            $path=Join-Path $root ($fixture.Architecture+'.dll');[IO.File]::WriteAllBytes($path,$bytes)
            Assert-Platform ((Get-ImageArchitecture $path) -eq $fixture.Architecture) 'NSS helper architecture follows the PE machine, independent of scanner bitness.'
        }
        [IO.File]::WriteAllText((Join-Path $root 'bad.dll'),'invalid');$rejected=$false
        try{Get-ImageArchitecture (Join-Path $root 'bad.dll')|Out-Null}catch{$rejected=$true}
        Assert-Platform $rejected 'Malformed native library headers cannot select a helper.'
        $coverage=Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Mar','2026-Jan','2026-Jan')})
        Assert-Platform ($coverage.Months.Count -eq 2 -and $coverage.MissingMonths.Count -eq 1 -and $coverage.MissingMonths[0] -eq '2026-Feb') 'Reference metadata discloses exact gaps and deduplicates months.'
        $single=Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Jan')})
        Assert-Platform ($single.Months.Count -eq 1 -and $single.MissingMonths.Count -eq 0) 'Single-month coverage remains a bounded source period.'
        $rejected=$false;try{Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Bad')})|Out-Null}catch{$rejected=$true}
        Assert-Platform $rejected 'Invalid coverage months fail validation.'
        foreach($fixture in @(@{Build=22631;Product='Windows 11 Version 23H2 for x64-based Systems';Server=$false},@{Build=17763;Product='Windows Server 2019';Server=$true})) {
            $context=[pscustomobject]@{Version=[version]"10.0.$($fixture.Build).100";IsServer=$fixture.Server;Architecture='x64'}
            $rules=@([pscustomobject]@{Cve='CVE-FIXTURE';Title='Fixture';Product=$fixture.Product;FixedBuild="10.0.$($fixture.Build).200";KB='fixture';Source='fixture'})
            $result=@(Get-WindowsPatchAssessment $rules $context)
            Assert-Platform ($result.Count -eq 1 -and $result[0].State -eq 'BelowPublishedFix') 'OS applicability uses host architecture, even from an x86 scanner.'
            $context.IsServer=-not $fixture.Server
            Assert-Platform (@(Get-WindowsPatchAssessment $rules $context).Count -eq 0) 'Workstation and server rules do not cross-match.'
        }
        Add-Type -Path (Join-Path $script:ModuleRoot 'NativeProcess.cs')
        $hostPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('[Console]::Write("x"*4096)'))
        $rejected=$false
        try{[StealthPrivesc.NativeProcess]::Run($hostPath,"-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded",10,128)|Out-Null}catch{$rejected=$_.Exception.GetBaseException() -is [IO.InvalidDataException]}
        Assert-Platform $rejected 'Oversized helper output stops collection instead of consuming unbounded memory.'
        $sampled=New-AssessmentDiagnostic -Reason 'Intentional domain sampling: queries are bounded by MaxItems.'
        Assert-Platform ($sampled.Code -eq 'SampledCoverage' -and $sampled.Explanation -match 'intentional') 'Sampling is distinct from query failure or truncation.'
        $report=Invoke-StealthPrivesc -CheckId 1,2,3,4,6,11,12,13,22,24 -MaxItems 10 -CommandTimeoutSeconds 30 -PassThru
        Assert-Platform ($report.ProcessArchitecture -eq $(if([Environment]::Is64BitProcess){'x64'}else{'x86'})) 'Report architecture matches the actual runtime.'
        Assert-Platform ($report.Summary.Error -eq 0) 'Core token, account, service and task collectors run without errors on this platform.'
        if(-not [Environment]::Is64BitProcess){Assert-Platform ($report.CollectionView -match 'WOW64') 'Reports disclose redirected collection views.'}
        Write-Host "PASS: $script:PlatformAssertions platform assertions ($($report.ProcessArchitecture)); skipped test groups: 0."
    } finally {
        $resolved=[IO.Path]::GetFullPath($root);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        if(-not $resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^StealthPrivesc-platform-[a-f0-9]{32}$'){throw 'Unsafe cleanup target.'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
