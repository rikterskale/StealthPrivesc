Describe 'Synthetic report export and offline analysis contracts' {
    BeforeAll {
        Import-Module ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../src/StealthPrivesc.psd1'))) -Force
        $script:ScannerModule=Get-Module StealthPrivesc
        function New-ReportFixture {
            [ordered]@{
                SchemaVersion='1.5';ToolVersion='0.2.1';RunStatus='Completed';StartedUtc='2026-01-01T00:00:00Z';FinishedUtc='2026-01-01T00:00:01Z'
                Notice='Synthetic fixture only';Computer='fixture';User='fixture';Elevated=$false;UserSid='S-1-5-21-1-2-3-1001'
                ProcessArchitecture=$(if([Environment]::Is64BitProcess){'x64'}else{'x86'});OperatingSystemArchitecture='x64';PowerShellVersion=$PSVersionTable.PSVersion.ToString()
                Scope=@{Network=$false;Domain=$false;Sensitive=$false;MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=1}
                Checks=@();Diagnostics=@();SkippedChecks=@();Summary=[ordered]@{Completed=0;Partial=0;Skipped=0;Unsupported=0;Error=0}
            }
        }
    }

    It 'Exports escaped HTML, schema-valid JSON and a secret-free diagnostic log' {
        $directory=Join-Path $TestDrive "space and O'Brien unicode-$([char]0x03bb)"
        $report=New-ReportFixture
        & $script:ScannerModule {
            param($Report,$Directory)
            $script:Context=$Report.Scope.Clone(); $script:Context.IncludeNetwork=$false; $script:Context.IncludeDomain=$false; $script:Context.IncludeSensitive=$false; $script:Context.SearchRoot=@()
            $script:Current=[ordered]@{Id=1;Title='<script>hostile title</script>';Category='Identity';Coverage='Implemented';Status='Completed';DurationMs=0;Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=@();Diagnostics=@();Verification=(New-CheckVerification 1)}
            Add-Evidence '<script>alert(1)</script>' 'Synthetic redacted evidence' @{Value='[REDACTED]'}
            $Report.Checks=@([pscustomobject]$script:Current); $Report.Summary.Completed=1
            $Report.AttackPathAnalysis=Get-StealthPrivescAttackPathAnalysis $Report
            $paths=Initialize-AssessmentOutput $Directory
            $failure=[Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('CANARY_EXPORT_SECRET'),'CANARY_EXPORT_SECRET',[Management.Automation.ErrorCategory]::PermissionDenied,'CANARY_EXPORT_SECRET')
            Write-DiagnosticLog (New-AssessmentDiagnostic 'Synthetic denied resource.' -ErrorRecord $failure)
            Export-Assessment $Report $Directory -Paths $paths
            $html=[IO.File]::ReadAllText($paths.Html); $json=[IO.File]::ReadAllText($paths.Json); $log=[IO.File]::ReadAllText($paths.Log)
            $html | Should -Not -Match '<script>'
            $html | Should -Match '&lt;script&gt;'
            $html | Should -Match 'id="check-1-finding-0"'
            ($html+$json+$log) | Should -Not -Match 'CANARY_EXPORT_SECRET'
            ($json | ConvertFrom-Json).Checks[0].Findings[0].Target | Should -Be '<script>alert(1)</script>'
            @(Get-ChildItem $Directory -Filter '*.tmp').Count | Should -Be 0
            if ($env:SP_CI_RESULTS) {
                $fixture=Join-Path $env:SP_CI_RESULTS 'report-fixture.json'
                Copy-Item -LiteralPath $paths.Json -Destination $fixture
            }
            $script:DiagnosticLogPath=$null
        } $report $directory
    }

    It 'Preserves an existing JSON report when serialization or output fails' {
        $path=Join-Path $TestDrive 'existing.json'; [IO.File]::WriteAllText($path,'{"original":true}')
        & $script:ScannerModule {
            param($Path)
            # Invalid target directory forces failure before replacing the existing file.
            { Save-AssessmentJson @{Fixture=$true} ($Path+'/invalid.json') } | Should -Throw
            [IO.File]::ReadAllText($Path) | Should -BeExactly '{"original":true}'
        } $path
    }

    It 'Exposes a log failure without stopping independent offline processing' {
        & $script:ScannerModule {
            param($Directory)
            $script:DiagnosticLogPath=$Directory
            $script:RunDiagnostics.Clear()
            Write-DiagnosticLog (New-AssessmentDiagnostic 'Fixture resource.') 3>$null
            $script:DiagnosticLogPath | Should -BeNullOrEmpty
            $script:RunDiagnostics.Count | Should -Be 1
            $script:RunDiagnostics[0].Phase | Should -Be 'Logging'
        } $TestDrive
    }

    It 'Marks absent correlation inputs as incomplete, without querying the host' {
        Mock Get-CimInstance -ModuleName StealthPrivesc { throw 'Offline analysis queried the host.' }
        Mock Invoke-ReadOnlyCommand -ModuleName StealthPrivesc { throw 'Offline analysis launched a process.' }
        $report=New-ReportFixture
        $before=$report | ConvertTo-Json -Depth 16
        $analysis=Get-StealthPrivescAttackPathAnalysis $report
        $analysis.Status | Should -Be 'Partial'
        $analysis.Paths.Count | Should -Be 0
        $analysis.RuleCoverage.Count | Should -Be 6
        ($report | ConvertTo-Json -Depth 16) | Should -BeExactly $before
        Should -Invoke Get-CimInstance -ModuleName StealthPrivesc -Times 0 -Exactly
        Should -Invoke Invoke-ReadOnlyCommand -ModuleName StealthPrivesc -Times 0 -Exactly
    }

    It 'Rejects duplicate imported check IDs' {
        $report=New-ReportFixture
        $report.Checks=@([pscustomobject]@{Id=1;Status='Completed';Findings=@()},[pscustomobject]@{Id=1;Status='Completed';Findings=@()})
        { Get-StealthPrivescAttackPathAnalysis $report } | Should -Throw '*unique check IDs*'
    }
}
