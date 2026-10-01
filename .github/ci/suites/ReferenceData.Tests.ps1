Describe 'Offline reference applicability and metadata' {
    BeforeAll {
        Import-Module ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../src/StealthPrivesc.psd1'))) -Force
        $script:ScannerModule=Get-Module StealthPrivesc
    }
    BeforeEach {
        & $script:ScannerModule {
            $script:Context=@{IncludeNetwork=$false;IncludeDomain=$false;Cache=@{};MaxItems=10}
            $script:Current=[ordered]@{Id=59;Title='Fixture';Status='Completed';Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=New-Object 'System.Collections.Generic.List[string]';Diagnostics=New-Object 'System.Collections.Generic.List[object]'}
            $script:DiagnosticLogPath=$null
        }
    }

    It 'Preserves month gaps, rejects malformed dates, and accepts scalar/date inputs' {
        & $script:ScannerModule {
            $coverage=Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Mar','2026-Jan','2026-Jan')})
            $coverage.Months.Count | Should -Be 2
            $coverage.MissingMonths | Should -Contain '2026-Feb'
            (Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Jan')})).MissingMonths.Count | Should -Be 0
            (Get-ReferenceMonthCoverage ([pscustomobject]@{})).Months.Count | Should -Be 0
            { Get-ReferenceMonthCoverage ([pscustomobject]@{Months=@('2026-Bad')}) } | Should -Throw
            { ConvertTo-ReferenceDate 'not a date' } | Should -Throw
            ConvertTo-ReferenceDate ([DateTimeOffset]::UtcNow) | Should -BeOfType ([DateTimeOffset])
            ConvertTo-ReferenceDate ([DateTime]::UtcNow) | Should -BeOfType ([DateTimeOffset])
            ConvertTo-ReferenceDate '2026-01-01T00:00:00Z' | Should -BeOfType ([DateTimeOffset])
        }
    }

    It 'Uses exact product, role, architecture and earliest fixing revision' {
        & $script:ScannerModule {
            $rules=@(
                [pscustomobject]@{Cve='CVE-FIXTURE';Title='Fixture';Product='Windows 11 Version 23H2 for x64-based Systems';FixedBuild='10.0.22631.100';KB='fixture';Source='fixture'},
                [pscustomobject]@{Cve='CVE-FIXTURE';Title='Fixture';Product='Windows 11 Version 23H2 for x64-based Systems';FixedBuild='10.0.22631.200';KB='fixture';Source='fixture'}
            )
            $context=[pscustomobject]@{Version=[version]'10.0.22631.99';IsServer=$false;Architecture='x64'}
            $result=@(Get-WindowsPatchAssessment $rules $context)
            $result.Count | Should -Be 1
            $result[0].State | Should -Be 'BelowPublishedFix'
            $result[0].FixedBuild | Should -Be '10.0.22631.100'
            $context.Version=[version]'10.0.22631.100'
            (Get-WindowsPatchAssessment $rules $context).State | Should -Be 'AtOrAbovePublishedFix'
            $context.IsServer=$true
            @(Get-WindowsPatchAssessment $rules $context).Count | Should -Be 0
            Test-WindowsProductMatch 'Windows Server 2019' $context | Should -BeTrue
            $context.Architecture='arm64'
            Test-WindowsProductMatch 'Windows Server 2019' $context | Should -BeFalse
            Test-WindowsProductMatch 'Windows Server 2025 ARM64' $context | Should -BeTrue
            Test-WindowsProductMatch 'Windows Server x86' $context | Should -BeFalse
            $context.Architecture='x86'
            Test-WindowsProductMatch 'Windows Server 32-bit' $context | Should -BeTrue
            $context.Version=[version]'10.0.26100.1'
            (Get-WindowsPatchAssessment $rules $context @('CVE-FIXTURE')).State | Should -Be 'NoMatchingProductRule'
            $rules[0].FixedBuild='bad'
            { Get-WindowsPatchAssessment $rules $context } | Should -Throw
        }
    }

    It 'Reports stale, incomplete and invalid snapshots without certifying safety' {
        $path=Join-Path $TestDrive 'reference.json'
        @{SchemaVersion=1;Source='Synthetic fixture';RetrievedUtc='2020-01-01T00:00:00Z';Months=@('2026-Jan','2026-Mar');MonthRetrievedUtc=@{'2026-Jan'='2020-01-01T00:00:00Z'};Entries=@(@{Id='fixture'})} | ConvertTo-Json -Depth 6 | Set-Content $path -Encoding UTF8
        & $script:ScannerModule {
            param($Path)
            $document=Get-ReferenceDocument $Path 'MSRC'
            $document.Entries.Count | Should -Be 1
            $script:Current.Status | Should -Be 'Partial'
            $script:Current.Limitations.Count | Should -BeGreaterThan 2
            Get-ReferenceDocument ($Path+'.missing') 'Fixture' | Should -BeNullOrEmpty
            [IO.File]::WriteAllText($Path,'{"SchemaVersion":99,"Entries":[]}')
            Get-ReferenceDocument $Path 'Fixture' | Should -BeNullOrEmpty
            [IO.File]::WriteAllText($Path,'{"SchemaVersion":1,"RetrievedUtc":"2026-01-01T00:00:00Z","Source":"fixture","Entries":[]}')
            Get-ReferenceDocument $Path 'MSRC' | Should -Not -BeNullOrEmpty
        } $path
    }

    It 'Matches exact case-insensitive driver hashes, not names' {
        $path=Join-Path $TestDrive 'fixture.sys'; [IO.File]::WriteAllText($path,'harmless bytes')
        $hash=(Get-FileHash $path -Algorithm SHA256).Hash
        & $script:ScannerModule {
            param($Path,$Hash)
            $rules=@([pscustomobject]@{SHA256=$Hash.ToLowerInvariant();Id='fixture';Category='fixture';Resources=@('synthetic')})
            $drivers=@([pscustomobject]@{Path=$Path;Name='fixture';State='Stopped'})
            @(Get-DriverHashMatches $rules $drivers).Count | Should -Be 1
            [IO.File]::WriteAllText($Path,'changed harmless bytes')
            @(Get-DriverHashMatches $rules $drivers).Count | Should -Be 0
            $rules[0].SHA256='bad'
            { Get-DriverHashMatches $rules $drivers } | Should -Throw
            Resolve-DriverPath '\SystemRoot\System32\fixture.sys' | Should -Match 'System32\\fixture\.sys$'
            Resolve-DriverPath '\??\C:\fixture.sys' | Should -Be 'C:\fixture.sys'
            Resolve-DriverPath '' | Should -BeNullOrEmpty
        } $path $hash
    }

    It 'Evaluates OS revision from controlled metadata without querying the real host' {
        Mock Get-CimInstance -ModuleName StealthPrivesc { [pscustomobject]@{Version='10.0.17763';BuildNumber='17763';ProductType=3;OSArchitecture='64-bit'} }
        Mock Read-Registry -ModuleName StealthPrivesc { [pscustomobject]@{State='Present';Value=123} }
        & $script:ScannerModule {
            $context=Get-WindowsVersionContext
            $context.Version.ToString() | Should -Be '10.0.17763.123'
            $context.IsServer | Should -BeTrue
        }
        Should -Invoke Get-CimInstance -ModuleName StealthPrivesc -Times 1 -Exactly
        Mock Read-Registry -ModuleName StealthPrivesc { [pscustomobject]@{State='Unknown';Value=$null} }
        & $script:ScannerModule { { Get-WindowsVersionContext } | Should -Throw }
    }
}
