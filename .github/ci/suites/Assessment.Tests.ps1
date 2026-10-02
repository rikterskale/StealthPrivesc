Describe 'Assessment planning, caching, budgets and measurements' {
    BeforeAll {
        $script:Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        Import-Module (Join-Path $script:Root 'src/StealthPrivesc.psd1') -Force
        $script:ScannerModule = Get-Module StealthPrivesc
        if (-not ('StealthPrivesc.Console' -as [type])) { Add-Type -Path (Join-Path $script:Root 'src/NativeConsole.cs') }
    }
    BeforeEach {
        # The real launcher deliberately reloads the module; bind fixtures and
        # mocks to its current instance after each CLI preview test.
        $script:ScannerModule = Get-Module StealthPrivesc
        & $script:ScannerModule {
            $script:Context = @{MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=10;IncludeNetwork=$false;IncludeDomain=$false;IncludeSensitive=$false;SearchRoot=@();Cache=@{};Elevated=$false}
            $script:Current = [ordered]@{Id=1;Title='Fixture';Status='Completed';Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=New-Object 'System.Collections.Generic.List[string]';Diagnostics=New-Object 'System.Collections.Generic.List[object]'}
            $script:Current.Verification = New-CheckVerification 1
            $script:DiagnosticLogPath = $null
            Initialize-AssessmentFootprint
        }
    }

    It 'Previews selection and scope without native compilation or output creation' {
        Mock Add-Type -ModuleName StealthPrivesc { throw 'Planning must not compile.' }
        Mock Initialize-RequiredNativeSupport -ModuleName StealthPrivesc { throw 'Planning must not load support.' }
        $directory = Join-Path $TestDrive 'plan-output'
        $plan = & (Join-Path $script:Root 'Invoke-StealthPrivesc.ps1') -Plan -CheckId 47,72,132,142 -OutputDirectory $directory
        @($plan.Checks | Where-Object Enabled).Id | Should -Be 47
        $plan.RequiredNativeTypes.Count | Should -Be 0
        Test-Path -LiteralPath $directory | Should -BeFalse
    }

    It 'Identifies conditional helpers, native dependencies and explicit network destinations' {
        $plan = Get-AssessmentPlan -CheckId 7,43,72,132,148 -IncludeSensitive -IncludeNetwork
        $plan.RequiredNativeTypes | Should -Contain 'NativeInspection'
        $plan.PotentialHelperProcesses | Should -Contain 'net.exe'
        $plan.PotentialHelperProcesses | Should -Contain $(if($PSVersionTable.PSEdition-eq'Desktop'){'powershell.exe'}else{'pwsh.exe'})
        ($plan.PotentialNetworkDestinations -join ' ') | Should -Match '169\.254\.169\.254|www\.microsoft\.com'
        @($plan.Checks | Where-Object Enabled).Count | Should -Be 5
    }

    It 'Loads no support for an empty dependency set and reuses existing types' {
        Mock Add-Type -ModuleName StealthPrivesc { throw 'Unexpected compilation.' }
        & $script:ScannerModule { Initialize-RequiredNativeSupport @(); Initialize-RequiredNativeSupport Console }
        Should -Invoke Add-Type -ModuleName StealthPrivesc -Times 0 -Exactly
    }

    It 'Rejects untrusted precompiled support before loading and never falls back to source' {
        Mock Get-NativeSupportDefinition -ModuleName StealthPrivesc { [pscustomobject]@{Name='Console';TypeName='AssessmentUnsignedFixtureDoesNotExist';Source='NativeConsole.cs'} }
        Mock Get-AuthenticodeSignature -ModuleName StealthPrivesc { [pscustomobject]@{Status='NotSigned';SignerCertificate=$null} }
        Mock Add-Type -ModuleName StealthPrivesc { throw 'Untrusted code must not be loaded.' }
        $edition=if($PSVersionTable.PSEdition-eq'Desktop'){'Desktop'}else{'Core'}
        $architecture=if([Environment]::Is64BitProcess){'x64'}else{'x86'}
        $directory=Join-Path $TestDrive "unsigned/$edition/$architecture"
        [void][IO.Directory]::CreateDirectory($directory)
        [IO.File]::WriteAllText((Join-Path $directory 'Console.dll'),'Unsigned fixture')
        & $script:ScannerModule { param($Directory) $script:Context.NativeAssemblyDirectory=$Directory; { Initialize-RequiredNativeSupport Console } | Should -Throw '*valid trusted Authenticode*' } (Join-Path $TestDrive 'unsigned')
        Should -Invoke Add-Type -ModuleName StealthPrivesc -Times 0 -Exactly
    }

    It 'Rejects unknown component names' {
        & $script:ScannerModule { { Initialize-RequiredNativeSupport 'unknown' } | Should -Throw 'Unknown native*' }
    }

    It 'Loads the expected precompiled type after signature verification' {
        $edition=if($PSVersionTable.PSEdition-eq'Desktop'){'Desktop'}else{'Core'}
        $architecture=if([Environment]::Is64BitProcess){'x64'}else{'x86'}
        $directory=Join-Path $TestDrive "assemblies/$edition/$architecture"
        [void][IO.Directory]::CreateDirectory($directory)
        Add-Type -TypeDefinition 'public class AssessmentPrecompiledFixture {}' -OutputAssembly (Join-Path $directory 'Console.dll')
        Mock Get-NativeSupportDefinition -ModuleName StealthPrivesc { [pscustomobject]@{Name='Console';TypeName='AssessmentPrecompiledFixture';Source='NativeConsole.cs'} }
        # The real loader is exercised; only certificate trust is simulated.
        Mock Get-AuthenticodeSignature -ModuleName StealthPrivesc { [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='Fixture'}} }
        & $script:ScannerModule {
            param($Directory)
            $script:Context.NativeAssemblyDirectory=$Directory
            Initialize-RequiredNativeSupport Console
            ('AssessmentPrecompiledFixture'-as[type]) | Should -Not -BeNullOrEmpty
            (Measure-AssessmentFootprint).Counters.NativeLoads | Should -Be 1
        } (Join-Path $TestDrive 'assemblies')
        Should -Invoke Get-AuthenticodeSignature -ModuleName StealthPrivesc -Times 1 -Exactly
        # The loader must release its file handle before returning.
        Remove-Item -LiteralPath (Join-Path $directory 'Console.dll')
    }

    It 'Queries a shared process snapshot, owners and modules once per assessment' {
        Mock Get-CimInstance -ModuleName StealthPrivesc { New-CimInstance -ClassName Win32_Process -ClientOnly -Property @{ProcessId=[uint32]123;Name='fixture.exe'} }
        Mock Invoke-CimMethod -ModuleName StealthPrivesc { [pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'} }
        Mock Get-Process -ModuleName StealthPrivesc { [pscustomobject]@{Modules=@([pscustomobject]@{FileName='C:\fixture.dll';ModuleName='fixture.dll'})} }
        & $script:ScannerModule {
            1..2 | ForEach-Object {
                $process = @(Get-AssessmentProcesses)[0]
                (Get-AssessmentProcessOwner $process).Sid | Should -Be 'S-1-5-18'
                @(Get-AssessmentProcessModules 123)[0].FileName | Should -Be 'C:\fixture.dll'
            }
            (Measure-AssessmentFootprint).Counters.CacheHits | Should -Be 3
            $script:Context.Cache=@{}
            @(Get-AssessmentProcesses).Count | Should -Be 1
        }
        Should -Invoke Get-CimInstance -ModuleName StealthPrivesc -Times 2 -Exactly
        Should -Invoke Invoke-CimMethod -ModuleName StealthPrivesc -Times 1 -Exactly
        Should -Invoke Get-Process -ModuleName StealthPrivesc -Times 1 -Exactly
    }

    It 'Replays cached ACL limitations and preserves query provenance' {
        Mock Test-UncachedPathAccess -ModuleName StealthPrivesc {
            & (Get-Module StealthPrivesc) { Add-CheckCommand PowerShell 'Get-Acl -LiteralPath fixture'; Set-CheckPartial 'Fixture ACL unavailable.' }
            [pscustomobject]@{Path='fixture';Rights=@()}
        }
        & $script:ScannerModule {
            Test-PathAccess 'fixture' | Out-Null
            $script:Current.Id=2; $script:Current.Status='Completed'; $script:Current.Verification=New-CheckVerification 2
            Test-PathAccess 'fixture' | Out-Null
            $script:Current.Status | Should -Be 'Partial'
            $script:Current.Verification.Commands[0].State | Should -Be 'Reused'
            $script:Current.Verification.Commands[0].SourceCheckId | Should -Be 1
        }
        Should -Invoke Test-UncachedPathAccess -ModuleName StealthPrivesc -Times 1 -Exactly
    }

    It 'Caches ordinary policy values while excluding credential values' {
        Mock Read-UncachedRegistry -ModuleName StealthPrivesc { [pscustomobject]@{State='Present';Value='CANARY_CACHED_SECRET'} }
        & $script:ScannerModule {
            1..2 | ForEach-Object { Read-Registry 'HKLM:\SOFTWARE\Policies\Fixture' 'EnableLUA' | Out-Null; Read-Registry 'HKLM:\SOFTWARE\Policies\Fixture' 'DefaultPassword' | Out-Null }
            @($script:Context.Cache.Keys).Count | Should -Be 1
            @($script:Context.Cache.Keys)[0] | Should -Not -Match 'DefaultPassword'
            (Measure-AssessmentFootprint | ConvertTo-Json -Depth 6) | Should -Not -Match 'CANARY_CACHED_SECRET'
        }
        Should -Invoke Read-UncachedRegistry -ModuleName StealthPrivesc -Times 3 -Exactly
    }

    It 'Enforces finding output bounds and restores the previous collector budget' {
        & $script:ScannerModule {
            { Invoke-BudgetedCollector -MaximumOutputCharacters 1024 -Collector { Add-Evidence 'first' 'Small fixture'; Add-Evidence 'second' 'Fixture' @{Value=('x'*2000)} } } | Should -Throw '*output budget*'
            $script:Current.Findings.Count | Should -Be 1
            $script:Context.CollectorBudget | Should -BeNullOrEmpty
        }
    }

    It 'Stops a cooperative collector when its deadline expires' {
        & $script:ScannerModule {
            $clock=[Diagnostics.Stopwatch]::StartNew()
            { Invoke-BudgetedCollector -TimeoutSeconds 1 -Collector { while($true){Start-Sleep -Milliseconds 50;Assert-CollectorBudget} } } | Should -Throw '*time budget*'
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
            $script:Context.CollectorBudget | Should -BeNullOrEmpty
        }
    }

    It 'Terminates a sleeping helper and counts its successful launch' {
        & $script:ScannerModule {
            $clock=[Diagnostics.Stopwatch]::StartNew()
            { Invoke-BudgetedCollector -Payload 'Start-Sleep -Seconds 30' -HostPath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -TimeoutSeconds 1 } | Should -Throw '*time limit*'
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 4
            (Measure-AssessmentFootprint).Counters.HelperLaunches | Should -Be 1
        }
    }

    It 'Bounds helper output and retains no helper payload in counters' {
        & $script:ScannerModule {
            { Invoke-BudgetedCollector -Payload "'CANARY_HELPER_SECRET' * 1000" -MaximumOutputCharacters 1024 -HostPath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -TimeoutSeconds 10 } | Should -Throw '*output exceeds*'
            (Measure-AssessmentFootprint | ConvertTo-Json -Depth 6) | Should -Not -Match 'CANARY_HELPER_SECRET'
        }
    }

    It 'Carries hostile-looking pipe names as data without executing them' {
        Mock Invoke-BudgetedCollector -ModuleName StealthPrivesc {
            $tokens=$null; $errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseInput($Payload,[ref]$tokens,[ref]$errors)
            $errors.Count | Should -Be 0
            $command=$ast.Find({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName()-eq'ConvertFrom-Json'},$true)
            ($command.CommandElements[1].Value | ConvertFrom-Json).Target | Should -Be "\\.\pipe\O'Brien`$(throw 'CANARY_PIPE_SECRET')"
            '{"Name":"fixture","Descriptor":[1,2,3],"ServerProcessId":123,"OpenError":0}'
        }
        & $script:ScannerModule { (Invoke-IsolatedNativeQuery Pipe "\\.\pipe\O'Brien`$(throw 'CANARY_PIPE_SECRET')").ServerProcessId | Should -Be 123 }
    }

    It 'Measures actual UTF-8 file bytes and export writes without content' {
        $path=Join-Path $TestDrive 'measured.txt'
        & $script:ScannerModule {
            param($Path)
            $text='CANARY_FILE_SECRET'+[char]0x03bb
            Write-AssessmentText $Path $text
            Read-AssessmentText $Path | Should -BeExactly $text
            $metrics=Measure-AssessmentFootprint
            $metrics.Counters.FileBytesRead | Should -Be ([Text.Encoding]::UTF8.GetByteCount($text))
            $metrics.Counters.OutputBytesWritten | Should -Be $metrics.Counters.FileBytesRead
            $metrics.Counters.OutputWrites | Should -Be 1
            ($metrics|ConvertTo-Json -Depth 6) | Should -Not -Match 'CANARY_FILE_SECRET'
            Add-AssessmentCounter NetworkRequests
            $metrics.Counters.ContainsKey('NetworkRequests') | Should -BeFalse
        } $path
    }

    It 'Stops file reads at the size budget and reports the numeric byte count' {
        $path=Join-Path $TestDrive 'oversized.bin'
        [IO.File]::WriteAllBytes($path,(New-Object byte[] 2048))
        & $script:ScannerModule {
            param($Path)
            { Read-AssessmentBytes $Path } | Should -Throw '*read budget*'
            (Measure-AssessmentFootprint).Counters.FileBytesRead | Should -Be 1025
        } $path
    }

    It 'Recognizes nested helper budget exceptions without exposing their messages' {
        & $script:ScannerModule {
            $inner=[TimeoutException]::new('CANARY_BUDGET_SECRET');$inner.Data['StealthPrivesc.BudgetExceeded']=$true;$inner.Data['StealthPrivesc.BudgetKind']='CollectorTime'
            $outer=[InvalidOperationException]::new('CANARY_BUDGET_SECRET',$inner)
            Test-CollectorBudgetException $outer | Should -BeTrue
            $record=[Management.Automation.ErrorRecord]::new($outer,'fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
            $diagnostic=New-AssessmentDiagnostic 'Collection budget reached.' -ErrorRecord $record
            $diagnostic.Code | Should -Be 'CollectorBudget'
            ($diagnostic|ConvertTo-Json -Depth 6) | Should -Not -Match 'CANARY_BUDGET_SECRET'
        }
    }

    It 'Preserves new budget and assembly options in check reruns' {
        & $script:ScannerModule {
            $script:Context.CollectorTimeoutSeconds=30; $script:Context.MaxCollectorOutputCharacters=2048; $script:Context.NativeAssemblyDirectory="C:\O'Brien\assemblies"
            $command=(New-CheckVerification 47).RerunCommand
            $command | Should -Match '-CollectorTimeoutSeconds 30 -MaxCollectorOutputCharacters 2048'
            $command | Should -Match "-NativeAssemblyDirectory 'C:\\O''Brien\\assemblies'"
        }
    }

    It 'Exports the saved footprint and keeps timeout findings as partial while continuing' {
        Mock Invoke-Check -ModuleName StealthPrivesc {
            & (Get-Module StealthPrivesc) {
                param($CheckId)
                if($CheckId-eq47){Add-Evidence 'fixture' 'Retained before timeout';$failure=[TimeoutException]::new('Fixture timeout');$failure.Data['StealthPrivesc.BudgetExceeded']=$true;throw $failure}
                Add-Evidence 'fixture' 'Next check completed'
            } $Id
        }
        $directory=Join-Path $TestDrive 'assessment'
        $report=Invoke-StealthPrivesc -CheckId 47,48 -OutputDirectory $directory -PassThru 3>$null
        $report.Checks[0].Status | Should -Be 'Partial'
        $report.Checks[0].Findings.Count | Should -Be 1
        $report.Checks[1].Status | Should -Be 'Completed'
        $report.Footprint.Counters.FindingBytes | Should -BeGreaterThan 0
        (Get-Content (Get-ChildItem $directory -Filter '*.json').FullName -Raw | ConvertFrom-Json).Footprint | Should -Not -BeNullOrEmpty
        (Measure-AssessmentFootprint).Counters.OutputWrites | Should -BeGreaterThan $report.Footprint.Counters.OutputWrites
    }
}
