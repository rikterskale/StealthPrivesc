[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','diagnoses',Justification='Pester consumes this discovery data in -ForEach.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','gates',Justification='Pester consumes this discovery data in -ForEach.')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $diagnoses = @(
        @{Exception=[UnauthorizedAccessException]::new('CANARY_EXCEPTION_SECRET');Code='AccessDenied'},
        @{Exception=[IO.FileNotFoundException]::new('CANARY_EXCEPTION_SECRET');Code='ResourceNotFound'},
        @{Exception=[FormatException]::new('CANARY_EXCEPTION_SECRET');Code='InvalidData'},
        @{Exception=[PlatformNotSupportedException]::new('CANARY_EXCEPTION_SECRET');Code='DependencyUnavailable'},
        @{Exception=[TimeoutException]::new('CANARY_EXCEPTION_SECRET');Code='CommandTimeout'},
        @{Exception=[Net.WebException]::new('CANARY_EXCEPTION_SECRET');Code='ConnectionFailed'}
    )
    $gates = @(@{Id=67;Switch='IncludeSensitive'},@{Id=70;Switch='IncludeDomain'},@{Id=132;Switch='IncludeNetwork'})
}

Describe 'Offline diagnostics, limits and redaction' {
    BeforeAll {
        $script:Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        Import-Module (Join-Path $script:Root 'src/StealthPrivesc.psd1') -Force
        $script:ScannerModule = Get-Module StealthPrivesc
    }
    BeforeEach {
        & $script:ScannerModule {
            $script:Context=@{MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=1;IncludeNetwork=$false;IncludeDomain=$false;IncludeSensitive=$false;SearchRoot=@();Cache=@{};Elevated=$false}
            $script:Current=[ordered]@{Id=1;Title='Fixture';Status='Completed';Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=New-Object 'System.Collections.Generic.List[string]';Diagnostics=New-Object 'System.Collections.Generic.List[object]'}
            $script:Current.Verification=New-CheckVerification 1
            $script:DiagnosticLogPath=$null
        }
    }

    It 'Classifies <Code> without leaking exception content' -ForEach $diagnoses {
        & $script:ScannerModule {
            param($Failure,$Expected)
            $record=[Management.Automation.ErrorRecord]::new($Failure,'CANARY_EXCEPTION_SECRET',[Management.Automation.ErrorCategory]::NotSpecified,'CANARY_EXCEPTION_SECRET')
            $diagnostic=New-AssessmentDiagnostic 'Synthetic input could not be read.' -ErrorRecord $record -CheckId 1
            $diagnostic.Code | Should -Be $Expected
            $diagnostic.SuggestedActions.Count | Should -BeGreaterThan 0
            ($diagnostic | ConvertTo-Json -Depth 8) | Should -Not -Match 'CANARY_EXCEPTION_SECRET'
            Format-AssessmentDiagnostic $diagnostic | Should -Not -Match 'CANARY_EXCEPTION_SECRET'
            (ConvertTo-DiagnosticHtml @($diagnostic) -join '') | Should -Not -Match 'CANARY_EXCEPTION_SECRET'
        } $Exception $Code
    }

    It 'Explains the scope gate for check <Id>' -ForEach $gates {
        & $script:ScannerModule {
            param($CheckId,$Flag)
            $script:Current.Id=$CheckId
            Set-CheckSkipped "Requires -$Flag." -SkipReason ScopeNotEnabled -RequiredSwitch $Flag
            $script:Current.Status | Should -Be 'Skipped'
            $script:Current.Diagnostics[0].RequiredSwitch | Should -Be $Flag
            $summary=@(Get-SkippedCheckSummary @([pscustomobject]$script:Current))
            $summary.Count | Should -Be 1
            $summary[0].RetryCommand | Should -Match "-CheckId $CheckId -$Flag"
        } $Id $Switch
    }

    It 'Enforces item limits and replays incomplete cached results' {
        & $script:ScannerModule {
            1..11 | ForEach-Object { Add-Evidence "item $_" 'Synthetic fixture' }
            $script:Current.Findings.Count | Should -Be 10
            $script:Current.Status | Should -Be 'Partial'
            @(Get-Limited @(1..11)).Count | Should -Be 10
            Get-Cached 'fixture' { Set-CheckPartial 'Fixture resource inaccessible.'; 42 } | Out-Null
            $script:Current.Status='Completed'; $script:Current.Limitations.Clear()
            $script:Current.Verification.Commands.Clear()
            @(Get-Cached 'fixture' { throw 'Unexpected cache miss' })[0] | Should -Be 42
            $script:Current.Status | Should -Be 'Partial'
        }
    }

    It 'Rejects remote paths without opt-in and accepts them only with recorded scope' {
        & $script:ScannerModule {
            Test-AllowedLocalPath '\\example.test\share\fixture' | Should -BeFalse
            Test-AllowedLocalPath '\\?\UNC\example.test\share\fixture' | Should -BeFalse
            $script:Context.IncludeNetwork=$true
            Test-AllowedLocalPath '\\example.test\share\fixture' | Should -BeTrue
        }
    }

    It 'Uses default search roots for omitted or empty selectors and preserves explicit roots' {
        & $script:ScannerModule {
            $expected = @($env:ProgramData,(Join-Path $env:USERPROFILE 'Documents'))
            foreach ($empty in @($null,@(),@($null),@(''))) {
                $script:Context.SearchRoot = $empty
                @(Get-SearchRoots) | Should -Be $expected
            }
            $script:Context.SearchRoot = @('C:\CI fixture one','C:\CI fixture two')
            @(Get-SearchRoots) | Should -Be $script:Context.SearchRoot
        }
    }

    It 'Retains Recall task evidence without claiming patch applicability when reference data is absent' {
        Mock Get-ReferenceDocument -ModuleName StealthPrivesc { $null }
        Mock Get-Tasks -ModuleName StealthPrivesc {
            [pscustomobject]@{TaskPath='\Recall\';TaskName='PolicyConfiguration';State='Ready';Principal=[pscustomobject]@{UserId='SYSTEM';RunLevel='Highest'}}
        }
        & $script:ScannerModule {
            $script:Context.VulnerabilityDatabasePath = 'missing-ci-reference.json'
            Invoke-ExecutionAnalysisCheck 27
            $script:Current.Status | Should -Be 'Partial'
            $script:Current.Findings.Count | Should -Be 1
            $script:Current.Findings[0].Severity | Should -Be 'Information'
            @($script:Current.Findings[0].Evidence.PatchAssessment).Count | Should -Be 0
        }
    }

    It 'Finds synthetic secret indicators without copying matched values' {
        $path=Join-Path $TestDrive 'settings.env'
        [IO.File]::WriteAllText($path,'password=CANARY_FILE_SECRET; api_key=CANARY_FILE_SECRET')
        & $script:ScannerModule {
            param($Path)
            Find-SecretMarkers $Path
            $script:Current.Findings.Count | Should -Be 1
            ($script:Current.Findings | ConvertTo-Json -Depth 8) | Should -Not -Match 'CANARY_FILE_SECRET'
            $script:Current.Findings[0].Evidence.Markers | Should -Contain 'PasswordAssignment'
        } $path
    }

    It 'Discloses oversized files and prohibits XML external entities' {
        $large=Join-Path $TestDrive 'large.txt'; [IO.File]::WriteAllText($large,('x'*2048))
        $xml=Join-Path $TestDrive 'hostile.xml'; [IO.File]::WriteAllText($xml,'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><r>&x;</r>')
        & $script:ScannerModule {
            param($Large,$Xml)
            Find-SecretMarkers $Large
            $script:Current.Status | Should -Be 'Partial'
            { Read-SafeXml $Xml } | Should -Throw
        } $large $xml
    }

    It 'Preserves numeric exit and timeout metadata without running helper processes' {
        & $script:ScannerModule {
            $exception=[InvalidOperationException]::new('CANARY_EXCEPTION_SECRET'); $exception.Data['StealthPrivesc.ExitCode']=7
            $record=[Management.Automation.ErrorRecord]::new($exception,'Fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
            (New-AssessmentDiagnostic 'Fixture process failure.' -ErrorRecord $record).TechnicalDetails.ExitCode | Should -Be 7
            $exception=[TimeoutException]::new('CANARY_EXCEPTION_SECRET'); $exception.Data['StealthPrivesc.TimeoutSeconds']=1
            $record=[Management.Automation.ErrorRecord]::new($exception,'Fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
            (New-AssessmentDiagnostic 'Fixture timeout.' -ErrorRecord $record).TechnicalDetails.TimeoutSeconds | Should -Be 1
        }
    }
}

Describe 'Verification metadata remains literal and bounded' {
    BeforeAll {
        Import-Module ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../src/StealthPrivesc.psd1'))) -Force
        $script:ScannerModule=Get-Module StealthPrivesc
    }

    It 'Round-trips quotes, Unicode and executable-looking path text as literals' {
        & $script:ScannerModule {
            foreach ($value in @("C:\O'Brien\fixture",'C:\literal $(throw 1); text',('C:\smart'+[char]0x2019+'quote'))) {
                $literal=ConvertTo-VerificationLiteral $value
                $tokens=$null; $errors=$null
                $ast=[Management.Automation.Language.Parser]::ParseInput($literal,[ref]$tokens,[ref]$errors)
                $errors.Count | Should -Be 0
                $strings=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]},$true))
                $strings.Count | Should -Be 1
                $strings[0].Value | Should -BeExactly $value
                @($ast.FindAll({param($node) $node -is [Management.Automation.Language.SubExpressionAst]},$true)).Count | Should -Be 0
            }
        }
    }

    It 'Preserves typed scope and paths in rerun metadata without executing it' {
        & $script:ScannerModule {
            $script:Context=@{IncludeNetwork=$true;IncludeDomain=$false;IncludeSensitive=$false;MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=1;SearchRoot=@("C:\O'Brien");DriverDatabasePath='relative.json';VulnerabilityDatabasePath='updates.json'}
            $record=New-CheckVerification 47
            $record.RerunCommand | Should -Match '-IncludeNetwork'
            $record.RerunCommand | Should -Not -Match '-IncludeDomain|-IncludeSensitive'
            $record.RerunCommand | Should -Match "-DriverDatabasePath 'relative.json'"
            $record.CollectorStarted | Should -BeFalse
            $record.SourceReferences=@([pscustomobject]@{Source='src/fixture';Line=1;Expression='<script>bad</script>'})
            ConvertTo-VerificationHtml $record | Should -Not -Match '<script>'
        }
    }

    It 'Deduplicates command records, replays cache provenance, and discloses overflow' {
        & $script:ScannerModule {
            $script:Context=@{IncludeNetwork=$false;IncludeDomain=$false;IncludeSensitive=$false;MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=1;SearchRoot=@();Cache=@{}}
            $script:Current=[ordered]@{Id=11;Title='Fixture';Status='Completed';Limitations=New-Object 'System.Collections.Generic.List[string]';Diagnostics=New-Object 'System.Collections.Generic.List[object]';Verification=(New-CheckVerification 11)}
            Get-Cached 'commands' { Add-CheckCommand PowerShell 'synthetic query'; 42 } | Out-Null
            $script:Current.Id=12; $script:Current.Verification=New-CheckVerification 12
            Get-Cached 'commands' { throw 'Unexpected probe' } | Out-Null
            $script:Current.Verification.Commands[0].State | Should -Be 'Reused'
            $script:Current.Verification.Commands[0].SourceCheckId | Should -Be 11
            Add-CheckCommand PowerShell 'same'; Add-CheckCommand PowerShell 'same'
            $script:Current.Verification.Commands[1].Count | Should -Be 2
            1..1000 | ForEach-Object { Add-CheckCommand PowerShell "synthetic query $_" }
            $script:Current.Verification.Commands.Count | Should -Be 1000
            $script:Current.Verification.OmittedCommandCount | Should -Be 2
        }
    }

    It 'Redacts arbitrary arguments and preserves only exact fixed query strings' {
        & $script:ScannerModule {
            Get-HelperVerificationArguments 'C:\Windows\net.exe' 'accounts' | Should -BeExactly 'accounts'
            Get-HelperVerificationArguments 'C:\Windows\net.exe' 'accounts CANARY_ARGUMENT_SECRET' | Should -Not -Match 'CANARY_ARGUMENT_SECRET'
            Get-HelperVerificationArguments 'fixture.exe' 'CANARY_ARGUMENT_SECRET' | Should -Not -Match 'CANARY_ARGUMENT_SECRET'
        }
    }
}
