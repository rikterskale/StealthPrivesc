[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scripts',Justification='Pester consumes this discovery data in -ForEach.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','native',Justification='Pester consumes this discovery data in -ForEach.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','checks',Justification='Pester consumes this discovery data in -ForEach.')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    $scripts = @(Get-ChildItem $root -File; Get-ChildItem (Join-Path $root 'src') -Recurse -File; Get-ChildItem (Join-Path $root '.github/ci') -Recurse -File) |
        Where-Object Extension -in @('.ps1','.psm1','.psd1') | ForEach-Object { @{Name=$_.FullName.Substring($root.Length+1);Path=$_.FullName} }
    $native = @(Get-ChildItem (Join-Path $root 'src') -Filter '*.cs' -File | ForEach-Object { @{Name=$_.Name;Path=$_.FullName} })
    $checks = @(Get-Content (Join-Path $root 'data/checks.json') -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ } | ForEach-Object { @{Id=$_.Id} })
}

Describe 'Source, manifest and dispatch contracts' {
    BeforeAll {
        $script:Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        Import-Module (Join-Path $script:Root 'src/StealthPrivesc.psd1') -Force -ErrorAction Stop
        $script:ScannerModule = Get-Module StealthPrivesc
    }

    It 'Parses <Name> on the actual runtime' -ForEach $scripts {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0 -Because ($errors.Message -join '; ')
    }

    It 'Compiles <Name> without executing its APIs' -ForEach $native {
        $options = @{Path=$Path;ErrorAction='Stop'}
        if ($Name -eq 'NativeWifi.cs' -and $PSVersionTable.PSEdition -eq 'Desktop') { $options.ReferencedAssemblies = @('System.Xml.dll') }
        { Add-Type @options } | Should -Not -Throw
    }

    It 'Exports exactly the manifest API and agrees with the report version' {
        $manifest = Test-ModuleManifest (Join-Path $script:Root 'src/StealthPrivesc.psd1')
        $expected = (Import-PowerShellDataFile (Join-Path $script:Root 'src/StealthPrivesc.psd1')).FunctionsToExport
        @(Compare-Object $expected @($script:ScannerModule.ExportedFunctions.Keys)).Count | Should -Be 0
        $text = Get-Content (Join-Path $script:Root 'src/StealthPrivesc.psm1') -Raw
        $text | Should -Match ("ToolVersion = '" + [regex]::Escape($manifest.Version.ToString()) + "'")
        $text | Should -Match "SchemaVersion = '1\.5'"
    }

    It 'Routes check <Id> to an existing collector with source references' -ForEach $checks {
        & $script:ScannerModule {
            param($CheckId)
            $collector = Get-CheckCollector $CheckId
            Get-Command $collector -CommandType Function | Should -Not -BeNullOrEmpty
            $references = @(Get-CheckSourceReferences $collector $CheckId)
            $references.Count | Should -BeGreaterThan 0
            @($references | Where-Object { $_.Line -lt 1 -or -not $_.Source.StartsWith('src/') }).Count | Should -Be 0
        } $Id
    }

    It 'Rejects unknown dispatch IDs' {
        & $script:ScannerModule { { Get-CheckCollector 0 } | Should -Throw; { Get-CheckCollector 149 } | Should -Throw }
    }

    It 'Does not expose host-configuration mutators in PowerShell collectors' {
        $mutators = '^(Set-Acl|Set-ItemProperty|New-Service|Set-Service|Start-Service|Stop-Service|Restart-Service|Start-ScheduledTask|Set-ScheduledTask|Register-ScheduledTask|Set-AppLockerPolicy|Set-MpPreference|Add-MpPreference|Invoke-Expression)$'
        $found = @(foreach ($file in Get-ChildItem (Join-Path $script:Root 'src') -Recurse -Filter '*.ps1') {
            $tokens=$null; $errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
            $ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) |
                Where-Object { $_.GetCommandName() -match $mutators }
        })
        $found.Count | Should -Be 0
    }

    It 'Reuses compiled support across repeated native and PowerShell helper calls' {
        Mock Add-Type -ModuleName StealthPrivesc { throw 'Native support was already compiled.' }
        $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        & $script:ScannerModule {
            param($HostPath)
            $script:Context = @{CommandTimeoutSeconds=15}
            $script:Current = @{}
            1..2 | ForEach-Object {
                (Invoke-ReadOnlyCommand -FileName (Join-Path $env:SystemRoot 'System32/cmd.exe') -Arguments '/d /c echo CI_HELPER_OUTPUT').Trim() | Should -BeExactly 'CI_HELPER_OUTPUT'
                (Invoke-ReadOnlyCommand -HostPath $HostPath -Payload "[System.Console]::WriteLine('CI_HELPER_OUTPUT')`n").Trim() | Should -BeExactly 'CI_HELPER_OUTPUT'
            }
        } $hostPath
    }
}

Describe 'Real CLI selection without running collectors' {
    BeforeAll { $script:Launcher = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../Invoke-StealthPrivesc.ps1')) }

    It 'Lists every catalog entry through the actual launcher' {
        $rows = @(& $script:Launcher -ListChecks)
        $rows.Count | Should -Be 148
        @($rows.Id | Sort-Object -Unique).Count | Should -Be 148
    }

    It 'Uses the intersection of selectors and deduplicates requested IDs' {
        $rows = @(& $script:Launcher -ListChecks -Category Identity -CheckId 1,1,2,11)
        $rows.Count | Should -Be 2
        $rows[0].Id | Should -Be 1
        $rows[1].Id | Should -Be 2
    }

    It 'Returns an actual empty selection rather than a null placeholder count' {
        @(& $script:Launcher -ListChecks -Category Services -CheckId 1).Count | Should -Be 0
    }

    It 'Rejects invalid selectors and parameter bounds' {
        { & $script:Launcher -ListChecks -CheckId 0 3>$null } | Should -Throw
        { & $script:Launcher -ListChecks -Category 'Unknown' 3>$null } | Should -Throw
        { & $script:Launcher -ListChecks -MaxItems 9 } | Should -Throw
        { & $script:Launcher -ListChecks -CommandTimeoutSeconds 301 } | Should -Throw
    }
}
