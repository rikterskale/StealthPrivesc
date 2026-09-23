#requires -Version 5.1
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'NOT RUN: Test-AttackPaths includes Windows runner integration. Run tools/Test-Project.ps1 on 64-bit Windows with PowerShell 5.1 and 7.'
    exit 2
}
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
& (Get-Module StealthPrivesc) {
    $script:PathAssertions=0
    function Assert-Path([bool]$Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" }; $script:PathAssertions++ }
    function New-Finding([string]$Target,[hashtable]$Evidence) { [pscustomobject]@{Target=$Target;Evidence=$Evidence;Observation='Synthetic fixture';Severity='Medium';Remediation='Restrict unintended control.'} }
    function New-PathFixture {
        $data=@{
            11=@((New-Finding 'AcmeService' @{Account='LocalSystem';Executable='C:\Program Files\Acme\svc.exe';StartMode='Auto';State='Stopped'}))
            12=@((New-Finding 'ACMESERVICE' @{Account='NT AUTHORITY\SYSTEM';Right='ChangeConfig';ElevatedToken=$false}))
            14=@((New-Finding 'service registry' @{Path='Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcmeService';Rights=@('SetValue')}))
            16=@((New-Finding 'service file' @{Path='c:\program files\acme\SVC.EXE';Rights=@('WriteDataOrAddFile')}))
            17=@((New-Finding 'AcmeService' @{Account='LocalSystem';Executable='C:\Program Files\Acme\svc.exe';InterceptionCandidate='C:\Program.exe'}),(New-Finding 'C:\Program.exe' @{Path='C:\Program.exe';Rights=@('WriteDataOrAddFile')}))
            20=@((New-Finding 'AcmeService' @{Right='Start';State='Stopped'}))
            22=@((New-Finding '\Acme\Nightly' @{Account='S-1-5-18';State='Ready';Settings=@{Enabled=$true};Actions=@(@{Type='Execute';Command=@{Executable='C:\Tasks\job.exe'}})}))
            23=@((New-Finding 'task file' @{Path='C:\Tasks\job.exe';Rights=@('WriteDataOrAddFile')}))
            24=@((New-Finding '\ACME\NIGHTLY' @{Right='UpdateTask';Context=@{Account='SYSTEM';Enabled=$true}}))
        }
        [pscustomobject]@{
            SchemaVersion='1.4';Notice='Synthetic demonstration; no host findings.';Computer='fixture';User='fixture\reader';UserSid='S-1-5-21-100-200-300-1001';Elevated=$false
            StartedUtc='fixture';RunStatus='Completed';Summary=@{Completed=9;Partial=0;Error=0;Skipped=0;Unsupported=0}
            Checks=@(foreach ($id in $data.Keys | Sort-Object) { [pscustomobject]@{Id=$id;Title="Fixture $id";Category='Fixture';Coverage='Implemented';Status='Completed';Findings=$data[$id];Limitations=@();Verification=[pscustomobject]@{RerunCommand=".\Invoke-StealthPrivesc.ps1 -CheckId $id -PassThru";WorkingDirectory='C:\scanner'}} })
        }
    }
    function Get-FixtureCheck([object]$Report,[int]$Id) { $Report.Checks | Where-Object Id -eq $Id }
    $fixture=New-PathFixture
    $before=$fixture | ConvertTo-Json -Depth 20
    $analysis=Get-StealthPrivescAttackPathAnalysis $fixture
    Assert-Path ($analysis.Status -eq 'Completed' -and $analysis.Paths.Count -eq 6) 'All six rules must correlate realistic structured evidence.'
    Assert-Path (($fixture | ConvertTo-Json -Depth 20) -ceq $before) 'Analysis must not mutate evidence.'
    Assert-Path (@($analysis.Paths | Where-Object { $_.EvidenceReferences.Count -lt 2 -or $_.Status -ne 'Candidate' -or $_.Prerequisites.Count -lt 2 }).Count -eq 0) 'Every candidate must retain supporting references and unresolved prerequisites.'
    $config=$analysis.Paths | Where-Object RuleId -eq ServiceConfiguration
    Assert-Path ($config.Confidence -eq 'Corroborated' -and $config.Priority -eq 'High' -and $config.Steps[2].Description -match 'Start') 'Direct service control has corroborated evidence and observed trigger context.'
    Assert-Path ($config.VerificationCommands.Count -eq 3) 'Supporting check rerun commands are retained.'
    Assert-Path (($analysis.Paths | Where-Object RuleId -eq TaskDefinition).Confidence -eq 'Conditional') 'Task DACL access alone does not establish scheduler update authorization.'
    $roundtrip=$before | ConvertFrom-Json
    $offline=Get-StealthPrivescAttackPathAnalysis $roundtrip
    Assert-Path (($offline.Paths.Id -join ',') -ceq ($analysis.Paths.Id -join ',')) 'Saved JSON and live reports produce identical path IDs and ordering.'
    $roundtrip.Checks=@($roundtrip.Checks | Sort-Object Id -Descending)
    Assert-Path (((Get-StealthPrivescAttackPathAnalysis $roundtrip).Paths.Id -join ',') -ceq ($analysis.Paths.Id -join ',')) 'Check order does not change IDs or ranking.'
    $limited=Get-StealthPrivescAttackPathAnalysis $fixture -MaxPaths 1
    Assert-Path ($limited.Paths.Count -eq 1 -and $limited.TotalCandidates -eq 6 -and $limited.OmittedPaths -eq 5 -and $limited.Status -eq 'Partial') 'Output truncation is counted and disclosed.'
    $limited=Get-StealthPrivescAttackPathAnalysis $fixture -MaxEvidence 1
    Assert-Path ($limited.EvidenceTruncated -and $limited.Status -eq 'Partial' -and $limited.Paths.Count -eq 0) 'Evidence limits cannot manufacture a chain from missing inputs.'
    $empty=New-PathFixture
    foreach ($check in $empty.Checks) { $check.Findings=@() }
    Assert-Path ((Get-StealthPrivescAttackPathAnalysis $empty).Paths.Count -eq 0) 'Empty inventories and missing ACLs produce no candidates.'
    $missing=New-PathFixture
    (Get-FixtureCheck $missing 12).Status='Skipped'
    $result=Get-StealthPrivescAttackPathAnalysis $missing
    Assert-Path (@($result.Paths | Where-Object RuleId -eq ServiceConfiguration).Count -eq 0 -and ($result.RuleCoverage | Where-Object RuleId -eq ServiceConfiguration).MissingChecks -contains 12) 'Skipped evidence is not consumed and required inputs are identified.'
    $partial=New-PathFixture
    (Get-FixtureCheck $partial 12).Status='Error'
    Assert-Path (((Get-StealthPrivescAttackPathAnalysis $partial).Paths | Where-Object RuleId -eq ServiceConfiguration).Confidence -eq 'Limited') 'Retained evidence from a failed check is explicitly downgraded.'
    $partial=New-PathFixture; $partial.RunStatus='Failed'
    Assert-Path (@((Get-StealthPrivescAttackPathAnalysis $partial).Paths | Where-Object Confidence -ne Limited).Count -eq 0) 'A failed run lowers confidence in every candidate.'
    $admin=New-PathFixture; $admin.Elevated=$true
    $result=Get-StealthPrivescAttackPathAnalysis $admin
    Assert-Path (@($result.Paths | Where-Object { $_.Assessment -ne 'PrivilegedAuditExposure' -or $_.Priority -ne 'Information' }).Count -eq 0) 'Already elevated access is not presented as new privilege escalation.'
    $unknown=New-PathFixture; $unknown.Elevated=$null
    Assert-Path (@((Get-StealthPrivescAttackPathAnalysis $unknown).Paths | Where-Object Assessment -ne UnknownStartingPrivilege).Count -eq 0) 'Unknown starting privilege remains unknown.'
    $disabled=New-PathFixture
    (Get-FixtureCheck $disabled 11).Findings[0].Evidence.StartMode='Disabled'
    (Get-FixtureCheck $disabled 22).Findings[0].Evidence.Settings.Enabled=$false
    Assert-Path ((Get-StealthPrivescAttackPathAnalysis $disabled).Paths.Count -eq 0) 'Disabled execution objects do not produce active candidates.'
    $identity=New-PathFixture
    (Get-FixtureCheck $identity 11).Findings[0].Evidence.Account='ACME\SYSTEM-adjacent'
    (Get-FixtureCheck $identity 22).Findings[0].Evidence.Account='SYSTEM-operator'
    Assert-Path ((Get-StealthPrivescAttackPathAnalysis $identity).Paths.Count -eq 0) 'Account-name substrings cannot establish a SYSTEM identity.'
    $unrelated=New-PathFixture
    (Get-FixtureCheck $unrelated 12).Findings[0].Target='AcmeServiceBackup'
    (Get-FixtureCheck $unrelated 16).Findings[0].Evidence.Path='C:\Program Files\Acme Backup\svc.exe'
    (Get-FixtureCheck $unrelated 14).Findings[0].Evidence.Path='HKLM:\SYSTEM\CurrentControlSet\Services\AcmeServiceExtra'
    (Get-FixtureCheck $unrelated 24).Findings[0].Target='\Other\Nightly'
    $result=Get-StealthPrivescAttackPathAnalysis $unrelated
    Assert-Path (@($result.Paths | Where-Object RuleId -in @('ServiceConfiguration','ServiceImage','ServiceRegistry','TaskDefinition')).Count -eq 0) 'Similar names, filenames and folder prefixes never establish object joins.'
    $parent=New-PathFixture
    (Get-FixtureCheck $parent 16).Findings[0].Evidence.Path='C:\Program Files\Acme'
    Assert-Path (((Get-StealthPrivescAttackPathAnalysis $parent).Paths | Where-Object RuleId -eq ServiceImage).Confidence -eq 'Conditional') 'Immediate-parent control remains conditional.'
    foreach ($unsafe in @('..\svc.exe','%ProgramFiles%\Acme\svc.exe','C:\Program Files\Acme\..\svc.exe')) {
        $relative=New-PathFixture
        (Get-FixtureCheck $relative 11).Findings[0].Evidence.Executable=$unsafe
        (Get-FixtureCheck $relative 16).Findings[0].Evidence.Path=$unsafe
        Assert-Path (@((Get-StealthPrivescAttackPathAnalysis $relative).Paths | Where-Object RuleId -eq ServiceImage).Count -eq 0) 'Unresolved paths are not expanded against the analyst host.'
    }
    $ambiguous=New-PathFixture
    $inventory=Get-FixtureCheck $ambiguous 11
    $inventory.Findings=@($inventory.Findings)+@($inventory.Findings[0])
    Assert-Path (@((Get-StealthPrivescAttackPathAnalysis $ambiguous).Paths | Where-Object { $_.RuleId.StartsWith('Service') }).Count -eq 0) 'Ambiguous duplicate execution objects are not joined.'
    & {
        function Get-CimInstance { throw 'Unexpected probe' }
        function Read-Registry { throw 'Unexpected probe' }
        function Invoke-ReadOnlyCommand { throw 'Unexpected execution' }
        Assert-Path ((Get-StealthPrivescAttackPathAnalysis (New-PathFixture)).Paths.Count -eq 6) 'Analysis only consumes existing evidence.'
    }
    $hostile=New-PathFixture
    (Get-FixtureCheck $hostile 11).Findings[0].Target='<script>alert(1)</script>'
    (Get-FixtureCheck $hostile 12).Findings[0].Target='<script>alert(1)</script>'
    (Get-FixtureCheck $hostile 12).Findings[0].Evidence['Secret']='NEVER_COPY_SOURCE_SECRET'
    $result=Get-StealthPrivescAttackPathAnalysis $hostile
    $html=ConvertTo-AttackPathHtml $result
    Assert-Path ($html -notmatch '<script>' -and $html -match '&lt;script&gt;') 'Attack-path HTML escapes host-supplied object names.'
    Assert-Path (($result | ConvertTo-Json -Depth 12) -notmatch 'NEVER_COPY_SOURCE_SECRET') 'The engine copies explicit metadata, not arbitrary evidence values.'

    $scratch=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-paths-'+[Guid]::NewGuid().ToString('N'))
    try {
        # Exercise report rendering with synthetic paths and real evidence anchors.
        $fixture=New-PathFixture
        foreach ($check in $fixture.Checks) { $check.PSObject.Properties.Remove('Verification') }
        $fixture | Add-Member NoteProperty AttackPathAnalysis (Get-StealthPrivescAttackPathAnalysis $fixture)
        Export-Assessment $fixture $scratch
        $saved=Get-Content (Get-ChildItem $scratch -Filter '*.html').FullName -Raw
        Assert-Path ($saved -match 'Attack path candidates' -and $saved -match 'href="#check-12-finding-0"' -and $saved -match 'id="check-12-finding-0"') 'HTML candidates link to actual source findings.'
        $decoded=Get-Content (Get-ChildItem $scratch -Filter '*.json').FullName -Raw | ConvertFrom-Json
        Assert-Path ($decoded.AttackPathAnalysis.Paths.Count -eq 6) 'JSON persists structured paths.'
        & {
            function Invoke-Check { param([int]$Id) Add-Evidence 'fixture' 'No mutation.' }
            $run=Invoke-StealthPrivesc -CheckId 1 -PassThru
            Assert-Path ($run.AttackPathAnalysis.Status -eq 'Partial' -and $run.AttackPathAnalysis.Paths.Count -eq 0) 'Post-scan integration reports missing inputs for a narrow scan.'
            function Get-StealthPrivescAttackPathAnalysis { param($Report) throw 'NEVER_DISCLOSE_ANALYSIS_ERROR' }
            $failed=Invoke-StealthPrivesc -CheckId 1 -PassThru -OutputDirectory (Join-Path $scratch 'failure') 3>$null
            Assert-Path ($failed.AttackPathAnalysis.Status -eq 'Error' -and $failed.Checks[0].Findings.Count -eq 1) 'Correlation failure preserves and exports original findings.'
            Assert-Path (($failed | ConvertTo-Json -Depth 16) -notmatch 'NEVER_DISCLOSE_ANALYSIS_ERROR') 'Analysis failures retain safe diagnostics only.'
        }
        Write-Host "PASS: $script:PathAssertions attack-path assertions; skipped test groups: 0."
    } finally {
        $resolved=[IO.Path]::GetFullPath($scratch)
        $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^StealthPrivesc-paths-[a-f0-9]{32}$') { throw 'Unsafe attack-path test cleanup.' }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}
