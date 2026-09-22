#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
$module=Get-Module StealthPrivesc
& $module {
    $script:TestsPassed=0
    function Assert-True([bool]$Value,[string]$Message){if(-not$Value){throw "FAIL: $Message"};$script:TestsPassed++}
    function Reset-TestContext {
        $script:Context=@{MaxItems=10;MaxFileBytes=1024;CommandTimeoutSeconds=1;IncludeNetwork=$false;IncludeDomain=$false;IncludeSensitive=$false;SearchRoot=@();Cache=@{};Elevated=$false}
        $script:Current=[ordered]@{Status='Completed';Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=New-Object 'System.Collections.Generic.List[string]'}
        $script:RegistryVisited=0
    }
    Reset-TestContext
    $catalog=@(Get-StealthPrivescCheck)
    Assert-True ($catalog.Count-eq148) 'All 148 checklist IDs must be represented.'
    Assert-True ((@($catalog.Id|Sort-Object -Unique).Count)-eq148) 'Catalog IDs must be unique.'
    Assert-True ((@($catalog|Where-Object{$_.Coverage-ne'Implemented'-and-not$_.Limitation}).Count)-eq0) 'Partial/unsupported checks must disclose limitations.'
    $rejected=$false;try{Get-StealthPrivescCheck -CheckId 149|Out-Null}catch{$rejected=$true};Assert-True $rejected 'Unknown ID must fail.'
    $rejected=$false;try{Get-StealthPrivescCheck -Category Wrong|Out-Null}catch{$rejected=$true};Assert-True $rejected 'Unknown category must fail.'
    Assert-True ((Get-ExecutablePath '"C:\Program Files\Acme\svc.exe" --password secret')-eq'C:\Program Files\Acme\svc.exe') 'Quoted executable extraction must omit arguments.'
    Assert-True ((Get-ExecutablePath 'C:\Program Files\Acme\svc.exe --password secret')-eq'C:\Program Files\Acme\svc.exe') 'Unquoted path extraction must retain spaces and omit arguments.'
    Assert-True (@(Get-UnquotedCandidates '"C:\Program Files\svc.exe" --arg').Count-eq0) 'Quoted path must not be flagged.'
    $candidates=@(Get-UnquotedCandidates 'C:\Program Files\Acme App\svc.exe --arg')
    Assert-True ($candidates.Count-eq2-and$candidates[0]-eq'C:\Program.exe'-and$candidates[1]-eq'C:\Program Files\Acme.exe') 'Generate executable prefixes, not argument prefixes.'
    Assert-True (@(Get-UnquotedCandidates 'C:\Windows\svc.exe --name "has spaces"').Count-eq0) 'Spaces in arguments must not be flagged.'
    Assert-True (-not(Test-AllowedLocalPath '\\server\share\thing.exe')) 'UNC access must require opt-in.'
    Assert-True ($script:Current.Status-eq'Partial') 'Skipped remote paths must mark coverage incomplete.'
    Reset-TestContext
    1..11|ForEach-Object{Add-Evidence "item $_" 'test'}
    Assert-True ($script:Current.Findings.Count-eq10-and$script:Current.Status-eq'Partial') 'Finding limit must be enforced and disclosed.'
    Reset-TestContext
    Get-Cached 'fixture' {Set-CheckPartial 'fixture access denied';42}|Out-Null
    $script:Current.Status='Completed';$script:Current.Limitations.Clear()
    Get-Cached 'fixture' {throw 'cache miss'}|Out-Null
    Assert-True ($script:Current.Status-eq'Partial') 'Cached collectors must retain incomplete-coverage evidence.'
    & {
        $script:FixtureRegistry=@{}
        function Read-Registry {
            param($Path,$Name)
            $key="$Path/$Name"
            if($script:FixtureRegistry.ContainsKey($key)){[pscustomobject]@{State='Present';Value=$script:FixtureRegistry[$key]}}
            else{[pscustomobject]@{State='Absent';Value=$null}}
        }
        foreach($machineValue in @(0,1)){
            foreach($userValue in @(0,1)){
                Reset-TestContext
                $script:FixtureRegistry=@{'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer/AlwaysInstallElevated'=$machineValue;'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer/AlwaysInstallElevated'=$userValue}
                Invoke-PolicyCheck 47
                $finding=$script:Current.Findings[0]
                Assert-True ($finding.Evidence.BothEnabled-eq[bool]($machineValue-and$userValue)) 'Installer finding must require both policies.'
                Assert-True (($finding.Severity-eq'High')-eq[bool]($machineValue-and$userValue)) 'Installer severity must match both policies.'
            }
        }
        Reset-TestContext
        $script:FixtureRegistry=@{}
        Invoke-PolicyCheck 47
        Assert-True (-not$script:Current.Findings[0].Evidence.BothEnabled) 'Missing installer values are not enabled.'
        Reset-TestContext
        $script:FixtureRegistry=@{'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate/WUServer'='http://testuser:NEVER_REPORT_PASSWORD@example.test:8530/?token=NEVER_REPORT_TOKEN';'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU/UseWUServer'=1}
        Invoke-PolicyCheck 53
        $json=$script:Current.Findings|ConvertTo-Json -Depth 8
        Assert-True ($json-notmatch'NEVER_REPORT|testuser') 'WSUS evidence must omit URL credentials and query strings.'
        Assert-True ($script:Current.Findings[0].Severity-eq'Medium') 'Enabled HTTP WSUS must be flagged as a candidate.'
        Reset-TestContext
        function Get-AppLockerPolicy { '<AppLockerPolicy Version="1" />' }
        Invoke-PolicyCheck 112
        Assert-True ($script:Current.Findings.Count-eq1) 'Empty AppLocker policies must not crash.'
        Reset-TestContext
        $script:FixtureRegistry=@{'fixture/Password'='NEVER_REPORT_PASSWORD';'fixture/ProxyServer'='testuser:NEVER_REPORT_PASSWORD@example.test';'fixture/PasswordLength'=16}
        Add-RegistryEvidence 'fixture' @('Password','ProxyServer','PasswordLength')
        $json=$script:Current.Findings|ConvertTo-Json -Depth 8
        Assert-True ($json-notmatch'NEVER_REPORT_PASSWORD') 'Registry passwords and proxy credentials must be redacted.'
        Assert-True ($script:Current.Findings[2].Evidence.Value-eq16) 'Password policy numbers must remain useful.'
        Reset-TestContext
        function Get-Services { [pscustomobject]@{Name='Fixture';DisplayName='Fixture';PathName='C:\Program Files\Acme Service\svc.exe --password NEVER_REPORT_PASSWORD';StartName='LocalSystem';StartMode='Auto';State='Running';ProcessId=123} }
        Invoke-ExecutionCheck 11
        $json=$script:Current.Findings|ConvertTo-Json -Depth 8
        Assert-True ($json-notmatch'NEVER_REPORT_PASSWORD') 'Service inventory must omit command arguments.'
        Assert-True ($script:Current.Findings[0].Evidence.Executable-eq'C:\Program Files\Acme Service\svc.exe') 'Service inventory must keep executable path.'
        Reset-TestContext
        function Get-Tasks { [pscustomobject]@{TaskPath='\Fixture\';TaskName='Task';Principal=[pscustomobject]@{UserId='SYSTEM';RunLevel='Highest';LogonType='Password'};State='Ready';Actions=@([pscustomobject]@{Execute='C:\Windows\cmd.exe';Arguments='/c echo NEVER_REPORT_PASSWORD'})} }
        Invoke-ExecutionCheck 22
        $json=$script:Current.Findings|ConvertTo-Json -Depth 8
        Assert-True ($json-notmatch'NEVER_REPORT_PASSWORD') 'Task inventory must omit action arguments.'
        Reset-TestContext
        Invoke-ExecutionCheck 26
        Assert-True ($script:Current.Findings.Count-eq1) 'Password-logon tasks must produce a credential-storage indicator.'
    }

    $testRoot=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-tests-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($testRoot)
    try{
        $fixture=Join-Path $testRoot 'settings.env'
        [IO.File]::WriteAllText($fixture,'password=DO_NOT_DISCLOSE_4921; api_key=DO_NOT_DISCLOSE_8237')
        Reset-TestContext
        Find-SecretMarkers $fixture
        $json=$script:Current.Findings|ConvertTo-Json -Depth 8
        Assert-True ($script:Current.Findings.Count-eq1) 'Detect secret markers in a fixture.'
        Assert-True ($json-notmatch'DO_NOT_DISCLOSE') 'Do not retain matched secret values.'
        Assert-True ($json-match'PasswordAssignment'-and$json-match'TokenAssignment') 'Retain marker categories.'
        [IO.File]::WriteAllText((Join-Path $testRoot 'large.txt'),('x'*2048))
        Find-SecretMarkers (Join-Path $testRoot 'large.txt')
        Assert-True ($script:Current.Status-eq'Partial') 'Oversized files must produce partial coverage.'
        $xmlFile=Join-Path $testRoot 'hostile.xml'
        [IO.File]::WriteAllText($xmlFile,'<!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/Windows/win.ini">]><root>&test;</root>')
        $rejected=$false;try{Read-SafeXml $xmlFile|Out-Null}catch{$rejected=$true}
        Assert-True $rejected 'Untrusted XML must prohibit DTD/external entity resolution.'
        1..15|ForEach-Object{[IO.File]::WriteAllText((Join-Path $testRoot "file$_.txt"),'innocuous')}
        Reset-TestContext
        $items=@(Get-BoundedFiles @($testRoot) -Depth 0)
        Assert-True ($items.Count-le10-and$script:Current.Status-eq'Partial') 'Traversal must bound items and disclose truncation.'
        Reset-TestContext
        Add-Evidence '<script>alert(1)</script>' 'test' @{Value='[REDACTED]'}
        $report=@{Notice='test';Computer='fixture';User='fixture';Elevated=$false;StartedUtc='now';Checks=@([pscustomobject]@{Id=1;Title='test';Status='Completed';Coverage='Implemented';Limitations=@();Findings=$script:Current.Findings})}
        Export-Assessment $report $testRoot
        $html=Get-Content (Get-ChildItem $testRoot -Filter '*.html').FullName -Raw
        Assert-True ($html-notmatch'<script>'-and$html-match'&lt;script&gt;') 'HTML report must escape hostile evidence.'
        $roundtrip=Get-Content (Get-ChildItem $testRoot -Filter '*.json').FullName -Raw|ConvertFrom-Json
        Assert-True ($roundtrip.Checks[0].Findings[0].Target-eq'<script>alert(1)</script>') 'JSON must preserve structured evidence safely.'
        if($env:OS-eq'Windows_NT'){
            if(-not('StealthPrivesc.Native'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'Native.cs')}
            $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $allow='(A;;0x2;;;'+$sid+')'
            foreach($restricted in [StealthPrivesc.Native]::Sids(11)){$allow+='(A;;0x2;;;'+$restricted.Sid+')'}
            $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor("O:${sid}G:SYD:$allow")
            $bytes=New-Object byte[] $descriptor.BinaryLength;$descriptor.GetBinaryForm($bytes,0)
            $access=[StealthPrivesc.Native]::CheckAccess($bytes,2,$false)
            Assert-True ($access.Error-eq0-and$access.Allowed) 'AccessCheck must grant an explicit current-token write right.'
            $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor("O:${sid}G:SYD:(D;;0x2;;;WD)$allow")
            $bytes=New-Object byte[] $descriptor.BinaryLength;$descriptor.GetBinaryForm($bytes,0)
            $access=[StealthPrivesc.Native]::CheckAccess($bytes,2,$false)
            Assert-True ($access.Error-eq0-and-not$access.Allowed) 'AccessCheck must honor deny ACEs before allow ACEs.'
            $smoke=Invoke-StealthPrivesc -CheckId 1,3,43,47,67,70,100,132 -MaxItems 10 -PassThru
            Assert-True (($smoke.Checks|Where-Object Id -eq 1).Status-eq'Completed') 'Native identity smoke test must complete.'
            Assert-True (($smoke.Checks|Where-Object Id -eq 43).Status-eq'Unsupported') 'Unsupported must never become completed.'
            Assert-True (($smoke.Checks|Where-Object Id -eq 67).Status-eq'Skipped') 'Sensitive checks require opt-in.'
            Assert-True (($smoke.Checks|Where-Object Id -eq 70).Status-eq'Skipped') 'Domain checks require opt-in.'
            Assert-True (($smoke.Checks|Where-Object Id -eq 132).Status-eq'Skipped') 'External network checks require opt-in.'
            Assert-True (($smoke.Checks|Where-Object Id -eq 100).Findings.Count-eq6) 'Single-entry registry rule groups must preserve every setting.'
            $nativeText=Get-Content (Join-Path $script:ModuleRoot 'Native.cs') -Raw
            Assert-True ($nativeText-notmatch'extern.*(?:AdjustTokenPrivileges|WriteProcessMemory|CreateRemoteThread|ChangeServiceConfig|StartService|ControlService)\(') 'Native surface must remain query-only.'
        }
        Write-Host "PASS: $script:TestsPassed assertions."
    } finally {
        $resolved=[IO.Path]::GetFullPath($testRoot)
        $tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        if(-not$resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($resolved)-notlike'StealthPrivesc-tests-*'){throw 'Unsafe cleanup target'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
