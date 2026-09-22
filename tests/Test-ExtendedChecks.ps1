#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
& (Get-Module StealthPrivesc) {
    $script:ExtendedAssertions=0
    function Assert([bool]$Value,[string]$Message){if(-not$Value){throw "FAIL: $Message"};$script:ExtendedAssertions++}
    function Reset {
        $script:Context=@{MaxItems=10;MaxFileBytes=1024;IncludeNetwork=$false;IncludeDomain=$false;Elevated=$false;CommandTimeoutSeconds=3;Cache=@{}}
        $script:Current=@{Status='Completed';Findings=New-Object 'System.Collections.Generic.List[object]';Limitations=New-Object 'System.Collections.Generic.List[string]'}
    }
    Reset
    # SecurityIdentifier.AccountDomainSid recursively exposes another SID object.
    # Keep SID values scalar at the collector boundary so report exporters remain bounded.
    function Get-LocalUser { [pscustomobject]@{Name='fixture';SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001');Enabled=$true;PasswordLastSet=$null;LastLogon=$null;PasswordExpires=$null;UserMayChangePassword=$true} }
    function Get-LocalGroup { [pscustomobject]@{Name='fixture-group';SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')} }
    function Get-LocalGroupMember { [pscustomobject]@{Name='fixture';SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001');ObjectClass='User';PrincipalSource='Local'} }
    try {
        Invoke-IdentityCheck 6
        Assert ($script:Current.Findings[0].Evidence.SID -is [string]) 'Account SID evidence is a scalar string.'
        Assert ($script:Current.Findings[1].Evidence.Members[0].SID -is [string]) 'Group member SID evidence is a scalar string.'
        $json=$script:Current | ConvertTo-Json -Depth 12 -WarningAction Stop
        Assert ($json -notmatch 'AccountDomainSid') 'Identity evidence serializes without recursive SID metadata.'
    } finally { Remove-Item Function:Get-LocalUser,Function:Get-LocalGroup,Function:Get-LocalGroupMember }
    Reset
    Assert (Test-AllowedLocalPath '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM') 'Local shadow-copy paths do not require network access.'
    Assert (-not(Test-AllowedLocalPath '\\?\UNC\server\share\file')) 'Extended UNC paths remain network-gated.'
    Reset
    $xml=New-Object Xml.XmlDocument;$xml.LoadXml('<root><Password>CANARY_PRIVATE_938472</Password><UserPassword>aexs://private</UserPassword><item cpassword="CANARY_PRIVATE_938472" /></root>')
    $indicators=@(Get-StructuredSecretIndicators $xml)
    Assert ($indicators.Count-eq3-and($indicators|ConvertTo-Json)-notmatch'CANARY_PRIVATE_938472') 'Structured credential indicators redact every value.'
    Assert ('SymantecSecureStorageReference'-in$indicators.Storage) 'Recognize Symantec secure-storage references.'
    $shape=Get-RedactedUrl 'https://user:CANARY_PRIVATE_938472@example.test/path?token=CANARY_PRIVATE_938472'
    Assert ($shape.Host-eq'example.test'-and($shape|ConvertTo-Json)-notmatch'CANARY_PRIVATE_938472') 'URL evidence strips userinfo, paths and query secrets.'
    $msi=Get-MsiActionIndicators 0xc02 $true 'REINSTALL' 'cmd.exe /c tool [INSTALLDIR]'
    Assert ($msi.Deferred-and$msi.NoImpersonate-and$msi.InExecuteSequence-and$msi.MentionsRepair-and$msi.DynamicProperties) 'MSI assessment combines scheduling, repair and property indicators.'
    $sample=[pscustomobject]@{SHA256=('a'*64);SHA1=('b'*40);Authentihash=[pscustomobject]@{SHA256=('c'*64);SHA1=('d'*40)};OriginalFilename='fixture.sys';FileVersion='1.0.0.5';Certificates=@()}
    $rule=[pscustomobject]@{Id='deny';Type='Deny';Hash=('c'*64)}
    $policy=[pscustomobject]@{FileRules=@($rule);SignerRules=@();SigningScenarios=@([pscustomobject]@{Value=131;ProductSigners=[pscustomobject]@{FileRulesRef=[pscustomobject]@{FileRuleRef=@('deny')}}})}
    Assert (@(Get-CIDenyMatches $policy $sample).Count-eq1) 'Authenticode hashes match referenced kernel-mode deny rules.'
    $policy.SigningScenarios[0].Value=12
    Assert (@(Get-CIDenyMatches $policy $sample).Count-eq0) 'A user-mode deny rule is not driver blocking evidence.'
    $policy.SigningScenarios[0].Value=131;$rule.Type='Allow'
    Assert (@(Get-CIDenyMatches $policy $sample).Count-eq0) 'An allow rule must never count as a deny.'
    $versionRule=[pscustomobject]@{FileName='fixture.sys';MinimumVersion='1.0.0.1';MaximumFileVersion='1.0.0.4'}
    Assert (-not(Test-CIFileRule $versionRule $sample)) 'CI version bounds exclude newer files.'
    $versionRule.MaximumFileVersion='1.0.0.5'
    Assert (Test-CIFileRule $versionRule $sample) 'CI maximum version comparison is inclusive.'
    $rules=@(
        [pscustomobject]@{Cve='CVE-2099-0001';Product='Windows 11 Version 23H2 for x64-based Systems';FixedBuild='10.0.22631.100';KB='TEST1';Source='fixture';Title='fixture'},
        [pscustomobject]@{Cve='CVE-2099-0001';Product='Windows 11 Version 23H2 for x64-based Systems';FixedBuild='10.0.22631.200';KB='TEST2';Source='fixture';Title='fixture'},
        [pscustomobject]@{Cve='CVE-2099-0002';Product='Windows Server 2022';FixedBuild='10.0.20348.100';KB='TEST3';Source='fixture';Title='fixture'}
    )
    $context=[pscustomobject]@{Version=[version]'10.0.22631.99';IsServer=$false;Architecture='x64'}
    $result=@(Get-WindowsPatchAssessment $rules $context)
    Assert ($result.Count-eq1-and$result[0].State-eq'BelowPublishedFix') 'Flag only the matching Windows product and branch.'
    Assert ($result[0].FixedBuild-eq'10.0.22631.100') 'Use the earliest fixing build for a product branch.'
    $context.Version=[version]'10.0.22631.100'
    Assert ((Get-WindowsPatchAssessment $rules $context).State-eq'AtOrAbovePublishedFix') 'The exact fixing revision is patched.'
    $context.Version=[version]'10.0.22631.300'
    Assert ((Get-WindowsPatchAssessment $rules $context).State-eq'AtOrAbovePublishedFix') 'A superseding cumulative revision is patched without an old KB.'
    $context.Version=[version]'10.0.26100.10'
    Assert ((Get-WindowsPatchAssessment $rules $context @('CVE-2099-0001')).State-eq'NoMatchingProductRule') 'Do not infer safety or vulnerability across servicing branches.'
    $context.Version=[version]'10.0.22631.99';$context.Architecture='arm64'
    Assert (@(Get-WindowsPatchAssessment $rules $context).Count-eq0) 'Do not apply x64 fixes to ARM64.'
    $context.Architecture='x64';$context.IsServer=$true
    Assert (@(Get-WindowsPatchAssessment $rules $context).Count-eq0) 'Do not apply client product fixes to Server.'
    $testRoot=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-extended-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($testRoot)
    try{
        $file=Join-Path $testRoot 'fixture.sys';[IO.File]::WriteAllText($file,'harmless driver hash fixture')
        $hash=(Get-FileHash $file -Algorithm SHA256).Hash
        $entries=@([pscustomobject]@{SHA256=$hash.ToLowerInvariant();Id='test';Category='vulnerable';Resources=@('fixture')})
        $drivers=@([pscustomobject]@{Name='TestDriver';Path=$file;State='Stopped'})
        $matches=@(Get-DriverHashMatches $entries $drivers)
        Assert ($matches.Count-eq1-and$matches[0].ReferenceId-eq'test') 'Match driver hashes case-insensitively.'
        [IO.File]::WriteAllText($file,'different harmless bytes')
        Assert (@(Get-DriverHashMatches $entries $drivers).Count-eq0) 'Never match a driver by filename alone.'
        $entries[0].SHA256='bad';$failed=$false
        try{Get-DriverHashMatches $entries $drivers|Out-Null}catch{$failed=$true}
        Assert $failed 'Reject malformed hash records.'
        Reset
        $missing=Get-ReferenceDocument (Join-Path $testRoot 'missing.json') 'Fixture'
        Assert ($null-eq$missing-and$script:Current.Status-eq'Partial') 'Missing reference data is incomplete, never clean.'
        if($env:OS-eq'Windows_NT'){
            foreach($type in @('Native','NativeObjects','NativeInspection')){if(-not("StealthPrivesc.$type"-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot "$type.cs")}}
            Add-Type -AssemblyName System.Security
            Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSecrets.cs')
            Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSqlite.cs')
            Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSessions.cs')
            $query=[StealthPrivesc.NativeSqlite]::Query(':memory:',"SELECT 'fixture' UNION ALL SELECT 'second'",1,2)
            Assert ($query.Rows.Count-eq1-and$query.Truncated) 'SQLite query results are bounded without copying databases.'
            $failed=$false;try{[StealthPrivesc.NativeSqlite]::Query(':memory:','CREATE TABLE forbidden (id INTEGER)',1,2)|Out-Null}catch{$failed=$true}
            Assert $failed 'SQLite mutation statements are rejected.'
            $json=[Text.Encoding]::UTF8.GetBytes('{"windows":[]}')
            $frame=[Text.Encoding]::ASCII.GetBytes("mozLz40`0")+[BitConverter]::GetBytes([uint32]$json.Length)+[byte]($json.Length-shl4)+$json
            Assert ([StealthPrivesc.NativeSessions]::Firefox($frame,1024)-eq'{"windows":[]}') 'Firefox session decompression accepts a bounded literal fixture.'
            $failed=$false;try{[StealthPrivesc.NativeSessions]::Firefox($frame,5)|Out-Null}catch{$failed=$true}
            Assert $failed 'Firefox decompression rejects output exceeding the configured cap.'
            $plain=[Text.Encoding]::UTF8.GetBytes('synthetic fixture password')
            $encrypted=[Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            $probe=[StealthPrivesc.NativeSecrets]::Browser($null,$encrypted)
            Assert ($probe.Recovered-and$probe.Value-eq'[REDACTED]') 'A synthetic DPAPI password is recoverable without returning its value.'
            $key=New-Object byte[] 16;$wrapped=[Text.Encoding]::ASCII.GetBytes('DPAPI')+[Security.Cryptography.ProtectedData]::Protect($key,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            $hex='0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf';$cipher=New-Object byte[] 32;for($j=0;$j-lt32;$j++){$cipher[$j]=[Convert]::ToByte($hex.Substring($j*2,2),16)}
            $blob=[Text.Encoding]::ASCII.GetBytes('v10')+(New-Object byte[] 12)+$cipher
            Assert ([StealthPrivesc.NativeSecrets]::Browser($wrapped,$blob).Recovered) 'Known AES-GCM fixture authenticates through DPAPI-wrapped browser key.'
            $blob[$blob.Length-1]=$blob[$blob.Length-1]-bxor1
            Assert (-not[StealthPrivesc.NativeSecrets]::Browser($wrapped,$blob).Recovered) 'A modified GCM authentication tag never reports recovery.'
            $class=[Guid]::NewGuid();$property=[Guid]::NewGuid()
            $sd=New-Object Security.AccessControl.RawSecurityDescriptor("O:SYG:SYD:(OA;;WP;$property;;WD)")
            $bytes=New-Object byte[] $sd.BinaryLength;$sd.GetBinaryForm($bytes,0)
            $access=[StealthPrivesc.Native]::CheckDirectoryAccess($bytes,0x20,$class,$property,$null)
            Assert ($access.Error-eq0-and$access.Allowed) 'Object-specific AD allow right is recognized.'
            Assert (-not[StealthPrivesc.Native]::CheckDirectoryAccess($bytes,0x20,$class,[Guid]::NewGuid(),$null).Allowed) 'An unrelated AD property is not granted.'
            $sd=New-Object Security.AccessControl.RawSecurityDescriptor("O:SYG:SYD:(OD;;WP;$property;;WD)(OA;;WP;$property;;WD)")
            $bytes=New-Object byte[] $sd.BinaryLength;$sd.GetBinaryForm($bytes,0)
            Assert (-not[StealthPrivesc.Native]::CheckDirectoryAccess($bytes,0x20,$class,$property,$null).Allowed) 'Object-specific AD deny overrides allow.'
            $indicators=Get-ADCSIndicators 1 0 0 @('1.3.6.1.5.5.7.3.2') $true $true
            Assert $indicators.ESC1Candidate 'Published client-auth template with enroll access and supplied subject is an ESC1 candidate.'
            Assert (-not(Get-ADCSIndicators 1 2 0 @('1.3.6.1.5.5.7.3.2') $true $true).ESC1Candidate) 'Manager approval blocks the direct ESC1 prerequisite combination.'
            Assert (Get-ADCSIndicators 0 0 0 @($null) $true $true).ESC2Candidate 'Null EKU attributes mean unrestricted purpose.'
            $namespace=[StealthPrivesc.NativeObjects]::Directory('\',1)
            Assert ($namespace.Status-eq0-and$namespace.Entries.Count-eq1-and$namespace.Truncated) 'Object namespace enumeration is bounded.'
            $endpoints=[StealthPrivesc.NativeInspection]::Endpoints(1)
            Assert ($endpoints.Error-eq0-and$endpoints.Items.Count-le1) 'Local RPC endpoint enumeration succeeds and is bounded.'
            $missing=[StealthPrivesc.NativeObjects]::Security('\StealthPrivescMissing-'+[Guid]::NewGuid().ToString('N'),$true)
            Assert ($missing.Status-ne0-and$null-eq$missing.Descriptor) 'Missing native objects return errors, not a permissive descriptor.'
        }
        Write-Host "PASS: $script:ExtendedAssertions extended assertions."
    }finally{
        $resolved=[IO.Path]::GetFullPath($testRoot)
        $tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        if(-not$resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($resolved)-notlike'StealthPrivesc-extended-*'){throw 'Unsafe cleanup target'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
