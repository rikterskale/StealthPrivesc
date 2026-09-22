function Invoke-ArtifactCheck {
    param([int]$Id)
    $roaming=$env:APPDATA; $local=$env:LOCALAPPDATA; $profile=$env:USERPROFILE
    $paths=@{
        68=@("$env:SystemRoot\Panther\unattend.xml","$env:SystemRoot\Panther\Unattend\unattend.xml","$env:SystemRoot\System32\Sysprep\unattend.xml","$env:SystemRoot\System32\Sysprep\sysprep.xml","$env:SystemDrive\unattend.xml")
        75=@("$roaming\Microsoft\Protect","$roaming\Microsoft\Credentials","$local\Microsoft\Credentials","$local\Microsoft\Vault")
        78=@("$roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","$roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt")
        81=@("$env:SystemRoot\System32\inetsrv\config\applicationHost.config","$env:SystemDrive\inetpub\wwwroot\web.config")
        82=@("$env:ProgramData\McAfee\Common Framework\SiteList.xml","$env:ProgramData\McAfee\Agent\db\SiteList.xml")
        85=@("${env:ProgramFiles}\Altiris\Altiris Agent","${env:ProgramFiles(x86)}\Altiris\Altiris Agent")
        86=@("${env:ProgramFiles}\Microsoft Monitoring Agent","${env:ProgramFiles}\System Center Operations Manager")
        88=@("$profile\Documents\Default.rdp","$local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings","$local\Microsoft\Terminal Server Client")
        89=@("$roaming\SuperPuTTY\Sessions.xml","$roaming\MTPuTTY\mtputty.xml","$profile\Documents\SuperPuTTY\Sessions.xml")
        90=@("$roaming\FileZilla\sitemanager.xml","$roaming\FileZilla\recentservers.xml","$roaming\WinSCP.ini")
        91=@("$roaming\KeePass\KeePass.config.xml","$roaming\KeePassXC\keepassxc.ini")
        92=@("$roaming\SQL Developer","$roaming\sqldeveloper")
        93=@("$profile\.aws\credentials","$profile\.aws\config","$profile\.azure\accessTokens.json","$profile\.azure\msal_token_cache.bin","$roaming\gcloud\application_default_credentials.json","$roaming\gcloud\credentials.db","$profile\.bluemix\config.json")
        98=@("$local\Google\Chrome\User Data\Default\Login Data","$local\Microsoft\Edge\User Data\Default\Login Data","$roaming\Mozilla\Firefox\Profiles")
        136=@("$local\Google\Chrome\User Data\Default\History","$local\Google\Chrome\User Data\Default\Bookmarks","$local\Microsoft\Edge\User Data\Default\History","$roaming\Mozilla\Firefox\Profiles")
        137=@("$roaming\Microsoft\Windows\Recent","$env:SystemDrive\`$Recycle.Bin")
        138=@("$local\Microsoft\Windows\INetCache\Content.Outlook","$local\Microsoft\OneNote","$roaming\Slack","$env:OneDrive")
        140=@("$profile\.wslconfig","$local\Packages")
    }
    if($paths.ContainsKey($Id)){
        foreach($path in $paths[$Id]){if($path){Add-Artifact $path 'Scoped application/profile' -Inspect:($Id-in@(68,78,81,82,88,89,90,91,93))}}
        if($Id-eq78){foreach($file in Get-BoundedFiles @("$profile\Documents") -Depth 2 -Pattern '^PowerShell_transcript.*\.txt$'){Add-Artifact $file.FullName 'PowerShell transcript' -Inspect}}
        if($Id-eq89){foreach($key in Get-Limited @(Get-RegistryChildren 'HKCU:\Software\SimonTatham\PuTTY\Sessions')){Add-Evidence $key.PSChildName 'PuTTY session key; connection values omitted.';Add-RegistryEvidence $key.PSPath @('PublicKeyFile')}}
        if($Id-eq91){foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 3 -Pattern '\.(kdbx?|keyx)$'){Add-Artifact $file.FullName 'Password database or key-file'}}
        if($Id-eq140){foreach($name in @('certutil.exe','bitsadmin.exe','mshta.exe','rundll32.exe','regsvr32.exe','wsl.exe','bash.exe')){Add-Artifact "$env:SystemRoot\System32\$name" 'Dual-use Windows executable'};foreach($key in Get-RegistryChildren 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'){Add-RegistryEvidence $key.PSPath @('DistributionName','BasePath')}}
        return
    }
    switch($Id){
        67 {
            $path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Add-RegistryEvidence $path @('AutoAdminLogon','DefaultUserName','DefaultDomainName')
            $password=Read-Registry $path 'DefaultPassword'
            Add-Evidence "$path\DefaultPassword" 'Auto-logon password registry exposure check; no LSA secret extraction.' @{State=$password.State;Value=$(if($password.State-eq'Present'){'[REDACTED]'})} $(if($password.State-eq'Present' -and $password.Value){'High'}else{'Information'}) 'Remove plaintext auto-logon credentials and rotate confirmed exposed passwords.'
        }
        69 { foreach($file in Get-BoundedFiles @("$env:ProgramData\Microsoft\Group Policy\History","$env:SystemRoot\System32\GroupPolicy") -Depth 8 -Pattern '\.xml$'){Find-SecretMarkers $file.FullName} }
        70 { $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;if(-not$computer.PartOfDomain){Set-CheckSkipped 'Computer is not domain joined.';return};foreach($file in Get-BoundedFiles @("\\$($computer.Domain)\SYSVOL\$($computer.Domain)\Policies") -Depth 8 -Pattern '\.xml$'){Find-SecretMarkers $file.FullName} }
        71 {
            foreach($base in @("$env:SystemRoot\System32\config","$env:SystemRoot\System32\config\RegBack","$env:SystemDrive\Windows.old\Windows\System32\config")){foreach($name in @('SAM','SYSTEM','SECURITY')){
                $path=Join-Path $base $name
                try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete));$stream.Dispose();Add-Evidence $path 'Registry hive can be opened for reading; no contents collected.' @{Readable=$true;ElevatedToken=$script:Context.Elevated} $(if($script:Context.Elevated){'Information'}else{'High'})}
                catch [IO.FileNotFoundException]{}catch [IO.DirectoryNotFoundException]{}catch [UnauthorizedAccessException]{Add-Evidence $path 'Read access denied.' @{Readable=$false}}catch{Set-CheckPartial "Hive readability unknown (locked or inaccessible): $path"}
            }}
        }
        72 { Add-Evidence 'Credential Manager' 'Saved credential metadata only; passwords are not requested.' @{Inventory=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\cmdkey.exe" '/list')} }
        73 { Add-Evidence 'Windows Vault' 'Vault container inventory; no credential retrieval.' @{Inventory=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\vaultcmd.exe" '/list')} }
        74 { Add-Artifact "$local\Microsoft\Vault" 'Credential Locker backing store';Add-Artifact "$roaming\Microsoft\Vault" 'Credential Locker backing store' }
        77 { Add-Evidence 'Kerberos cache' 'Current-logon ticket metadata only; no ticket or session-key export.' @{Inventory=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\klist.exe" '')} }
        79 {
            foreach($log in @('Microsoft-Windows-PowerShell/Operational','Security','Microsoft-Windows-Sysmon/Operational')){
                try{ $ids=switch($log){'Security'{@(4688)} 'Microsoft-Windows-PowerShell/Operational'{@(4103,4104)} default{@(1)}}
                    $events=@(Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids} -MaxEvents $script:Context.MaxItems -ErrorAction Stop)
                    foreach($event in $events){if($event.ToXml()-match'(?i)(password|passwd|pwd|api[_-]?key|client[_-]?secret|access[_-]?token)\s*["'']?\s*[:=]'){Add-Evidence "$log/$($event.RecordId)" 'Possible secret assignment in event data; contents omitted.' @{Id=$event.Id;TimeCreated=$event.TimeCreated;Values='[REDACTED]'} 'Medium'}}
                    if($events.Count-eq$script:Context.MaxItems){Set-CheckPartial 'Event limit reached; only the newest matching events were inspected.'}
                }catch{Set-CheckPartial "Log unavailable or no matching records: $log"}
            }
        }
        80 {
            foreach($root in @('HKCU:\Software','HKLM:\SOFTWARE')){foreach($key in Get-Limited @(Get-RegistryChildren $root)){
                try{foreach($name in $key.GetValueNames()){if($name-match'(?i)password|passwd|secret|token|credential'){Add-Evidence "$($key.Name)/$name" 'Sensitive registry-value name; value omitted.' @{Value='[REDACTED]'} 'Low'}}}catch{Set-CheckPartial 'Some registry value names were inaccessible.'}
            }}
        }
        83 { foreach($class in @('CCM_NetworkAccessAccount')){try{foreach($item in Get-CimInstance -Namespace root\ccm\policy\Machine\ActualConfig -ClassName $class -ErrorAction Stop){Add-Evidence $class 'SCCM Network Access Account policy object is readable; encrypted fields not collected.' @{Present=$true;Decrypted=$false} 'Low'}}catch{Set-CheckPartial 'SCCM policy namespace absent or inaccessible.'}} }
        84 { foreach($file in Get-BoundedFiles @("$env:SystemRoot\ccmcache") -Depth 3 -Pattern '\.(xml|ini|config|ps1|bat|cmd|txt|json|yml|yaml)$'){Add-Artifact $file.FullName 'SCCM cache' -Inspect} }
        87 { foreach($key in @('HKLM:\SOFTWARE\RealVNC\vncserver','HKLM:\SOFTWARE\TightVNC\Server','HKLM:\SOFTWARE\TigerVNC\WinVNC4')){Add-RegistryEvidence $key @('Password','PasswordViewOnly')};foreach($file in @("${env:ProgramFiles}\uvnc bvba\UltraVNC\ultravnc.ini","${env:ProgramFiles(x86)}\uvnc bvba\UltraVNC\ultravnc.ini")){Add-Artifact $file 'VNC configuration' -Inspect} }
        94 {
            foreach($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')){foreach($cert in Get-Limited @(Get-ChildItem $store -ErrorAction Stop)){Add-Evidence $cert.Thumbprint 'Certificate metadata; private keys are not exported.' ($cert|Select-Object Subject,Issuer,NotBefore,NotAfter,HasPrivateKey,Thumbprint)}}
            foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 3 -Pattern '\.(pfx|p12|pem|key)$'){Add-Artifact $file.FullName 'Certificate/private-key'}
        }
        {$_ -in @(95,96)} {
            foreach($file in Get-BoundedFiles @("$env:ProgramData\Microsoft\Wlansvc\Profiles\Interfaces") -Depth 2 -Pattern '\.xml$'){
                if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Wi-Fi profile exceeded file size limit.';continue}
                try{$xml=Read-SafeXml $file.FullName;$auth=$xml.SelectSingleNode('//*[local-name()="authentication"]');$key=$xml.SelectSingleNode('//*[local-name()="keyMaterial"]');$validate=$xml.SelectNodes('//*[local-name()="PerformServerValidation" or local-name()="DisableUserPromptForServerValidation"]');
                    Add-Evidence $file.FullName 'Wi-Fi profile security metadata; network names and key material omitted.' @{Authentication=$(if($auth){$auth.InnerText});KeyMaterialPresent=($null-ne$key);KeyMaterial='[REDACTED]';ValidationSettings=@($validate|ForEach-Object{@{Name=$_.LocalName;Value=$_.InnerText}})}
                }catch{Set-CheckPartial 'A Wi-Fi profile could not be parsed.'}
            }
        }
        97 { $value=Get-Clipboard -Raw -ErrorAction Stop;Add-Evidence 'Clipboard' 'Clipboard inspected for secret markers; contents omitted.' @{NonEmpty=(-not[string]::IsNullOrEmpty($value));SecretMarker=([string]$value-match'(?i)password|api[_-]?key|access[_-]?token|BEGIN .*PRIVATE KEY');Value='[REDACTED]'} }
        99 { foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 4 -Pattern '(?i)\.(config|xml|ini|json|ya?ml|ps1|bat|cmd|log|txt|env|conf|bak)$|^\.?(git-credentials|netrc|npmrc|pypirc)$|^id_(rsa|ed25519)$'){Find-SecretMarkers $file.FullName} }
    }
}
