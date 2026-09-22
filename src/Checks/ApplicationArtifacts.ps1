function Get-StructuredSecretIndicators {
    param([xml]$Xml)
    foreach($node in $Xml.SelectNodes('//*')){
        if($node.LocalName-match'(?i)^(password|passwd|pwd|cpassword|UserPassword|PasswordBlob|encryptedPassword|keyMaterial)$'-and$node.InnerText){
            [pscustomobject]@{Field=$node.LocalName;Storage=$(if($node.InnerText.StartsWith('aexs://')){'SymantecSecureStorageReference'}elseif($node.LocalName-match'cpassword|encrypted|blob'){'EncryptedOrEncoded'}else{'Present'});Value='[REDACTED]'}
        }
        foreach($attribute in $node.Attributes){if($attribute.LocalName-match'(?i)^(password|passwd|pwd|cpassword|UserPassword|connectionString)$'-and$attribute.Value){[pscustomobject]@{Field=$attribute.LocalName;Storage=$(if($attribute.LocalName-eq'cpassword'){'GppPublicKeyEncrypted'}elseif($attribute.Value.StartsWith('aexs://')){'SymantecSecureStorageReference'}else{'Present'});Value='[REDACTED]'}}}
    }
}
function Add-StructuredArtifact {
    param([string]$Path,[string]$Kind)
    Add-ReadableArtifact $Path $Kind
    if((Get-FilePresence $Path)-ne'Present'){return}
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Application configuration exceeds MaxFileBytes.';return}
    if($file.Extension-in@('.xml','.config','.rdg','.settings')){
        try{foreach($indicator in Get-StructuredSecretIndicators (Read-SafeXml $Path)){Add-Evidence $Path "$Kind credential field detected; values discarded." $indicator 'Medium'}}
        catch{Set-CheckPartial 'Application XML could not be parsed.'}
    }
    Find-SecretMarkers $Path
}
function Invoke-ApplicationArtifactCheck {
    param([int]$Id)
    switch($Id){
        71 {
            Invoke-ArtifactCheck 71
            try{foreach($shadow in Get-Limited @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)){foreach($name in @('SAM','SYSTEM','SECURITY')){Add-ReadableArtifact ($shadow.DeviceObject+'\Windows\System32\config\'+$name) 'Shadow-copy hive readability; contents are not copied.'}}}catch{Set-CheckPartial 'Shadow-copy enumeration unavailable.'}
        }
        80 {
            foreach($key in Get-RegistryTree @('HKCU:\Software','HKLM:\SOFTWARE')){
                try{foreach($name in $key.GetValueNames()){$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$nameMarker=$name-match'(?i)password|passwd|secret|token|credential';$contentMarker=$value-is[string]-and$value-match'(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*["'']?\s*[:=]|BEGIN .*PRIVATE KEY';if($nameMarker-or$contentMarker){Add-Evidence ($key.Name+'/'+$name) 'Possible credential registry field or embedded assignment.' @{NameMarker=$nameMarker;ContentMarker=$contentMarker;NonEmpty=($null-ne$value-and[string]$value-ne'');Value='[REDACTED]'} 'Low'}}}
                catch{Set-CheckPartial 'Some registry fields were unreadable.'}
            }
        }
        81 {
            $assembly=Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
            if((Get-FilePresence $assembly)-eq'Present'){
                $manager=$null
                try{
                    Add-Type -Path $assembly -ErrorAction Stop;$manager=New-Object Microsoft.Web.Administration.ServerManager
                    foreach($pool in Get-Limited @($manager.ApplicationPools)){$model=$pool.ProcessModel;$present=-not[string]::IsNullOrEmpty($model.Password);Add-Evidence $pool.Name 'IIS application-pool process-model credentials queried in the current context; password discarded.' @{IdentityType=[string]$model.IdentityType;UserNamePresent=(-not[string]::IsNullOrEmpty($model.UserName));PasswordReturned=$present;Value='[REDACTED]'} $(if($present){'High'}else{'Information'})}
                    foreach($site in Get-Limited @($manager.Sites)){foreach($app in $site.Applications){foreach($directory in $app.VirtualDirectories){$path=[Environment]::ExpandEnvironmentVariables($directory.PhysicalPath);Add-StructuredArtifact (Join-Path $path 'web.config') 'IIS site configuration';$present=-not[string]::IsNullOrEmpty($directory.Password);Add-Evidence ($site.Name+$directory.Path) 'IIS virtual-directory credential accessibility.' @{PasswordReturned=$present;Value='[REDACTED]'} $(if($present){'High'}else{'Information'})}}}
                }catch{Set-CheckPartial 'IIS configuration API inaccessible or protected fields could not be decrypted.'}finally{if($manager){$manager.Dispose()}}
            }
            foreach($path in @("$env:SystemRoot\System32\inetsrv\config\applicationHost.config","$env:SystemDrive\inetpub\wwwroot\web.config")){Add-StructuredArtifact $path 'IIS configuration'}
        }
        85 {
            foreach($root in @('HKLM:\SOFTWARE\Altiris\Altiris Agent','HKLM:\SOFTWARE\WOW6432Node\Altiris\Altiris Agent')){Add-RegistryEvidence $root @('Version','InstallDir');foreach($key in Get-RegistryChildren ($root+'\Servers')){Add-Evidence $key.PSChildName 'Configured Symantec Notification Server.'}}
            foreach($root in @("${env:ProgramFiles}\Altiris\Altiris Agent\Client Policies","${env:ProgramFiles(x86)}\Altiris\Altiris Agent\Client Policies","$env:ProgramData\Symantec\Symantec Agent")){
                foreach($file in Get-BoundedFiles @($root) -Depth 3 -Pattern '\.xml$'){
                    if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'Symantec policy exceeded MaxFileBytes.';continue}
                    try{$xml=Read-SafeXml $file.FullName;$nodes=@($xml.SelectNodes('//*[local-name()="PkgAccessCredentials"]'));foreach($node in $nodes){Add-Evidence $file.FullName 'Symantec Account Connectivity Credentials policy reference.' @{CredentialNodePresent=$true;SecureStorageReference=($node.OuterXml-match'aexs://');Values='[REDACTED]'} 'Medium'}}catch{Set-CheckPartial 'Symantec client policy XML could not be parsed.'}
                }
            }
        }
        86 {
            try{$events=@(Get-WinEvent -FilterHashtable @{LogName='Operations Manager';Id=@(7026,7002)} -MaxEvents ($script:Context.MaxItems+1) -ErrorAction Stop);foreach($event in Get-Limited $events){Add-Evidence "Operations Manager/$($event.RecordId)" 'SCOM Run As account logon trace indicates configured credentials; event payload is redacted.' @{Id=$event.Id;TimeCreated=$event.TimeCreated;SuccessfulLogon=($event.Id-eq7026);Payload='[REDACTED]'} 'Low'}}catch{Set-CheckPartial 'SCOM log absent, inaccessible, or contains no matching Run As events.'}
        }
        {$_-in@(82,88,89,90,91,92,93)} {
            foreach($profile in Get-ProfileRoots){
                $roaming=Join-Path $profile 'AppData\Roaming';$local=Join-Path $profile 'AppData\Local'
                $roots=switch($Id){
                    82 {@("$env:ProgramData\McAfee",'C:\Program Files\McAfee','C:\Program Files (x86)\McAfee')}
                    88 {@("$profile\Documents","$local\Microsoft\Remote Desktop Connection Manager","$local\Microsoft\Terminal Server Client")}
                    89 {@("$roaming\SuperPuTTY","$roaming\MTPuTTY","$profile\Documents\SuperPuTTY")}
                    90 {@("$roaming\FileZilla","$roaming\WinSCP")}
                    91 {@("$roaming\KeePass","$roaming\KeePassXC")}
                    92 {@("$roaming\SQL Developer","$roaming\sqldeveloper")}
                    93 {@("$profile\.aws","$profile\.azure","$roaming\gcloud","$profile\.config\gcloud","$profile\.bluemix","$profile\.kube")}
                }
                $pattern=switch($Id){82{'^SiteList\.xml$'}88{'\.(rdp|rdg|settings)$'}91{'\.(xml|ini|kdbx?|keyx?)$'}default{'.*'}}
                foreach($file in Get-BoundedFiles $roots -Depth 5 -Pattern $pattern){if($file.Extension-in@('.db','.bin','.kdb','.kdbx')){Add-ReadableArtifact $file.FullName 'Application credential/token backing store'}else{Add-StructuredArtifact $file.FullName 'Application credential configuration'}}
                if($Id-eq90){Add-StructuredArtifact "$roaming\WinSCP.ini" 'WinSCP configuration'}
                if($Id-eq82){break}
            }
            if($Id-eq89){foreach($key in Get-RegistryChildren 'HKCU:\Software\SimonTatham\PuTTY\Sessions'){Add-RegistryEvidence $key.PSPath @('HostName','UserName','PortNumber','PublicKeyFile');$file=Read-Registry $key.PSPath 'PublicKeyFile';if($file.State-eq'Present'-and$file.Value){Add-ReadableArtifact $file.Value 'PuTTY referenced private key'}}}
            if($Id-eq90){foreach($key in Get-RegistryChildren 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'){Add-RegistryEvidence $key.PSPath @('HostName','UserName','Password','PublicKeyFile') -SensitiveNames @('Password')}}
            if($Id-eq91){foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 5 -Pattern '\.(kdbx?|keyx?)$'){Add-ReadableArtifact $file.FullName 'Password database/key-file clue'}}
        }
        138 {
            foreach($profile in Get-ProfileRoots){foreach($root in @("$profile\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook","$profile\AppData\Local\Microsoft\OneNote","$profile\AppData\Roaming\Slack")){foreach($file in Get-BoundedFiles @($root) -Depth 4){Add-ReadableArtifact $file.FullName 'Collaboration/download/backup artifact'}}}
            foreach($key in Get-RegistryChildren 'HKCU:\Software\Microsoft\OneDrive\Accounts'){Add-RegistryEvidence $key.PSPath @('UserFolder','DisplayName');$folder=Read-Registry $key.PSPath 'UserFolder';if($folder.State-eq'Present'){foreach($file in Get-BoundedFiles @($folder.Value) -Depth 2){Add-Evidence $file.FullName 'OneDrive synchronized-file metadata.' @{Length=$file.Length;LastWriteUtc=$file.LastWriteTimeUtc;Attributes=[string]$file.Attributes}}}}
        }
    }
}
