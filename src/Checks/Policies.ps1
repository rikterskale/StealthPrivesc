function Invoke-PolicyCheck {
    param([int]$Id)
    $policyRoot='HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    $system='HKLM:\SYSTEM\CurrentControlSet'
    $rules=@{
        48=@(@("$policyRoot\Installer",@('DisableLUAInRepair')))
        51=@(@("$policyRoot NT\Printers\PointAndPrint",@('RestrictDriverInstallationToAdministrators','NoWarningNoElevationOnInstall','UpdatePromptSettings','Restricted','TrustedServers')), @("$policyRoot NT\Printers\PackagePointAndPrint",@('PackagePointAndPrintOnly','PackagePointAndPrintServerList')))
        52=@(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer',@('DisableCoInstallers')))
        64=@(@("$system\Services\CLFS\Authentication",@('Mode','EnforcementTransitionPeriod')))
        100=@(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',@('EnableLUA','ConsentPromptBehaviorAdmin','ConsentPromptBehaviorUser','PromptOnSecureDesktop','FilterAdministratorToken','LocalAccountTokenFilterPolicy')))
        101=@(@("$system\Control\Lsa",@('RunAsPPL','RunAsPPLBoot')))
        102=@(@("$system\Control\DeviceGuard",@('EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures')),@("$system\Control\Lsa",@('LsaCfgFlags')))
        103=@(@("$system\Control\SecurityProviders\WDigest",@('UseLogonCredential')),@('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',@('CachedLogonsCount')))
        104=@(@("$policyRoot\CredentialsDelegation",@('AllowSavedCredentials','AllowFreshCredentials','AllowDefaultCredentials','ConcatenateDefaults_AllowSaved','AllowSavedCredentialsWhenNTLMOnly')))
        105=@(@("$system\Control\Lsa",@('LmCompatibilityLevel','NoLMHash')),@("$system\Control\Lsa\MSV1_0",@('NtlmMinClientSec','NtlmMinServerSec','RestrictSendingNTLMTraffic','RestrictReceivingNTLMTraffic','AuditReceivingNTLMTraffic')))
        106=@(@("$system\Services\LanmanServer\Parameters",@('SMB1','RequireSecuritySignature','EnableSecuritySignature')),@("$system\Services\LanmanWorkstation\Parameters",@('RequireSecuritySignature','EnableSecuritySignature')))
        107=@(@("$policyRoot\NetworkProvider\HardenedPaths",@('\\*\SYSVOL','\\*\NETLOGON')))
        108=@(@("$policyRoot NT\DNSClient",@('EnableMulticast','EnableMDNS')),@("$system\Services\Tcpip6\Parameters",@('DisabledComponents')))
        109=@(@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings',@('ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect')),@("$policyRoot\CurrentVersion\Internet Settings",@('ProxySettingsPerUser')))
        110=@(@('HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd',@('AdmPwdEnabled','PasswordAgeDays','PasswordLength')),@("$policyRoot\LAPS",@('BackupDirectory','PasswordAgeDays','PasswordLength','ADPasswordEncryptionEnabled')))
        113=@(@("$policyRoot\PowerShell\ScriptBlockLogging",@('EnableScriptBlockLogging','EnableScriptBlockInvocationLogging')),@("$policyRoot\PowerShell\ModuleLogging",@('EnableModuleLogging')),@("$policyRoot\PowerShell\Transcription",@('EnableTranscripting','EnableInvocationHeader')))
        121=@(@("$policyRoot\System",@('DontDisplayNetworkSelectionUI')))
        122=@(@("$system\Control\Terminal Server",@('fDenyTSConnections')),@("$system\Control\Terminal Server\WinStations\RDP-Tcp",@('UserAuthentication','SecurityLayer','MinEncryptionLevel')),@("$policyRoot NT\Terminal Services",@('DisablePasswordSaving','fPromptForPassword','fDisableCdm','fDisableClip')))
        147=@(@("$system\Services\NTDS\Parameters",@('LDAPServerIntegrity','LdapEnforceChannelBinding')))
    }
    if($rules.ContainsKey($Id)){
        $entries=$rules[$Id]
        if($entries[0] -is [string]){ $entries=,$entries }
        foreach($rule in $entries){Add-RegistryEvidence -Path $rule[0] -Names $rule[1]}
        if($Id-eq102){foreach($d in Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop){Add-Evidence 'Device Guard' 'Reported runtime virtualization security state.' ($d|Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning)}}
        if($Id-eq106){Add-Evidence 'SMB server' 'Effective SMB server configuration.' (Get-SmbServerConfiguration -ErrorAction Stop|Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature);Add-Evidence 'SMB client' 'Effective SMB client configuration.' (Get-SmbClientConfiguration -ErrorAction Stop|Select-Object RequireSecuritySignature,EnableSecuritySignature)}
        if($Id-eq113){Add-Evidence 'PowerShell' 'Runtime and installed engine versions.' @{Runtime=$PSVersionTable.PSVersion.ToString();LanguageMode=$ExecutionContext.SessionState.LanguageMode.ToString()};Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' @('PowerShellVersion');Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' @('PowerShellVersion')}
        return
    }
    switch($Id){
        47 {
            $machine=Read-Registry "$policyRoot\Installer" 'AlwaysInstallElevated'
            $user=Read-Registry 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
            $both=($machine.State-eq'Present' -and $machine.Value-eq1 -and $user.State-eq'Present' -and $user.Value-eq1)
            Add-Evidence 'Windows Installer' $(if($both){'AlwaysInstallElevated is enabled for both machine and user.'}else{'AlwaysInstallElevated configuration; both settings must be 1 for the current configuration.'}) @{Machine=$machine;User=$user;BothEnabled=$both} $(if($both){'High'}else{'Information'}) 'Disable AlwaysInstallElevated in both computer and user policy.'
        }
        53 {
            $server=Read-Registry "$policyRoot\WindowsUpdate" 'WUServer'; $enabled=Read-Registry "$policyRoot\WindowsUpdate\AU" 'UseWUServer'
            $http=($server.State-eq'Present' -and $server.Value-match'^http://' -and $enabled.Value-eq1)
            # URLs can carry credentials. Report scheme and host only.
            $uri=$null; $valid=[Uri]::TryCreate([string]$server.Value,[UriKind]::Absolute,[ref]$uri)
            Add-Evidence 'WSUS' 'Intranet update-server transport configuration; HTTP alone does not prove exploitability.' @{ServerState=$server.State;Scheme=$(if($valid){$uri.Scheme});Host=$(if($valid){$uri.DnsSafeHost});UseWUServer=$enabled;EnabledHttp=$http} $(if($http){'Medium'}else{'Information'}) 'Use HTTPS and review update-signing and proxy policies.'
            Add-RegistryEvidence "$policyRoot\WindowsUpdate" @('SetProxyBehaviorForUpdateDetection','DisableWindowsUpdateAccess')
        }
        57 { foreach($bios in Get-CimInstance Win32_BIOS -ErrorAction Stop){Add-Evidence $bios.Manufacturer 'BIOS release date is an age indicator, not a vulnerability verdict.' @{Version=$bios.SMBIOSBIOSVersion;ReleaseDate=$bios.ReleaseDate;AgeDays=$(if($bios.ReleaseDate){[int]((Get-Date)-$bios.ReleaseDate).TotalDays})}} }
        66 { Add-RegistryEvidence "$system\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" @('Enabled');Add-RegistryEvidence "$system\Control\CI\Config" @('VulnerableDriverBlocklistEnable');Set-CheckPartial 'Only related Code Integrity state is collected; no validated KernelQuick/ValleyRAT indicator signatures are included.' }
        111 { foreach($u in Get-LocalUser -ErrorAction Stop|Where-Object{$_.SID.Value-match'-500$'}){Add-Evidence $u.Name 'Built-in Administrator account state.' @{Enabled=$u.Enabled;SID=$u.SID.Value} $(if($u.Enabled){'Low'}else{'Information'})} }
        112 {
            [xml]$xml=Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $collections=@($xml.SelectNodes('/AppLockerPolicy/RuleCollection'))
            if(-not$collections.Count){Add-Evidence 'AppLocker' 'No effective rule collections returned.';return}
            foreach($collection in $collections){Add-Evidence $collection.GetAttribute('Type') 'Effective AppLocker rule collection.' @{EnforcementMode=$collection.GetAttribute('EnforcementMode');Rules=@($collection.ChildNodes|Where-Object NodeType -eq Element).Count};foreach($rule in $collection.ChildNodes){if($rule.NodeType-ne'Element'){continue};Add-Evidence $rule.GetAttribute('Name') 'AppLocker rule metadata; effectiveness depends on collection enforcement and exclusions.' @{Action=$rule.GetAttribute('Action');UserOrGroupSid=$rule.GetAttribute('UserOrGroupSid');Type=$rule.LocalName};foreach($condition in $rule.SelectNodes('.//FilePathCondition')){Add-WritablePath ([Environment]::ExpandEnvironmentVariables($condition.GetAttribute('Path')).TrimEnd('*','\')) 'Writable AppLocker path-rule candidate; exclusions and rule matching need review.'}}}
        }
        114 { foreach($endpoint in Get-PSSessionConfiguration -ErrorAction Stop){Add-Evidence $endpoint.Name 'PowerShell remoting endpoint.' ($endpoint|Select-Object Name,Permission,PSVersion,RunAsUser)} }
        115 {
            try{foreach($av in Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop){Add-Evidence $av.displayName 'Registered antivirus product.' ($av|Select-Object displayName,productState,timestamp)}}catch{Set-CheckPartial 'SecurityCenter2 antivirus inventory unavailable (common on Windows Server).' -ErrorRecord $_}
            foreach($key in Get-RegistryChildren 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'){Add-Evidence $key.PSChildName 'Registered AMSI provider CLSID.'}
            foreach($service in Get-Services|Where-Object{$_.Name-match'(?i)WinDefend|Sense|WdNisSvc|Sysmon|CrowdStrike|Sentinel|Sophos|Carbon|Cylance'}){Add-Evidence $service.Name 'Security-product service-name heuristic.' @{State=$service.State;DisplayName=$service.DisplayName}}
        }
        116 {
            Add-Evidence 'Microsoft Defender' 'Runtime protection state.' (Get-MpComputerStatus -ErrorAction Stop|Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,AntivirusSignatureLastUpdated)
            Add-Evidence 'Microsoft Defender preferences' 'Exclusions and ASR configuration.' (Get-MpPreference -ErrorAction Stop|Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions)
            Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' @('OnboardingState')
        }
        117 {
            Add-Evidence 'Audit policy' 'Effective audit policy (localized).' @{Policy=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\auditpol.exe" '/get /category:*')}
            foreach($s in Get-Services|Where-Object{$_.Name-match'^(Sysmon|Sysmon64|Wecsvc)$'}){Add-Evidence $s.Name 'Sysmon or Event Collector service state.' @{State=$s.State;StartMode=$s.StartMode}}
            foreach($key in Get-RegistryChildren "$policyRoot\EventLog\EventForwarding\SubscriptionManager"){Add-Evidence $key.PSPath 'Event forwarding policy subkey.'}
        }
        118 {
            try{Add-Evidence 'Secure Boot' 'UEFI Secure Boot runtime state.' @{Enabled=(Confirm-SecureBootUEFI -ErrorAction Stop)}}catch{Set-CheckPartial 'Secure Boot state unavailable (permissions or unsupported firmware).' -ErrorRecord $_}
            try{Add-Evidence 'TPM' 'TPM state.' (Get-Tpm -ErrorAction Stop|Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerIdTxt,ManufacturerVersion)}catch{Set-CheckPartial 'TPM query unavailable.' -ErrorRecord $_}
            try{foreach($v in Get-BitLockerVolume -ErrorAction Stop){Add-Evidence $v.MountPoint 'BitLocker volume state; recovery material omitted.' ($v|Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage)}}catch{Set-CheckPartial 'BitLocker state unavailable.' -ErrorRecord $_}
        }
        119 {
            foreach($base in @('HKCU:\Software\Policies\Microsoft\Office\16.0','HKLM:\Software\Policies\Microsoft\Office\16.0','HKCU:\Software\Microsoft\Office\16.0')){foreach($app in @('Word','Excel','PowerPoint')){
                Add-RegistryEvidence "$base\$app\Security" @('VBAWarnings','BlockContentExecutionFromInternet','AccessVBOM')
                Add-RegistryEvidence "$base\$app\Security\ProtectedView" @('DisableInternetFilesInPV','DisableUnsafeLocationsInPV','DisableAttachmentsInPV')
                foreach($key in Get-RegistryChildren "$base\$app\Security\Trusted Locations"){$location=Read-Registry $key.PSPath 'Path';if($location.State-eq'Present'){Add-WritablePath $location.Value 'Writable Office trusted location.'}}
            }}
        }
        120 {
            Add-RegistryEvidence 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' @('HideFileExt')
            Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel' @('MyComputer','LocalIntranet','Internet','TrustedSites','UntrustedSites')
            foreach($ext in @('.hta','.js','.vbs','.wsf','.ps1')){Add-RegistryEvidence "Registry::HKEY_CLASSES_ROOT\$ext" @('')}
        }
        123 { foreach($p in Get-NetFirewallProfile -ErrorAction Stop){Add-Evidence $p.Name 'Firewall profile.' ($p|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked)};foreach($r in Get-Limited @(Get-NetFirewallRule -Enabled True -ErrorAction Stop)){Add-Evidence $r.Name 'Enabled firewall rule; port/address filters not expanded.' ($r|Select-Object DisplayName,Direction,Action,Profile,PolicyStoreSourceType)} }
    }
}
