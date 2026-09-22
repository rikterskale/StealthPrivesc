function Invoke-PolicyAnalysisCheck {
    param([int]$Id)
    $root='HKLM:\SOFTWARE\Policies\Microsoft\Windows';$system='HKLM:\SYSTEM\CurrentControlSet'
    switch($Id){
        48 {
            $setting=Read-Registry "$root\Installer" 'DisableLUAInRepair'
            Add-Evidence 'Windows Installer repair' 'Repair elevation prompt suppression policy; applicability is subject to installed Windows servicing.' @{PolicyState=$setting.State;DisabledPrompt=($setting.State-eq'Present'-and$setting.Value-eq1);Value=$setting.Value} $(if($setting.State-eq'Present'-and$setting.Value-eq1){'Medium'}else{'Information'})
        }
        51 {
            Invoke-PolicyCheck 51
            $path="$root NT\Printers\PointAndPrint";$restrict=Read-Registry $path 'RestrictDriverInstallationToAdministrators';$install=Read-Registry $path 'NoWarningNoElevationOnInstall';$update=Read-Registry $path 'UpdatePromptSettings'
            $service=Get-Services|Where-Object Name -eq Spooler
            Add-Evidence 'Point and Print' 'Explicit settings that weaken printer-driver installation controls. Missing restriction settings use servicing-dependent defaults.' @{SpoolerState=$(if($service){$service.State});ExplicitlyAllowsNonAdmins=($restrict.State-eq'Present'-and$restrict.Value-eq0);SuppressesInstallPrompt=($install.State-eq'Present'-and$install.Value-eq1);SuppressesUpdatePrompt=($update.State-eq'Present'-and$update.Value-eq0)} $(if(($restrict.State-eq'Present'-and$restrict.Value-eq0)-or($install.State-eq'Present'-and$install.Value-eq1)){'Medium'}else{'Information'})
        }
        52 {$setting=Read-Registry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer' 'DisableCoInstallers';Add-Evidence 'Driver co-installers' 'Co-installer policy.' @{State=$setting.State;Disabled=($setting.State-eq'Present'-and$setting.Value-eq1);Value=$setting.Value}}
        64 {
            $path="$system\Services\CLFS\Authentication";$mode=Read-Registry $path 'Mode';$period=Read-Registry $path 'EnforcementTransitionPeriod';$start=Read-Registry $path 'LearningModeStartTime'
            $meaning='UnknownOrUnsupported';if($mode.State-eq'Present'){$meaning=switch([int]$mode.Value){0{'Enforced'}1{'Learning'}2{'AdministratorDisabled'}3{'SystemDisabled'}default{'UnknownMode'}}}
            Add-Evidence $path 'CLFS authentication configuration. Missing values do not establish whether this OS/driver implements the mitigation.' @{Mode=$meaning;RawMode=$mode;TransitionPeriodSeconds=$period;LearningStart=$start;AutomaticTransitionDisabled=($period.State-eq'Present'-and$period.Value-eq0)} $(if($meaning-in@('AdministratorDisabled','SystemDisabled')){'Medium'}else{'Information'})
        }
        66 {
            $path="$system\Services\kernelquick";$type=Read-Registry $path 'Type';$image=Read-Registry $path 'ImagePath'
            if($type.State-eq'Present'-or$image.State-eq'Present'){Add-Evidence $path 'KernelQuick service-name indicator reported in ValleyRAT research; validate provenance before concluding compromise.' @{Type=$type;ImagePath=$image;Source='https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/'} 'High'}
            foreach($name in @('KernelQuick_HideFsFiles','KernelQuick_ProtectedImages')){$value=Read-Registry $path $name;if($value.State-eq'Present'){Add-Evidence "$path/$name" 'KernelQuick configuration indicator.' @{Present=$true;Value='[REDACTED]'} 'High'}}
            $key=Read-Registry 'HKLM:\SOFTWARE\IpDates' 'IpDates';if($key.State-eq'Present'){Add-Evidence 'HKLM:\SOFTWARE\IpDates' 'Registry indicator requiring contextual investigation.' @{Value='[REDACTED]'} 'Low'}
        }
        104 {
            Invoke-PolicyCheck 104
            foreach($key in Get-RegistryChildren "$root\CredentialsDelegation"){
                foreach($name in $key.GetValueNames()){$value=Read-Registry $key.PSPath $name;Add-Evidence ($key.Name+'/'+$name) 'Credential-delegation allow/deny target pattern.' @{State=$value.State;TargetPattern=$value.Value;Wildcard=([string]$value.Value-match'\*')} $(if([string]$value.Value-eq'*'-and$key.PSChildName-like'Allow*'){'Medium'}else{'Information'})}
            }
        }
        108 {
            Invoke-PolicyCheck 108
            foreach($adapter in Get-Limited @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)){Add-Evidence $adapter.Description 'Per-interface NetBIOS over TCP/IP policy (0=DHCP/default, 1=enabled, 2=disabled).' ($adapter|Select-Object InterfaceIndex,TcpipNetbiosOptions,DHCPEnabled)}
            foreach($adapter in Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop){Add-Evidence $adapter.Name 'IPv6 interface binding.' @{Enabled=$adapter.Enabled}}
        }
        109 {
            Invoke-PolicyCheck 109
            Add-Evidence 'WinHTTP' 'Machine WinHTTP proxy configuration.' @{Configuration=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\netsh.exe" 'winhttp show proxy')}
            foreach($base in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings','HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings')){
                $connections=Read-Registry ($base+'\Connections') 'DefaultConnectionSettings';if($connections.State-eq'Present'-and$connections.Value-is[byte[]]-and$connections.Value.Length-ge12){$flags=[BitConverter]::ToUInt32($connections.Value,8);Add-Evidence $base 'Internet Settings connection flags.' @{Direct=[bool]($flags-band1);Proxy=[bool]($flags-band2);AutoConfig=[bool]($flags-band4);AutoDetectWPAD=[bool]($flags-band8)}}
                foreach($zone in 0..4){Add-RegistryEvidence ($base+'\Zones\'+$zone) @('1200','1201','1400','1601','1806','1A00','2500')}
            }
        }
        114 {
            try{foreach($endpoint in Get-PSSessionConfiguration -ErrorAction Stop){Add-Evidence $endpoint.Name 'Remoting endpoint configuration.' ($endpoint|Select-Object Name,Permission,PSVersion,RunAsUser);$sddl=Get-OptionalProperty $endpoint 'SecurityDescriptorSddl';if($sddl){$sd=New-Object Security.AccessControl.RawSecurityDescriptor($sddl);$bytes=New-Object byte[] $sd.BinaryLength;$sd.GetBinaryForm($bytes,0);Add-DescriptorRights $endpoint.Name $bytes @{Execute=0x20;WriteDacl=0x40000;WriteOwner=0x80000} @(0x20005,0x20028,0x20020,0xf003f)}}}catch{Set-CheckPartial 'Remoting endpoint configuration unavailable or requires administrative access.'}
        }
        117 {
            try{Invoke-PolicyCheck 117}catch{Set-CheckPartial 'Audit-policy or security-service inventory requires additional access.'}
            Add-RegistryEvidence "$root\EventLog\EventForwarding\SubscriptionManager" @('1','2','3')
            try{Add-Evidence 'Event forwarding' 'Configured collector subscription identifiers.' @{Subscriptions=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\wecutil.exe" 'es')}}catch{Set-CheckPartial 'Event collector subscription inventory inaccessible.'}
            foreach($path in @("$system\Services\SysmonDrv\Parameters","$system\Services\Sysmon64\Parameters")){Add-RegistryEvidence $path @('HashingAlgorithm','Options')}
        }
        123 {
            foreach($profile in Get-NetFirewallProfile -ErrorAction Stop){Add-Evidence $profile.Name 'Firewall profile.' ($profile|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked)}
            foreach($rule in Get-Limited @(Get-NetFirewallRule -Enabled True -PolicyStore ActiveStore -ErrorAction Stop)){
                Add-Evidence $rule.Name 'Effective firewall rule with address, port, program and service filters.' @{Rule=($rule|Select-Object DisplayName,Direction,Action,Profile,PolicyStoreSourceType);Ports=@($rule|Get-NetFirewallPortFilter|Select-Object Protocol,LocalPort,RemotePort);Addresses=@($rule|Get-NetFirewallAddressFilter|Select-Object LocalAddress,RemoteAddress);Programs=@($rule|Get-NetFirewallApplicationFilter|Select-Object Program,Package);Services=@($rule|Get-NetFirewallServiceFilter|Select-Object Service)}
            }
        }
    }
}
