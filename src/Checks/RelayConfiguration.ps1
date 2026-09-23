function Invoke-RelayConfigurationCheck {
    Invoke-PolicyCheck 147
    Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' @('EnableLUA','ConsentPromptBehaviorAdmin')
    if(-not$script:Context.IncludeDomain){Set-CheckPartial 'Domain-controller relay prerequisites require -IncludeDomain; local NTDS values are not a substitute for DC policy.';return}
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if(-not$computer.PartOfDomain){Set-CheckSkipped 'Computer is not domain joined.' -SkipReason DomainNotJoined;return}
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain=Get-ADDomain -ErrorAction Stop
    $object=Get-ADObject -Identity $domain.DistinguishedName -Properties ms-DS-MachineAccountQuota -ErrorAction Stop
    Add-Evidence $domain.DNSRoot 'Domain machine-account creation quota; positive quota is a supporting prerequisite, not proof of a relay path.' @{MachineAccountQuota=$object.'ms-DS-MachineAccountQuota'}
    $dc=Get-ADDomainController -Discover -DomainName $domain.DNSRoot -ErrorAction Stop
    $payload=@{Host=[string]$dc.HostName}|ConvertTo-Json -Compress
    $encodedPayload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $code=@'
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
$base=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$p.Host)
$key=$null
try{$key=$base.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters',$false);if(-not$key){throw 'DC NTDS policy key unavailable'};$result=@{};foreach($name in @('LDAPServerIntegrity','LdapEnforceChannelBinding')){$result[$name]=@{Present=($name-in$key.GetValueNames());Value=$key.GetValue($name)}};$result|ConvertTo-Json -Depth 4 -Compress}finally{if($key){$key.Dispose()};$base.Dispose()}
'@
    $code=$code.Replace('__PAYLOAD__',$encodedPayload);$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    try{$settings=Invoke-ReadOnlyCommand "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -NonInteractive -EncodedCommand $encoded"|ConvertFrom-Json;Add-Evidence ([string]$dc.HostName) 'DC LDAP signing and channel-binding configuration. Missing values depend on the DC version and servicing; one discovered DC does not represent all DCs.' @{Settings=$settings;SigningExplicitlyNotRequired=($settings.LDAPServerIntegrity.Present-and$settings.LDAPServerIntegrity.Value-ne2);ChannelBindingExplicitlyDisabled=($settings.LdapEnforceChannelBinding.Present-and$settings.LdapEnforceChannelBinding.Value-eq0)}}catch{Set-CheckPartial 'Remote DC registry policy could not be read within the configured timeout; relay prerequisites remain unknown.' -ErrorRecord $_}
}
