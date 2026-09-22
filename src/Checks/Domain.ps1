function Invoke-DomainCheck {
    param([int]$Id)
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if(-not $computer.PartOfDomain){Set-CheckSkipped 'Computer is not joined to an Active Directory domain.';return}
    if(-not(Get-Module -ListAvailable ActiveDirectory)){Set-CheckSkipped 'Requires the Windows RSAT ActiveDirectory module.';return}
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain=Get-ADDomain -ErrorAction Stop
    switch($Id){
        141 {
            $applied=@()
            try{$applied=@(Get-CimInstance -Namespace root\RSOP\Computer -ClassName RSOP_GPO -ErrorAction Stop)}catch{Set-CheckPartial 'Computer RSoP data unavailable; current applied GPOs cannot be confirmed.'}
            foreach($entry in Get-Limited $applied){
                $guid=[regex]::Match([string]$entry.guidName,'\{[0-9a-fA-F-]{36}\}').Value
                if(-not$guid){continue}
                $dn='CN='+$guid+',CN=Policies,CN=System,'+$domain.DistinguishedName
                $gpo=Get-ADObject -Identity $dn -Properties displayName,gPCFileSysPath,nTSecurityDescriptor -ErrorAction Stop
                Add-Evidence $gpo.DistinguishedName 'GPO reported by computer RSoP.' @{Name=$gpo.displayName;FileSysPath=$gpo.gPCFileSysPath;Enabled=$entry.enabled;AccessDenied=$entry.accessDenied;FilterAllowed=$entry.filterAllowed}
                Add-ADControlEvidence $gpo
                if($gpo.gPCFileSysPath){Add-WritablePath $gpo.gPCFileSysPath 'Writable SYSVOL directory for an applied GPO.';foreach($item in Get-BoundedFiles @($gpo.gPCFileSysPath) -Depth 4 -Directories){Add-WritablePath $item.FullName 'Writable applied GPO file or subdirectory.'}}
            }
            foreach($root in @("$env:SystemRoot\System32\GroupPolicy","$env:SystemRoot\System32\GroupPolicyUsers")){foreach($file in Get-BoundedFiles @($root) -Depth 4){Add-Artifact $file.FullName 'Local GPO configuration';Add-WritablePath $file.FullName 'Writable local GPO configuration';if($file.Name-eq'Registry.pol'){Read-RegistryPolicyMetadata $file.FullName}}}
        }
        142 {
            # Query each schema separately: legacy or Windows LAPS attributes may not exist.
            foreach($attribute in @('ms-Mcs-AdmPwd','msLAPS-Password','msLAPS-EncryptedPassword')){
                try{$object=Get-ADComputer -Identity $env:COMPUTERNAME -Properties $attribute -ErrorAction Stop;$property=$object.PSObject.Properties[$attribute];$present=($null-ne$property -and $null-ne$property.Value -and @($property.Value).Count-gt0 -and -not($property.Value-is[string]-and[string]::IsNullOrEmpty($property.Value)))
                    Add-Evidence $object.DistinguishedName 'Current computer LAPS attribute readability; value discarded.' @{Attribute=$attribute;ReturnedValue=$present;Value='[REDACTED]';Encrypted=($attribute-eq'msLAPS-EncryptedPassword')} $(if($present -and $attribute-ne'msLAPS-EncryptedPassword'){'Medium'}else{'Information'})
                }catch{Set-CheckPartial "LAPS attribute unavailable, schema absent or access denied: $attribute"}
            }
        }
        143 {foreach($account in Get-Limited @(Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword -ResultSetSize ($script:Context.MaxItems+1) -ErrorAction Stop)){Add-Evidence $account.DistinguishedName 'gMSA retrieval authorization relationships.' @{Name=$account.Name;Principals=@($account.PrincipalsAllowedToRetrieveManagedPassword|ForEach-Object{[string]$_})};if($script:Context.IncludeSensitive){$blob=$null;try{$value=Get-ADServiceAccount -Identity $account.DistinguishedName -Properties 'msDS-ManagedPassword' -ErrorAction Stop;$blob=$value.'msDS-ManagedPassword';Add-Evidence $account.DistinguishedName 'gMSA managed-password material readability; bytes erased after checking presence.' @{Returned=($null-ne$blob-and$blob.Length-gt0);Value='[REDACTED]'} $(if($blob){'Medium'}else{'Information'})}catch{Set-CheckPartial 'Some gMSA password attributes could not be queried.'}finally{if($blob-is[byte[]]){[Array]::Clear($blob,0,$blob.Length)}}}}}
        144 {foreach($object in Get-Limited @(Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=group)(objectClass=computer))' -Properties nTSecurityDescriptor,objectSid -ResultSetSize ($script:Context.MaxItems+1) -ErrorAction Stop)){Add-ADControlEvidence $object}}
        145 {foreach($account in Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(objectClass=computer)))' -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet,PasswordNeverExpires,Enabled -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){Add-Evidence $account.DistinguishedName 'User account with SPNs; ticket requests are not performed.' @{Name=$account.Name;SPNs=@($account.ServicePrincipalName);EncryptionTypes=$account.'msDS-SupportedEncryptionTypes';PasswordLastSet=$account.PasswordLastSet;PasswordNeverExpires=$account.PasswordNeverExpires;Enabled=$account.Enabled} 'Low'}}
        146 {
            $root=Get-ADRootDSE -ErrorAction Stop
            $published=@{}
            $caBase='CN=Enrollment Services,CN=Public Key Services,CN=Services,'+$root.configurationNamingContext
            foreach($ca in Get-ADObject -SearchBase $caBase -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates,dNSHostName,nTSecurityDescriptor -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){
                foreach($name in $ca.certificateTemplates){if(-not$published.ContainsKey($name)){$published[$name]=@()};$published[$name]+=$ca.dNSHostName}
                Add-Evidence $ca.DistinguishedName 'AD CS enrollment service and published templates.' @{Host=$ca.dNSHostName;Templates=@($ca.certificateTemplates)}
                Add-ADControlEvidence $ca
            }
            $base='CN=Certificate Templates,CN=Public Key Services,CN=Services,'+$root.configurationNamingContext
            foreach($template in Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,nTSecurityDescriptor -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){
                $canEnroll=Test-DirectoryRight $template 0x100 ([Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')
                $indicators=Get-ADCSIndicators -NameFlags ([int64]$template.'msPKI-Certificate-Name-Flag') -EnrollmentFlags ([int64]$template.'msPKI-Enrollment-Flag') -RequiredSignatures ([int]$template.'msPKI-RA-Signature') -Eku @($template.pKIExtendedKeyUsage) -CanEnroll ($canEnroll-eq$true) -Published ($published.ContainsKey($template.Name))
                Add-Evidence $template.DistinguishedName 'AD CS template exposure assessment combining publication, current-token enrollment access, issuance controls and EKUs. CA-side policy can further constrain enrollment.' @{Name=$template.displayName;PublishingCAs=@($published[$template.Name]);Indicators=$indicators;EnrollmentAccessKnown=($null-ne$canEnroll);EKUs=@($template.pKIExtendedKeyUsage)} $(if($indicators.ESC1Candidate-or$indicators.ESC2Candidate-or$indicators.ESC3Candidate){'High'}else{'Information'})
                Add-ADControlEvidence $template
            }
        }
    }
    Set-CheckPartial 'Domain queries are bounded by MaxItems; this is a sample, not a domain-wide assurance result.'
}
function Add-ADControlEvidence {
    param([object]$Object)
    if(-not$Object.nTSecurityDescriptor){Set-CheckPartial 'AD object security descriptor unavailable.';return}
    foreach($right in @(@('WriteDacl',0x40000),@('WriteOwner',0x80000),@('Delete',0x10000),@('WriteAllProperties',0x20))){
        if((Test-DirectoryRight $Object $right[1])-eq$true){Add-Evidence $Object.DistinguishedName 'Current token has an AD object control right after Windows object-specific DACL evaluation.' @{Right=$right[0];Method='AccessCheckByType'} 'Medium'}
    }
    $properties=@($Object.nTSecurityDescriptor.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object{[Guid]$_.ObjectType-ne[Guid]::Empty}|ForEach-Object ObjectType|Select-Object -Unique)
    foreach($property in $properties){
        foreach($right in @(@('WriteProperty',0x20),@('ExtendedRight',0x100))){
            if((Test-DirectoryRight $Object $right[1] $property)-eq$true){Add-Evidence $Object.DistinguishedName 'Current token has an object-specific AD right.' @{Right=$right[0];ObjectType=[string]$property;Method='AccessCheckByType'} 'Low'}
        }
    }
}
