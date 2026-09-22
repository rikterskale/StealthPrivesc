function Invoke-DomainCheck {
    param([int]$Id)
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if(-not $computer.PartOfDomain){Set-CheckSkipped 'Computer is not joined to an Active Directory domain.';return}
    if(-not(Get-Module -ListAvailable ActiveDirectory)){Set-CheckSkipped 'Requires the Windows RSAT ActiveDirectory module.';return}
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain=Get-ADDomain -ErrorAction Stop
    switch($Id){
        141 {
            $base='CN=Policies,CN=System,'+$domain.DistinguishedName
            foreach($gpo in Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName,gPCFileSysPath,nTSecurityDescriptor -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){
                Add-Evidence $gpo.DistinguishedName 'Domain GPO container; application to this computer is not established.' @{Name=$gpo.displayName;FileSysPath=$gpo.gPCFileSysPath}
                Add-ADControlEvidence $gpo
            }
        }
        142 {
            # Query each schema separately: legacy or Windows LAPS attributes may not exist.
            foreach($attribute in @('ms-Mcs-AdmPwd','msLAPS-Password','msLAPS-EncryptedPassword')){
                try{$object=Get-ADComputer -Identity $env:COMPUTERNAME -Properties $attribute -ErrorAction Stop;$property=$object.PSObject.Properties[$attribute];$present=($null-ne$property -and $null-ne$property.Value -and @($property.Value).Count-gt0)
                    Add-Evidence $object.DistinguishedName 'Current computer LAPS attribute readability; value discarded.' @{Attribute=$attribute;ReturnedValue=$present;Value='[REDACTED]';Encrypted=($attribute-eq'msLAPS-EncryptedPassword')} $(if($present -and $attribute-ne'msLAPS-EncryptedPassword'){'Medium'}else{'Information'})
                }catch{Set-CheckPartial "LAPS attribute unavailable, schema absent or access denied: $attribute"}
            }
        }
        143 {foreach($account in Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){Add-Evidence $account.DistinguishedName 'gMSA retrieval authorization relationships; managed passwords are not requested.' @{Name=$account.Name;Principals=@($account.PrincipalsAllowedToRetrieveManagedPassword|ForEach-Object{[string]$_})}}}
        144 {foreach($object in Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=group)(objectClass=computer))' -Properties nTSecurityDescriptor -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){Add-ADControlEvidence $object}}
        145 {foreach($account in Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(objectClass=computer)))' -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet,PasswordNeverExpires,Enabled -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){Add-Evidence $account.DistinguishedName 'User account with SPNs; ticket requests are not performed.' @{Name=$account.Name;SPNs=@($account.ServicePrincipalName);EncryptionTypes=$account.'msDS-SupportedEncryptionTypes';PasswordLastSet=$account.PasswordLastSet;PasswordNeverExpires=$account.PasswordNeverExpires;Enabled=$account.Enabled} 'Low'}}
        146 {
            $root=Get-ADRootDSE -ErrorAction Stop
            $base='CN=Certificate Templates,CN=Public Key Services,CN=Services,'+$root.configurationNamingContext
            foreach($template in Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,nTSecurityDescriptor -ResultSetSize $script:Context.MaxItems -ErrorAction Stop){
                Add-Evidence $template.DistinguishedName 'AD CS template flags; publication, enrollment rights and CA policy must also be evaluated.' @{Name=$template.displayName;SubjectNameFlags=$template.'msPKI-Certificate-Name-Flag';EnrollmentFlags=$template.'msPKI-Enrollment-Flag';AuthorizedSignatures=$template.'msPKI-RA-Signature';EKUs=@($template.pKIExtendedKeyUsage)}
                Add-ADControlEvidence $template
            }
        }
    }
    Set-CheckPartial 'Domain queries are bounded by MaxItems; this is a sample, not a domain-wide assurance result.'
}
function Add-ADControlEvidence {
    param([object]$Object)
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$sids=@($identity.User.Value)+@([StealthPrivesc.Native]::Sids(2)|Where-Object{($_.Attributes-band4)-and-not($_.Attributes-band16)}|ForEach-Object Sid)}finally{$identity.Dispose()}
    if(-not$Object.nTSecurityDescriptor){Set-CheckPartial 'AD object security descriptor unavailable.';return}
    foreach($ace in $Object.nTSecurityDescriptor.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($ace.IdentityReference.Value-in$sids -and $ace.AccessControlType-eq'Allow' -and ([int]$ace.ActiveDirectoryRights-band0xc0128)){
            Add-Evidence $Object.DistinguishedName 'Potential AD object control ACE; deny ACEs, object-specific rights and inheritance need review.' @{Trustee=$ace.IdentityReference.Value;Rights=[string]$ace.ActiveDirectoryRights;ObjectType=[string]$ace.ObjectType;InheritedObjectType=[string]$ace.InheritedObjectType;Inherited=$ace.IsInherited} 'Low'
        }
    }
}
