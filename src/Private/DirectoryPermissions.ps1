function Get-DirectoryClassGuid {
    param([string]$Class)
    if($Class-notmatch'^[A-Za-z][A-Za-z0-9-]*$'){throw 'Invalid AD schema class name.'}
    $value=@(Get-Cached "ADClass/$Class" {
        $root=Get-ADRootDSE -ErrorAction Stop
        $schema=Get-ADObject -SearchBase $root.schemaNamingContext -LDAPFilter "(lDAPDisplayName=$Class)" -Properties schemaIDGUID -ErrorAction Stop
        if(-not$schema){throw 'Schema class not found.'}
        New-Object Guid(,$schema.schemaIDGUID)
    })
    [Guid]$value[0]
}
function Test-DirectoryRight {
    param([object]$Object,[uint32]$Right,[Guid]$Property=[Guid]::Empty)
    if(-not$Object.nTSecurityDescriptor){Set-CheckPartial 'An AD object security descriptor was unavailable.';return $null}
    $descriptor=$Object.nTSecurityDescriptor.GetSecurityDescriptorBinaryForm()
    $self=$null
    if($Object.PSObject.Properties['ObjectSid']-and$Object.ObjectSid){$sid=New-Object Security.Principal.SecurityIdentifier([string]$Object.ObjectSid);$self=New-Object byte[] $sid.BinaryLength;$sid.GetBinaryForm($self,0)}
    $class=Get-DirectoryClassGuid $Object.ObjectClass
    $result=[StealthPrivesc.Native]::CheckDirectoryAccess($descriptor,$Right,$class,$Property,$self)
    if($result.Error){Set-CheckPartial "Object-specific AD access evaluation failed (Win32 $($result.Error)).";return $null}
    return $result.Allowed
}
function Get-ADCSIndicators {
    param([int64]$NameFlags,[int64]$EnrollmentFlags,[int]$RequiredSignatures,[string[]]$Eku,[bool]$CanEnroll,[bool]$Published)
    $clientAuth=@('1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4','2.5.29.37.0')
    $Eku=@($Eku|Where-Object{-not[string]::IsNullOrWhiteSpace($_)})
    $authentication=($Eku.Count-eq0-or@($Eku|Where-Object{$_-in$clientAuth}).Count-gt0)
    $approval=($EnrollmentFlags-band2)-ne0
    $issuable=$CanEnroll-and$Published-and-not$approval-and$RequiredSignatures-eq0
    [pscustomobject]@{
        Published=$Published;CurrentTokenCanEnroll=$CanEnroll;ManagerApproval=$approval;RequiredSignatures=$RequiredSignatures
        SubjectSuppliedByRequester=($NameFlags-band1)-ne0;AuthenticationEku=$authentication
        ESC1Candidate=($issuable-and($NameFlags-band1)-ne0-and$authentication)
        ESC2Candidate=($issuable-and($Eku.Count-eq0-or'2.5.29.37.0'-in$Eku))
        ESC3Candidate=($issuable-and'1.3.6.1.4.1.311.20.2.1'-in$Eku)
        NoSecurityExtension=($EnrollmentFlags-band0x80000)-ne0
    }
}
