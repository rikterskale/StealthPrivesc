
function Get-CodeIntegrityPolicy {
    <#
    .SYNOPSIS
    Parser for binary code integrity files.

    Author: @itm4n
    Credit: Matthew Graeber (@mattifestation), James Forshaw (@tiraniddo), Gerhart (@gerhart01)
    License: BSD 3-Clause

    .DESCRIPTION
    Get-CodeIntegrityPolicy parses a binary file that contains a Code Integrity policy

    .PARAMETER FilePath
    Path of a binary code integrity file.

    .EXAMPLE
    PS C:\> Get-CodeIntegrityPolicy -FilePath C:\Windows\System32\CodeIntegrity\DriversIPolicy.p7b

    PolicyTypeID         : D2BDA982-CCF6-4344-AC5B-0B44427B6816
    PlatformID           : 2E07F7E4-194C-4D20-B7C9-6F44A6C5A234
    PolicyVersion        : 10.0.27720.0
    FileRules            : {@{Id=ID_DENY_D_0001; Type=Deny; MinimumVersion=65535.65535.65535.65535;
                           Hash=000E984D3EEBC54259A24A17745EED07D9C3658B86462CB5EBC26381302F7A38}, @{Id=ID_DENY_D_0002;
                           Type=Deny; MinimumVersion=65535.65535.65535.65535;
                           Hash=002223FDDC5658EA22B7A8979984A9B54F63B316}, @{Id=ID_DENY_D_0003; Type=Deny;
                           MinimumVersion=65535.65535.65535.65535;
                           Hash=00573981F5478DBEC6704FB77131AD92E91F00178CCCCCAEB2F70763E927F2D7}, @{Id=ID_DENY_D_0004;
                           Type=Deny; MinimumVersion=65535.65535.65535.65535;
                           Hash=005C8117D7BF2E73E6139D3C91F24B70E22A844E}...}
    SignerRules          : {@{Id=ID_SIGNER_S_0001; Name=Signer 1; CertRootType=TBS;
                           CertRootValue=4843A82ED3B1F2BFBEE9671960E1940C942F688D;
                           FileAttribRef=System.Collections.Generic.List`1[System.Management.Automation.PSObject]},
                           @{Id=ID_SIGNER_S_0002; Name=Signer 2; CertRootType=TBS;
                           CertRootValue=4678C6E4A8787A8E6ED2BCE8792B122F6C08AFD8;
                           FileAttribRef=System.Collections.Generic.List`1[System.Management.Automation.PSObject]},
                           @{Id=ID_SIGNER_S_0003; Name=Signer 3; CertRootType=TBS;
                           CertRootValue=A08E79C386083D875014C409C13D144E0A24386132980DF11FF59737C8489EB1;
                           CertPublisher=CAPCOM Co.,Ltd.}, @{Id=ID_SIGNER_S_0004; Name=Signer 4; CertRootType=TBS;
                           CertRootValue=D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE; CertOemID=Cheat
                           Engine}...}
    SigningScenarios     : {@{Id=ID_SIGNINGSCENARIO_DRIVERS_1; Value=131; MinimumHashAlgorithmSpecified=False;
                           ProductSigners=}, @{Id=ID_SIGNINGSCENARIO_WINDOWS; Value=12;
                           MinimumHashAlgorithmSpecified=False; ProductSigners=}}
    HvciOptionsSpecified : False
    Settings             : {@{Provider=PolicyInfo; Key=Information; ValueName=Id; Value=10.0.27720.0},
                           @{Provider=PolicyInfo; Key=Information; ValueName=Name; Value=Microsoft Windows Driver Policy},
                           @{Provider=PolicyInfo; Key=NoRevalidationUponRefresh; ValueName=NoRevalidationUponRefreshValue;
                           Value=True}}
    PolicyID             : d2bda982-ccf6-4344-ac5b-0b44427b6816
    BasePolicyID         : d2bda982-ccf6-4344-ac5b-0b44427b6816

    .NOTES
    All credit for the parser's code goes to @mattifestation, @tiraniddo, and @gerhart01. This is an adaptation of it so that it better integrates into PrivescCheck. In particular, I removed the custom assembly definition to avoid the .Net artifacts generation at runtime, and the XML serializer as it is not required in this use case.

    .LINK
    https://gist.github.com/gerhart01/156a93856d48a11b7772bcb15c652160
    #>

    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [String] $FilePath
    )

    begin {
        $FunctionalCheck = $true

        # Namespace "System.Security" is not loaded by default
        try { Add-Type -Assembly System.Security } catch { $FunctionalCheck = $false; Write-Warning "Failed to load assembly: System.Security" }

        $GuidLength = 0x10
        $HeaderLengthMax = 0x44

        $BinaryReader = $null
        $MemoryStream = $null
    }

    process {
        if (-not $FunctionalCheck) { return }

        $FilePathResolved = Resolve-Path -Path $FilePath -ErrorAction SilentlyContinue
        if ($null -eq $FilePathResolved) {
            Write-Warning "[GCIP] Failed to resolve policy file path ($($FilePath))."
            return
        }

        Write-Verbose "[GCIP] Policy file path is valid ($($FilePathResolved))."

        try {
            $CIPolicyBytes = [Byte[]] [IO.File]::ReadAllBytes($FilePathResolved)
        }
        catch {
            Write-Warning "[GCIP] Failed to read policy file ($($_.Exception.Message))."
            return
        }

        Write-Verbose "[GCIP] Read $($CIPolicyBytes.Count) bytes from policy file."

        try {
            $ContentType = [Security.Cryptography.Pkcs.ContentInfo]::GetContentType($CIPolicyBytes)
            if ($ContentType.Value -eq '1.2.840.113549.1.7.2') {
                Write-Verbose "[GCIP] File is a PKCS#7 SignedData blob; decoding to extract the inner policy."
                $Cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                $Cms.Decode($CIPolicyBytes)
                $CIPolicyBytes = $Cms.ContentInfo.Content
                Write-Verbose "[GCIP] Inner (unwrapped) policy is $($CIPolicyBytes.Count) bytes."
                if ($CIPolicyBytes[0] -eq 4) {
                    # Policy is stored as an OCTET STRING
                    Write-Verbose "[GCIP] Inner policy is wrapped in an ASN.1 OCTET STRING; unwrapping."
                    $PolicySize = $CIPolicyBytes[1]
                    $BaseIndex = 2
                    if (($PolicySize -band 0x80) -eq 0x80) {
                        $SizeCount = $PolicySize -band 0x7F
                        $BaseIndex += $SizeCount
                        $PolicySize = 0
                        for ($i = 0; $i -lt $SizeCount; $i++) {
                            $PolicySize = $PolicySize -shl 8
                            $PolicySize = $PolicySize -bor $CIPolicyBytes[2 + $i]
                        }
                    }
                    $CIPolicyBytes = $CIPolicyBytes[$BaseIndex..($BaseIndex + $PolicySize - 1)]
                }
            }
        }
        catch {
            Write-Verbose "[GCIP] Not a PKCS#7 signed policy ($($_.Exception.Message)); treating the file as a raw binary policy."
        }

        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$CIPolicyBytes)
        $BinaryReader = New-Object -TypeName System.IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)

        $CIPolicy = New-Object -TypeName PSObject

        try {
            $Signature = $BinaryReader.ReadInt32()

            if ($Signature -lt 2 -or $Signature -gt 9) {
                Write-Warning "[GCIP] Invalid CI policy header (0x$($Signature.ToString('X8'))). This file is likely not a binary CI policy."
                return
            }

            $PolicyFormatVersion = $Signature
            $PolicyTypeID = [Guid] ([Byte[]] $BinaryReader.ReadBytes($GuidLength))
            $PlatformID = [Guid] ([Byte[]] $BinaryReader.ReadBytes($GuidLength))

            $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "PolicyTypeID" -Value $PolicyTypeID.ToString().ToUpper()
            $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "PlatformID" -Value $PlatformID.ToString().ToUpper()

            $OptionFlags = $BinaryReader.ReadInt32()
            if (($OptionFlags -band [Int32]::MinValue) -ne [Int32]::MinValue) {
                Write-Warning "[GCIP] Invalid policy options flag (0x$($OptionFlags.ToString('X8')))."
                return
            }

            $CIPolicy | Add-Member -NotePropertyName OptionFlags -NotePropertyValue ($OptionFlags -band [Int32]::MaxValue)

            $EKURuleEntryCount = $BinaryReader.ReadInt32()
            $FileRuleEntryCount = $BinaryReader.ReadInt32()
            $SignerRuleEntryCount = $BinaryReader.ReadInt32()
            $SignerScenarioEntryCount = $BinaryReader.ReadInt32()
            Write-Verbose "[GCIP] EKU: $($EKURuleEntryCount); File: $($FileRuleEntryCount); Signer: $($SignerRuleEntryCount); Signer Scenario: $($SignerScenarioEntryCount)."

            $Revision = $BinaryReader.ReadUInt16()
            $Build = $BinaryReader.ReadUInt16()
            $Minor = $BinaryReader.ReadUInt16()
            $Major = $BinaryReader.ReadUInt16()
            $PolicyVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision
            Write-Verbose "[GCIP] Policy version: $($PolicyVersion)"

            $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "PolicyVersion" -Value $PolicyVersion

            $HeaderLength = $BinaryReader.ReadInt32()
            if ($HeaderLength -ne ($HeaderLengthMax - 4)) {
                Write-Warning "[GCIP] Invalid header footer (0x$($HeaderLength.ToString('X8')))."
                return
            }

            if ($EKURuleEntryCount -gt 0) {
                $EKURuleArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $EKURuleEntryCount; $i++) {
                    $EKURule = New-Object -TypeName PSObject

                    $EkuValueLen = $BinaryReader.ReadUInt32()
                    $PaddingBytes = 4 - $EkuValueLen % 4 -band 3
                    $EKUValueBytes = $BinaryReader.ReadBytes($EkuValueLen)
                    $null = $BinaryReader.ReadBytes($PaddingBytes)
                    $EKUValueBytesCopy = $EKUValueBytes
                    $EKUValueBytesCopy[0] = 6
                    $OID = ConvertTo-CodeIntegrityOid -EncodedOIDBytes $EKUValueBytesCopy

                    $EKURule | Add-Member -MemberType "NoteProperty" -Name "Id" -Value "ID_EKU_E_$(($i + 1).ToString('X4'))"
                    $EKURule | Add-Member -MemberType "NoteProperty" -Name "Value" -Value (Convert-ByteArrayToHexString -Bytes $EKUValueBytes)

                    if ($OID) {
                        if ($OID.FriendlyName) {
                            $EKURule | Add-Member -MemberType "NoteProperty" -Name "FriendlyName" -Value $OID.FriendlyName
                        } elseif ($OID.Value) {
                            $EKURule | Add-Member -MemberType "NoteProperty" -Name "FriendlyName" -Value $OID.Value
                        }
                    }

                    $EKURuleArray.Add($EKURule)
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "EKURules" -Value $EKURuleArray
                Write-Verbose "[GCIP] Parsed $($EKURuleArray.Count)/$($EKURuleEntryCount) EKU(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            if ($FileRuleEntryCount -gt 0) {
                $FileRuleArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                    $FileRule = New-Object -TypeName PSObject

                    $FileRuleTypeValue = $BinaryReader.ReadInt32()
                    switch ($FileRuleTypeValue) {
                        0 {
                            $TypeName = 'Deny'
                            $ID = "ID_DENY_D_$(($i + 1).ToString('X4'))"
                        }

                        1 {
                            $TypeName = 'Allow'
                            $ID = "ID_ALLOW_A_$(($i + 1).ToString('X4'))"
                        }

                        2 {
                            $TypeName = 'FileAttrib'
                            $ID = "ID_FILEATTRIB_F_$(($i + 1).ToString('X4'))"
                        }

                        default { throw "Invalid file rule type: 0x$($FileRuleTypeValue.ToString('X8'))" }
                    }

                    $FileRule | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $ID
                    $FileRule | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $TypeName

                    $FileName = Get-BinaryString -BinaryReader $BinaryReader
                    if ($FileName) {
                        $FileRule | Add-Member -MemberType "NoteProperty" -Name "FileName" -Value $FileName
                    }

                    $Revision = $BinaryReader.ReadUInt16()
                    $Build = $BinaryReader.ReadUInt16()
                    $Minor = $BinaryReader.ReadUInt16()
                    $Major = $BinaryReader.ReadUInt16()
                    $MinimumVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision

                    if ($MinimumVersion -ne '0.0.0.0') {
                        $FileRule | Add-Member -MemberType "NoteProperty" -Name "MinimumVersion" -Value $MinimumVersion
                    }

                    $HashLen = $BinaryReader.ReadUInt32()
                    if ($HashLen -gt 0) {
                        $PaddingBytes = 4 - $HashLen % 4 -band 3
                        $HashBytes = $BinaryReader.ReadBytes($HashLen)
                        $null = $BinaryReader.ReadBytes($PaddingBytes)
                        $FileRule | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value (Convert-ByteArrayToHexString -Bytes $HashBytes)
                    }

                    $FileRuleArray.Add($FileRule)
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "FileRules" -Value $FileRuleArray
                Write-Verbose "[GCIP] Parsed $($FileRuleArray.Count)/$($FileRuleEntryCount) file rule(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            if ($SignerRuleEntryCount) {
                $SignerRuleArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $SignerRuleEntryCount; $i++) {
                    $SignerRule = New-Object -TypeName PSObject

                    $SignerRule | Add-Member -MemberType "NoteProperty" -Name "Id" -Value "ID_SIGNER_S_$(($i + 1).ToString('X4'))"
                    $SignerRule | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Signer $($i + 1)"

                    $CertRootTypeValue = $BinaryReader.ReadInt32()
                    switch ($CertRootTypeValue) {
                        0 { $CertRootType = 'TBS' }
                        1 { $CertRootType = 'WellKnown' }
                        default { throw "Invalid certificate root type: 0x$($CertRootTypeValue.ToString('X8'))" }
                    }

                    if ($CertRootType -eq 'TBS') {
                        $CertRootLength = $BinaryReader.ReadUInt32()
                        if ($CertRootLength) {
                            $PaddingBytes = 4 - $CertRootLength % 4 -band 3
                            [Byte[]] $CertRootBytes = $BinaryReader.ReadBytes($CertRootLength)
                            $null = $BinaryReader.ReadBytes($PaddingBytes)
                        }
                    } else {
                        $CertRootBytes = [Byte[]] @(($BinaryReader.ReadUInt32() -band 0xFF))
                    }

                    $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertRootType" -Value $CertRootType
                    $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertRootValue" -Value (Convert-ByteArrayToHexString -Bytes $CertRootBytes)

                    $CertEKULength = $BinaryReader.ReadUInt32()
                    if ($CertEKULength -gt 0) {
                        $EKUArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                        for ($j = 0; $j -lt $CertEKULength; $j++) {
                            $EKUIndex = $BinaryReader.ReadUInt32()
                            $EKUArray.Add($CIPolicy.EKURules[$EKUIndex].Id)
                        }

                        $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertEKU" -Value $EKUArray
                    }

                    $CertIssuer = Get-BinaryString -BinaryReader $BinaryReader
                    if ($CertIssuer) {
                        $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertIssuer" -Value $CertIssuer
                    }

                    $CertPublisher = Get-BinaryString -BinaryReader $BinaryReader
                    if ($CertPublisher) {
                        $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertPublisher" -Value $CertPublisher
                    }

                    $CertOemID = Get-BinaryString -BinaryReader $BinaryReader
                    if ($CertOemID) {
                        $SignerRule | Add-Member -MemberType "NoteProperty" -Name "CertOemID" -Value $CertOemID
                    }

                    $FileAttribRefLength = $BinaryReader.ReadUInt32()
                    if ($FileAttribRefLength -gt 0) {
                        $FileAttribRefArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                        for ($j = 0; $j -lt $FileAttribRefLength; $j++) {
                            $FileAttribRefIndex = $BinaryReader.ReadUInt32()
                            $FileAttribRefArray.Add($CIPolicy.FileRules[$FileAttribRefIndex].Id)
                        }

                        $SignerRule | Add-Member -MemberType "NoteProperty" -Name "FileAttribRef" -Value $FileAttribRefArray
                    }

                    $SignerRuleArray.Add($SignerRule)
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "SignerRules" -Value $SignerRuleArray
                Write-Verbose "[GCIP] Parsed $($SignerRuleArray.Count)/$($SignerRuleEntryCount) signer(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            $UpdatePolicySignersLength = $BinaryReader.ReadUInt32()
            if ($UpdatePolicySignersLength -gt 0) {
                $UpdatePolicySigners = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $UpdatePolicySignersLength; $i++) {
                    $UpdatePolicySignersIndex = $BinaryReader.ReadUInt32()
                    $UpdatePolicySigners.Add($SignerRuleArray[$UpdatePolicySignersIndex].Id)
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "UpdatePolicySigners" -Value $UpdatePolicySigners
                Write-Verbose "[GCIP] Parsed $($UpdatePolicySigners.Count)/$($UpdatePolicySignersLength) update policy signer(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            $CISignersLength = $BinaryReader.ReadUInt32()
            if ($CISignersLength -gt 0) {
                $CISigners = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $CISignersLength; $i++) {
                    $CISignersIndex = $BinaryReader.ReadUInt32()
                    $CISigners.Add($CIPolicy.SignerRules[$CISignersIndex].Id)
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "CISigners" -Value $CISigners
                Write-Verbose "[GCIP] Parsed $($CISigners.Count)/$($CISignersLength) CI signer(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            if ($SignerScenarioEntryCount -gt 0) {
                $SignerScenarioArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                for ($i = 0; $i -lt $SignerScenarioEntryCount; $i++) {
                    $SigningScenarioValue = [Byte] ($BinaryReader.ReadUInt32() -band 0xFF)

                    $DriverSigningScenarioCount = 1
                    $WindowsSigningScenarioCount = 0

                    switch ($SigningScenarioValue) {
                        131 {
                            $ID = "ID_SIGNINGSCENARIO_DRIVERS_$($DriverSigningScenarioCount.ToString('X'))"
                            $DriverSigningScenarioCount++
                        }

                        12 {
                            $ID = 'ID_SIGNINGSCENARIO_WINDOWS'
                            if ($WindowsSigningScenarioCount) {
                                $ID += "_$(($WindowsSigningScenarioCount + 1).ToString('X'))"
                            }
                            $WindowsSigningScenarioCount++
                        }

                        default {
                            $ID = "ID_SIGNINGSCENARIO_S_$(($i + 1).ToString('X4'))"
                        }
                    }

                    $SigningScenario = New-Object -TypeName PSObject
                    $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Id
                    $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $SigningScenarioValue

                    $InheritedScenarios = $null

                    $InheritedScenarioLength = $BinaryReader.ReadUInt32()
                    if ($InheritedScenarioLength -gt 0) {
                        $InheritedScenarios = [System.Collections.Generic.List[UInt32]]::new()

                        for ($j = 0; $j -lt $InheritedScenarioLength; $j++) {
                            $InheritedScenarios.Add($BinaryReader.ReadUInt32())
                        }

                        $InheritedScenariosString = $InheritedScenarios -join ','
                        $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "InheritedScenarios" -Value $InheritedScenariosString
                    }

                    $MinimumHashValueValue = [UInt16] ($BinaryReader.ReadUInt32() -band [UInt16]::MaxValue)
                    if ($MinimumHashValueValue -ne 0x800C) {
                        $MinimumHashValue = $MinimumHashValueValue
                        $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "MinimumHashAlgorithmSpecified" -Value $True
                        $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "MinimumHashAlgorithm" -Value $MinimumHashValue
                    }
                    else {
                        $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "MinimumHashAlgorithmSpecified" -Value $False
                    }

                    1..3 | ForEach-Object {
                        $AllowedSignersCount = $BinaryReader.ReadUInt32()
                        $AllowSignersObject = $null

                        if ($AllowedSignersCount -gt 0) {
                            $AllowSignersObject = New-Object -TypeName PSObject
                            $AllowSignerArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                            for ($j = 0; $j -lt $AllowedSignersCount; $j++) {
                                $AllowedSignerIndex = $BinaryReader.ReadUInt32()
                                $ExceptDenyRuleLength = $BinaryReader.ReadUInt32()
                                $ExceptDenyRulesArray = $null
                                if ($ExceptDenyRuleLength -gt 0) {
                                    $ExceptDenyRulesArray = [System.Collections.Generic.List[String]]::new()
                                    for ($k = 0; $k -lt $ExceptDenyRuleLength; $k++) {
                                        $ExceptDenyRuleIndex = $BinaryReader.ReadUInt32()
                                        $ExceptDenyRulesArray.Add($CIPolicy.FileRules[$ExceptDenyRuleIndex].Id)
                                    }
                                }

                                $AllowSignerEntry = New-Object -TypeName PSObject
                                $AllowSignerEntry | Add-Member -MemberType "NoteProperty" -Name "SignerId" -Value $CIPolicy.SignerRules[$AllowedSignerIndex].Id
                                $AllowSignerEntry | Add-Member -MemberType "NoteProperty" -Name "ExceptDenyRule" -Value $ExceptDenyRulesArray
                                $AllowSignerArray.Add($AllowSignerEntry)
                            }

                            $AllowSignersObject | Add-Member -MemberType "NoteProperty" -Name "AllowedSigner" -Value $AllowSignerArray
                        }

                        $DeniedSignersCount = $BinaryReader.ReadUInt32()
                        $DeniedSignersObject = $null
                        if ($DeniedSignersCount -gt 0) {
                            $DeniedSignersObject = New-Object -TypeName PSObject
                            $DeniedSignerArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                            for ($j = 0; $j -lt $DeniedSignersCount; $j++) {
                                $DeniedSignerIndex = $BinaryReader.ReadUInt32()
                                $ExceptAllowRuleLength = $BinaryReader.ReadUInt32()
                                $ExceptAllowRulesArray = $null
                                if ($ExceptAllowRuleLength -gt 0) {
                                    $ExceptAllowRulesArray = [System.Collections.Generic.List[String]]::new()
                                    for ($k = 0; $k -lt $ExceptAllowRuleLength; $k++) {
                                        $ExceptAllowRuleIndex = $BinaryReader.ReadUInt32()
                                        $ExceptAllowRulesArray.Add($CIPolicy.SignerRules[$ExceptAllowRuleIndex].Id)
                                    }
                                }

                                $DeniedSignerEntry = New-Object -TypeName PSObject
                                $DeniedSignerEntry | Add-Member -MemberType "NoteProperty" -Name "SignerId" -Value $CIPolicy.SignerRules[$DeniedSignerIndex].Id
                                $DeniedSignerEntry | Add-Member -MemberType "NoteProperty" -Name "ExceptDenyRule" -Value $ExceptAllowRulesArray
                                $DeniedSignerArray.Add($DeniedSignerEntry)
                            }

                            $DeniedSignersObject | Add-Member -MemberType "NoteProperty" -Name "DeniedSigner" -Value $DeniedSignerArray
                        }

                        $FileRulesRefCount = $BinaryReader.ReadUInt32()
                        $FileRulesRefObject = $null
                        if ($FileRulesRefCount -gt 0) {
                            $FileRulesRefObject = New-Object -TypeName PSObject
                            $FileRuleRefArray = [System.Collections.Generic.List[String]]::new()

                            for ($j = 0; $j -lt $FileRulesRefCount; $j++) {
                                $FileRulesRefIndex = $BinaryReader.ReadUInt32()
                                $FileRuleRefArray.Add($CIPolicy.FileRules[$FileRulesRefIndex].Id)
                            }

                            $FileRulesRefObject | Add-Member -MemberType "NoteProperty" -Name "FileRuleRef" -Value $FileRuleRefArray
                        }

                        $NullSigner = $False
                        if (($AllowedSignersCount -eq 0) -and ($DeniedSignersCount -eq 0) -and ($FileRulesRefCount -eq 0)) {
                            $NullSigner = $True
                        }

                        switch ($_) {
                            1 { # Product signers
                                if (-not $NullSigner) {
                                    $ProductSigner = New-Object -TypeName PSObject

                                    if ($AllowSignersObject) { $ProductSigner | Add-Member -MemberType "NoteProperty" -Name "AllowedSigners" -Value $AllowSignersObject }
                                    if ($DeniedSignersObject) { $ProductSigner | Add-Member -MemberType "NoteProperty" -Name "DeniedSigners" -Value $DeniedSignersObject }
                                    if ($FileRulesRefObject) { $ProductSigner | Add-Member -MemberType "NoteProperty" -Name "FileRulesRef" -Value $FileRulesRefObject }

                                    $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "ProductSigners" -Value $ProductSigner
                                }
                            }

                            2 { # Test signers
                                if (-not $NullSigner) {
                                    $TestSigner = New-Object -TypeName PSObject

                                    if ($AllowSignersObject) { $TestSigner | Add-Member -MemberType "NoteProperty" -Name "AllowedSigners" -Value $AllowSignersObject }
                                    if ($DeniedSignersObject) { $TestSigner | Add-Member -MemberType "NoteProperty" -Name "DeniedSigners" -Value $DeniedSignersObject }
                                    if ($FileRulesRefObject) { $TestSigner | Add-Member -MemberType "NoteProperty" -Name "FileRulesRef" -Value $FileRulesRefObject }

                                    $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "TestSigners" -Value $TestSigner
                                }
                            }

                            3 { # Test signing signers
                                if (-not $NullSigner) {
                                    $TestSigningSigner = New-Object -TypeName PSObject

                                    if ($AllowSignersObject) { $TestSigningSigner | Add-Member -MemberType "NoteProperty" -Name "AllowedSigners" -Value $AllowSignersObject }
                                    if ($DeniedSignersObject) { $TestSigningSigner | Add-Member -MemberType "NoteProperty" -Name "DeniedSigners" -Value $DeniedSignersObject }
                                    if ($FileRulesRefObject) { $TestSigningSigner | Add-Member -MemberType "NoteProperty" -Name "FileRulesRef" -Value $FileRulesRefObject }

                                    $SigningScenario | Add-Member -MemberType "NoteProperty" -Name "TestSigningSigners" -Value $TestSigningSigner
                                }
                            }
                        }
                    }

                    $SignerScenarioArray.Add($SigningScenario)
                }

                for ($i = 0; $i -lt $SignerScenarioEntryCount; $i++) {
                    if ($SignerScenarioArray[$i].InheritedScenarios) {
                        $ScenarioIndices = [Int[]] ($SignerScenarioArray[$i].InheritedScenarios -split ',')
                        $SignerScenarioArray[$i].InheritedScenarios = ($ScenarioIndices | ForEach-Object { $SignerScenarioArray[$_].Id }) -join ','
                    }
                }

                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "SigningScenarios" -Value $SignerScenarioArray
                Write-Verbose "[GCIP] Parsed $($SignerScenarioArray.Count)/$($SignerScenarioEntryCount) signing scenario(s). Stream position: $($BinaryReader.BaseStream.Position)."
            }

            $HVCIOptions = $BinaryReader.ReadUInt32()
            Write-Verbose "[GCIP] HVCI Options: 0x$($HVCIOptions.ToString('X8'))."

            if ($HVCIOptions) {
                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "HVCIOptions" -Value $HVCIOptions
                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "HvciOptionsSpecified" -Value $True
            } else {
                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "HvciOptionsSpecified" -Value $False
            }

            if ($PolicyFormatVersion -ge 3) {
                Write-Verbose "[GCIP] Format version $($PolicyFormatVersion): parsing the Secure Settings section. Stream position: $($BinaryReader.BaseStream.Position)."
                try {
                    $SettingCount = $BinaryReader.ReadUInt32()
                    Write-Verbose "[GCIP] Secure Settings: $($SettingCount) entry(ies)."

                    if ($SettingCount -gt 0) {
                        $SettingsArray = [System.Collections.Generic.List[PSCustomObject]]::new()

                        for ($i = 0; $i -lt $SettingCount; $i++) {
                            $Provider = Get-BinaryString -BinaryReader $BinaryReader
                            $Key = Get-BinaryString -BinaryReader $BinaryReader
                            $ValueName = Get-BinaryString -BinaryReader $BinaryReader
                            $ValueType = $BinaryReader.ReadUInt32()

                            switch ($ValueType) {
                                0 { $SettingValue = [Boolean] $BinaryReader.ReadUInt32() }
                                1 { $SettingValue = [UInt32]  $BinaryReader.ReadUInt32() }
                                2 { $SettingValue = Convert-ByteArrayToHexString -Bytes (Get-BinaryBlob -BinaryReader $BinaryReader) }
                                3 { $SettingValue = [String] (Get-BinaryString -BinaryReader $BinaryReader) }
                                default { throw "Invalid secure setting value type: $ValueType" }
                            }

                            $SettingEntry = New-Object -TypeName PSObject
                            $SettingEntry | Add-Member -MemberType "NoteProperty" -Name "Provider" -Value $Provider
                            $SettingEntry | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $Key
                            $SettingEntry | Add-Member -MemberType "NoteProperty" -Name "ValueName" -Value $ValueName
                            $SettingEntry | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $SettingValue
                            $SettingsArray.Add($SettingEntry)
                        }
                    }

                    $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "Settings" -Value $SettingsArray
                    Write-Verbose "[GCIP] Parsed $($SettingsArray.Count)/$($SettingCount) secure setting(s). Stream position: $($BinaryReader.BaseStream.Position)."
                }
                catch {
                    Write-Warning "[GCIP] Failed to fully parse the Secure Settings section: $($_.Exception.Message). The recovered policy will still contain everything up to and including HvciOptions."
                }

                try {
                    $FileRuleList = if ($CIPolicy.FileRules) { $CIPolicy.FileRules } else { @() }
                    $SignerList = if ($CIPolicy.SignerRules) { $CIPolicy.SignerRules } else { @() }
                    $Stream = $BinaryReader.BaseStream

                    while (($Stream.Position + 4) -le $Stream.Length) {
                        $SectionTag = $BinaryReader.ReadUInt32()
                        if ($SectionTag -lt 3 -or $SectionTag -gt 8 -or $SectionTag -gt $PolicyFormatVersion) {
                            Write-Verbose "[GCIP] Extension sections done at tag $($SectionTag) (out of range); $($Stream.Length - $Stream.Position) byte(s) left unread."
                            break
                        }

                        Write-Verbose "[GCIP] Parsing extension section V$($SectionTag) at stream position $($Stream.Position - 4)."

                        switch ($SectionTag) {
                            3 { # Per-file-rule MaximumFileVersion + AppIDs, per-signer SignTimeAfter
                                foreach ($FileRule in $FileRuleList) {
                                    $Revision = $BinaryReader.ReadUInt16()
                                    $Build = $BinaryReader.ReadUInt16()
                                    $Minor = $BinaryReader.ReadUInt16()
                                    $Major = $BinaryReader.ReadUInt16()
                                    $MaxVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision
                                    if ($MaxVersion -ne '0.0.0.0') {
                                        Add-Member -InputObject $FileRule -NotePropertyName "MaximumFileVersion" -NotePropertyValue $MaxVersion.ToString()
                                    }

                                    $AppIDCount = $BinaryReader.ReadUInt32()
                                    if ($AppIDCount) {
                                        $AppIDs = for ($j = 0; $j -lt $AppIDCount; $j++) { Get-BinaryString -BinaryReader $BinaryReader }
                                        Add-Member -InputObject $FileRule -NotePropertyName "AppIDs" -NotePropertyValue ($AppIDs -join ';')
                                    }
                                }
                                foreach ($Signer in $SignerList) {
                                    $SignTime = $BinaryReader.ReadUInt64()
                                    if ($SignTime -gt 0 -and $SignTime -lt 0x7FFFFFFFFFFFFFFF) {
                                        Add-Member -InputObject $Signer -NotePropertyName "SignTimeAfter" -NotePropertyValue ([DateTime]::FromFileTimeUtc($SignTime)).ToString('yyyy-MM-ddTHH:mm:ss')
                                    }
                                }
                            }

                            4 { # Per-file-rule InternalName / FileDescription / ProductName
                                foreach ($FileRule in $FileRuleList) {
                                    $InternalName    = Get-BinaryString -BinaryReader $BinaryReader
                                    $FileDescription = Get-BinaryString -BinaryReader $BinaryReader
                                    $ProductName     = Get-BinaryString -BinaryReader $BinaryReader
                                    if ($InternalName) {
                                        Add-Member -InputObject $FileRule -NotePropertyName "InternalName" -NotePropertyValue $InternalName
                                    }
                                    if ($FileDescription) {
                                        Add-Member -InputObject $FileRule -NotePropertyName "FileDescription" -NotePropertyValue $FileDescription
                                    }
                                    if ($ProductName) {
                                        Add-Member -InputObject $FileRule -NotePropertyName "ProductName" -NotePropertyValue $ProductName
                                    }
                                }
                            }

                            5 { # Per-file-rule PackageFamilyName + PackageVersion
                                foreach ($FileRule in $FileRuleList) {
                                    $PackageFamilyName = Get-BinaryString -BinaryReader $BinaryReader
                                    if ($PackageFamilyName) {
                                        Add-Member -InputObject $FileRule -NotePropertyName "PackageFamilyName" -NotePropertyValue $PackageFamilyName
                                    }
                                    $Revision = $BinaryReader.ReadUInt16()
                                    $Build = $BinaryReader.ReadUInt16()
                                    $Minor = $BinaryReader.ReadUInt16()
                                    $Major = $BinaryReader.ReadUInt16()
                                    $PkgVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision
                                    if ($PkgVersion -ne '0.0.0.0') {
                                        Add-Member -InputObject $FileRule -NotePropertyName "PackageVersion" -NotePropertyValue $PkgVersion.ToString()
                                    }
                                }
                            }

                            6 { # Supplemental-policy PolicyID + BasePolicyID
                                $PolicyIDBytes = $BinaryReader.ReadBytes($GuidLength)
                                $BasePolicyIDBytes = $BinaryReader.ReadBytes($GuidLength)
                                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "PolicyID" -Value $(([Guid] $PolicyIDBytes).ToString())
                                $CIPolicy | Add-Member -MemberType "NoteProperty" -Name "BasePolicyID" -Value $(([Guid] $BasePolicyIDBytes).ToString())
                                $IndexCount = $BinaryReader.ReadUInt32()
                                for ($j = 0; $j -lt $IndexCount; $j++) { $null = $BinaryReader.ReadUInt32() }
                            }

                            7 { # Per-file-rule FilePath
                                foreach ($FileRule in $FileRuleList) {
                                    $FilePath = Get-BinaryString -BinaryReader $BinaryReader
                                    if ($FilePath) {
                                        Add-Member -InputObject $FileRule -NotePropertyName "FilePath" -NotePropertyValue $FilePath
                                    }
                                }
                            }

                            8 { # AppSettings - not representable in this XML schema; stop here.
                                Write-Verbose "[GCIP] AppSettings (V8) section is present but not decoded by this parser."
                                $SectionTag = 0
                            }
                        }

                        if ($SectionTag -eq 0) { break }
                    }
                }
                catch {
                    Write-Warning "[GCIP] Failed to fully parse the version-tagged extension sections: $($_.Exception.Message). The recovered XML contains everything parsed up to the failure."
                }
            }
        }
        catch {
            Write-Warning "[GCIP] Unhandled exception: $($_.Exception.Message)."
            return
        }

        $CIPolicy
    }

    end {
        if ($BinaryReader) { $BinaryReader.Close() }
        if ($MemoryStream) { $MemoryStream.Close() }
    }
}

function ConvertTo-CodeIntegrityOid {
    <#
    .SYNOPSIS
    Decodes a DER encoded ASN.1 object identifier (OID)

    .DESCRIPTION
    ConvertTo-CodeIntegrityOid decodes a DER encoded ASN.1 object identifier (OID). This can be used as a helper function for binary certificate parsers.

    .PARAMETER EncodedOIDBytes
    Specifies the bytes of an absolute (starts with 6), encoded OID.

    .EXAMPLE
    ConvertTo-CodeIntegrityOid -EncodedOIDBytes @(0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x05)

    .OUTPUTS
    System.Security.Cryptography.Oid
    ConvertTo-CodeIntegrityOid outputs an OID object representing the decoded OID.
    #>

    [OutputType([System.Security.Cryptography.Oid])]
    param (
        [Parameter(Mandatory = $True, Position = 0)]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $EncodedOIDBytes
    )

    # This only handles absolute encoded OIDs - those that start with 6.
    # [Security.Cryptography.CryptoConfig]::EncodeOID only handles absolute OIDs.

    # This article describes the OID encoding/decoding process:
    # https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809(v=vs.85).aspx

    if (($EncodedOIDBytes.Length -lt 2) -or ($EncodedOIDBytes[0] -ne 6) -or ($EncodedOIDBytes[1] -ne ($EncodedOIDBytes.Length - 2))) {
        throw 'Invalid encoded EKU OID value.'
    }

    $OIDComponents = New-Object -TypeName 'System.Collections.Generic.List[Int]'

    $SecondComponent = $EncodedOIDBytes[2] % 40
    $FirstComponent = ($EncodedOIDBytes[2] - $SecondComponent) / 40

    $OIDComponents.Add($FirstComponent)
    $OIDComponents.Add($SecondComponent)

    $i = 3

    while ($i -lt $EncodedOIDBytes.Length) {
        if (-not ($EncodedOIDBytes[$i] -band 0x80)) {
            # It is just single-byte encoded
            $OIDComponents.Add($EncodedOIDBytes[$i])
            $i++
        } else {
            # It is either two or three byte encoded
            $Byte1 = ($EncodedOIDBytes[$i] -shl 1) -shr 1 # Strip the high bit
            $Byte2 = $EncodedOIDBytes[$i+1]

            if ($Byte2 -band 0x80) {
                # three byte encoded
                $Byte3 = $EncodedOIDBytes[$i+2]
                $i += 3

                $Byte2 = $Byte2 -band 0x7F
                if ($Byte2 -band 1) { $Byte3 = $Byte3 -bor 0x80 }
                if ($Byte1 -band 1) { $Byte2 = $Byte2 -bor 0x80 }
                $Byte2 = $Byte2 -shr 1
                $Byte1 = $Byte1 -shr 1
                if ($Byte2 -band 1) { $Byte2 = $Byte2 -bor 0x80 }
                $Byte1 = $Byte1 -shr 1

                $OIDComponents.Add([BitConverter]::ToInt32(@($Byte3, $Byte2, $Byte1, 0), 0))
            } else {
                # two byte encoded
                $i +=2

                # "Shift" the low bit from the high byte to the high bit of the low byte
                if ($Byte1 -band 1) { $Byte2 = $Byte2 -bor 0x80 }
                $Byte1 = $Byte1 -shr 1

                $OIDComponents.Add([BitConverter]::ToInt16(@($Byte2, $Byte1), 0))
            }
        }
    }

    [Security.Cryptography.Oid] ($OIDComponents -join '.')
}

function Get-BinaryString {

    [OutputType('String')]
    param (
        [Parameter(Mandatory)]
        [IO.BinaryReader]
        [ValidateNotNullOrEmpty()]
        $BinaryReader
    )

    $StringLength = $BinaryReader.ReadUInt32()

    if ($StringLength) {
        $PaddingBytes = 4 - $StringLength % 4 -band 3

        $StringBytes = $BinaryReader.ReadBytes($StringLength)
        $null = $BinaryReader.ReadBytes($PaddingBytes)

        [Text.Encoding]::Unicode.GetString($StringBytes)
    }

    $null = $BinaryReader.ReadInt32()
}

function Get-BinaryBlob {

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory)]
        [IO.BinaryReader]
        [ValidateNotNullOrEmpty()]
        $BinaryReader
    )

    $Length = $BinaryReader.ReadUInt32()

    if ($Length) {
        $PaddingBytes = 4 - $Length % 4 -band 3

        $Bytes = $BinaryReader.ReadBytes($Length)
        $null = $BinaryReader.ReadBytes($PaddingBytes)

        ,$Bytes
    } else {
        ,([Byte[]] @())
    }
}
