function Get-OptionalProperty {
    param([object]$Object,[string]$Name)
    if($null-ne$Object-and$Object.PSObject.Properties[$Name]){$Object.$Name}
}
function Test-CIFileRule {
    param([object]$Rule,[object]$Sample)
    $hash=Get-OptionalProperty $Rule 'Hash'
    if($hash){$hashes=@($Sample.SHA256,(Get-OptionalProperty $Sample 'SHA1'));$auth=Get-OptionalProperty $Sample 'Authentihash';if($auth){$hashes+=@($auth.SHA256,$auth.SHA1)};return $hash-in$hashes}
    $matched=$false
    foreach($pair in @(@('FileName','OriginalFilename'),@('InternalName','InternalName'),@('ProductName','ProductName'),@('FileDescription','FileDescription'))){$expected=Get-OptionalProperty $Rule $pair[0];if($expected){$matched=$true;$actual=Get-OptionalProperty $Sample $pair[1];if(-not$actual-or$actual-notlike$expected){return $false}}}
    if(-not$matched){return $false}
    $version=$null;if(-not[version]::TryParse([string](Get-OptionalProperty $Sample 'FileVersion'),[ref]$version)){return $null}
    $min=Get-OptionalProperty $Rule 'MinimumVersion';$max=Get-OptionalProperty $Rule 'MaximumFileVersion'
    if($min-and[version]$min-ne[version]'65535.65535.65535.65535'-and$version-lt[version]$min){return $false}
    if($max-and$version-gt[version]$max){return $false}
    foreach($extra in @('FilePath','AppIDs','PackageFamilyName')){if(Get-OptionalProperty $Rule $extra){return $null}}
    return $true
}
function Get-CIDenyMatches {
    param([object]$Policy,[object]$Sample)
    $rules=@(Get-OptionalProperty $Policy 'FileRules');$signers=@(Get-OptionalProperty $Policy 'SignerRules')
    foreach($scenario in @(Get-OptionalProperty $Policy 'SigningScenarios')|Where-Object Value -eq 131){
        $product=Get-OptionalProperty $scenario 'ProductSigners'
        $refs=Get-OptionalProperty (Get-OptionalProperty $product 'FileRulesRef') 'FileRuleRef'
        foreach($rule in $rules|Where-Object{$_.Type-eq'Deny'-and$_.Id-in$refs}){if((Test-CIFileRule $rule $Sample)-eq$true){[pscustomobject]@{RuleId=$rule.Id;Kind='FileDeny';Conditional=$false}}}
        foreach($denied in @(Get-OptionalProperty (Get-OptionalProperty $product 'DeniedSigners') 'DeniedSigner')){
            $signer=$signers|Where-Object Id -eq $denied.SignerId|Select-Object -First 1
            if(-not$signer-or$signer.CertRootType-ne'TBS'){continue}
            $hashes=@(foreach($certificate in @(Get-OptionalProperty $Sample 'Certificates')){foreach($property in $certificate.TBS.PSObject.Properties){$property.Value}})
            if($signer.CertRootValue-notin$hashes){continue}
            # TBS matches alone are insufficient when publisher, EKU, issuer, OEM,
            # exceptions, signing time or file attributes constrain the signer.
            $conditional=$false
            foreach($name in @('CertPublisher','CertIssuer','CertOemID','CertEKU','SignTimeAfter','FileAttribRef')){if(Get-OptionalProperty $signer $name){$conditional=$true}}
            if(Get-OptionalProperty $denied 'ExceptDenyRule'){$conditional=$true}
            [pscustomobject]@{RuleId=$signer.Id;Kind='SignerDeny';Conditional=$conditional}
        }
    }
}
function Read-CIPolicyIsolated {
    param([string]$Path)
    if(-not(Test-AllowedLocalPath $Path)){return}
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop;if($file.Length-gt64MB){throw 'Policy exceeds parser size limit.'}
    $payload=@{Parser=(Join-Path $script:ModuleRoot 'ThirdParty/PrivescCheck/CodeIntegrity.ps1');Path=$Path}|ConvertTo-Json -Compress
    $encodedPayload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $code=@'
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
. $p.Parser
function Convert-ByteArrayToHexString([byte[]]$Bytes){[BitConverter]::ToString($Bytes).Replace('-','')}
$warnings=@();$policy=Get-CodeIntegrityPolicy -FilePath $p.Path -WarningVariable warnings -WarningAction SilentlyContinue
if(-not$policy){throw 'Policy could not be parsed'}
foreach($rule in $policy.FileRules){if($rule.PSObject.Properties['MinimumVersion']){$rule.MinimumVersion=[string]$rule.MinimumVersion}}
@{Policy=$policy;Incomplete=($warnings.Count-gt0)}|ConvertTo-Json -Depth 25 -Compress
'@
    $code=$code.Replace('__PAYLOAD__',$encodedPayload);$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    Invoke-ReadOnlyCommand "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -NonInteractive -EncodedCommand $encoded"|ConvertFrom-Json
}
