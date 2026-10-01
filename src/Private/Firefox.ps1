function Invoke-FirefoxRecoveryProbe {
    param([string]$Path)
    $libraries=@("$env:ProgramW6432\Mozilla Firefox\nss3.dll","${env:ProgramFiles}\Mozilla Firefox\nss3.dll","${env:ProgramFiles(x86)}\Mozilla Firefox\nss3.dll") | Select-Object -Unique
    $library=$libraries|Where-Object{(Get-FilePresence $_)-eq'Present'}|Select-Object -First 1
    if(-not$library){Set-CheckPartial 'Firefox NSS runtime is not installed in a supported location; login recovery cannot be assessed.';return @()}
    $signature=Get-AuthenticodeSignature -LiteralPath $library -ErrorAction Stop
    if($signature.Status-ne'Valid'-or-not$signature.SignerCertificate-or$signature.SignerCertificate.Subject-notmatch'Mozilla Corporation'){Set-CheckPartial 'Firefox NSS runtime publisher could not be verified.';return @()}
    try { $helperPath=Get-WindowsPowerShellPath -Architecture (Get-ImageArchitecture $library) }
    catch { Set-CheckPartial 'Firefox NSS runtime architecture could not be determined.' -ErrorRecord $_;return @() }
    $payload=@{Source=(Join-Path $script:ModuleRoot 'NativeNss.cs');Library=$library;Path=$Path;MaxItems=$script:Context.MaxItems;MaxBytes=$script:Context.MaxFileBytes}|ConvertTo-Json -Compress
    $encodedPayload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $code=@'
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
if((Get-Item -LiteralPath $p.Path).Length-gt$p.MaxBytes){throw 'Firefox login file too large'}
if(-not('StealthPrivesc.NativeNss'-as[type])){Add-Type -Path $p.Source -ErrorAction Stop}
$data=Get-Content -LiteralPath $p.Path -Raw|ConvertFrom-Json
$entries=@($data.logins|Select-Object -First $p.MaxItems)
$results=[StealthPrivesc.NativeNss]::Inspect($p.Library,[IO.Path]::GetDirectoryName($p.Path),[string[]]@($entries|ForEach-Object encryptedPassword))
@{Items=@($results);Truncated=(@($data.logins).Count-gt$p.MaxItems)}|ConvertTo-Json -Depth 4 -Compress
'@
    try{$result=(Invoke-ReadOnlyCommand -Payload ($code.Replace('__PAYLOAD__',$encodedPayload)) -HostPath $helperPath)|ConvertFrom-Json;if($result.Truncated){Set-CheckPartial 'Firefox recovery probe reached MaxItems.'};return @($result.Items)}
    catch{Set-CheckPartial 'Firefox read-only recovery probe failed (architecture, primary password, profile or NSS access); no passwords were requested interactively.' -ErrorRecord $_;return @()}
}
