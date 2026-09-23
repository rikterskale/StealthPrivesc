function Invoke-CredentialStoreCheck {
    param([int]$Id)
    switch($Id){
        76 {
            if(-not('StealthPrivesc.NativeSspi'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeSspi.cs') -ErrorAction Stop}
            $result=[StealthPrivesc.NativeSspi]::Probe()
            Add-Evidence 'Current-logon NTLM security package' 'Local SSPI authentication probe; no challenge manipulation, security downgrade or network exchange. Authentication tokens erased before reporting.' $result $(if($result.CredentialResponseReturned){'Low'}else{'Information'})
            if($result.Status-ge2147483648){Set-CheckPartial 'SSPI probe did not complete under the current token/policy.'}
        }
        73 {
            if([Environment]::OSVersion.Version-lt[version]'6.2'){Set-CheckSkipped 'Vault collector requires Windows 8 / Server 2012 or newer.' -SkipReason UnsupportedPlatform;return}
            if(-not('StealthPrivesc.NativeVault'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeVault.cs') -ErrorAction Stop}
            $result=[StealthPrivesc.NativeVault]::Inspect($script:Context.MaxItems)
            foreach($item in $result.Items){
                Add-Evidence "$($item.VaultId)/$($item.ItemIndex)" 'Windows Vault entry retrieval attempted in the current user context; returned authenticator data erased before reporting.' $item $(if($item.SecretReturned){'Medium'}else{'Information'})
                if($item.RetrievalStatus){Set-CheckPartial 'Some vault entries could not be retrieved in the current context.'}
            }
            if($result.Errors.Count){Set-CheckPartial "Vault API failures: $($result.Errors -join ', ')."}
            if($result.Truncated){Set-CheckPartial 'Vault enumeration exceeded MaxItems.'}
        }
        74 {
            # Windows PowerShell supplies the WinRT projection removed from modern .NET runtimes.
            $code=@'
$ErrorActionPreference='Stop'
$null=[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault=New-Object Windows.Security.Credentials.PasswordVault
$entries=@($vault.RetrieveAll())
$results=@();$count=0
foreach($entry in $entries){
    if($count-ge__MAX__){break};$count++
    $present=$false;$errorType=$null
    try{$entry.RetrievePassword();$present=-not[string]::IsNullOrEmpty($entry.Password);$entry.Password=''}catch{$errorType=$_.Exception.GetType().Name}
    $results+=@{Index=$count;ResourcePresent=(-not[string]::IsNullOrEmpty($entry.Resource));UserNamePresent=(-not[string]::IsNullOrEmpty($entry.UserName));SecretReturned=$present;Value='[REDACTED]';Error=$errorType}
}
@{Items=$results;Truncated=($entries.Count-gt__MAX__)}|ConvertTo-Json -Depth 5 -Compress
'@
            $code=$code.Replace('__MAX__',[string]$script:Context.MaxItems)
            $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
            $hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $result=Invoke-ReadOnlyCommand $hostPath "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"|ConvertFrom-Json
            foreach($item in $result.Items){Add-Evidence "PasswordVault/$($item.Index)" 'WinRT Credential Locker accessibility; values redacted inside the isolated collector.' $item $(if($item.SecretReturned){'Medium'}else{'Information'});if($item.Error){Set-CheckPartial 'Some Credential Locker entries could not be retrieved.'}}
            if($result.Truncated){Set-CheckPartial 'Credential Locker enumeration exceeded MaxItems.'}
        }
        75 {
            foreach($profile in Get-ProfileRoots){
                foreach($relative in @('AppData\Roaming\Microsoft\Protect','AppData\Roaming\Microsoft\Credentials','AppData\Local\Microsoft\Credentials','AppData\Local\Microsoft\Vault')){
                    foreach($file in Get-BoundedFiles @((Join-Path $profile $relative)) -Depth 3){Add-ReadableArtifact $file.FullName 'DPAPI master-key/credential-blob discovery; readability does not establish decryptability.'}
                }
            }
        }
    }
}
function Get-ProfileRoots {
    Get-Cached 'ProfileRoots' {
        $env:USERPROFILE
        try{foreach($profile in Get-CimInstance Win32_UserProfile -ErrorAction Stop){if($profile.LocalPath-ne$env:USERPROFILE-and-not$profile.Special){$profile.LocalPath}}}
        catch{Set-CheckPartial 'Additional user profiles could not be enumerated; current-user paths are still inspected.' -ErrorRecord $_}
    }
}
function Add-ReadableArtifact {
    param([string]$Path,[string]$Kind)
    if(-not(Test-AllowedLocalPath $Path)){return}
    try{
        $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)){return}
        $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete))
        $stream.Dispose()
        Add-Evidence $file.FullName $Kind @{Readable=$true;Bytes=$file.Length;LastWriteUtc=$file.LastWriteTimeUtc.ToString('o');Value='[REDACTED]'} 'Low'
    }catch [System.Management.Automation.ItemNotFoundException]{}
    catch [UnauthorizedAccessException]{Add-Evidence $Path 'Artifact read access denied.' @{Readable=$false}}
    catch{Set-CheckPartial "Artifact readability could not be established: $Path" -ErrorRecord $_}
}
