function Get-ReferencedPaths {
    param([string]$Executable,[string]$Arguments,[string]$WorkingDirectory)
    $seen=@{}
    $path=Get-ExecutablePath $Executable
    if($path){$seen[$path]=$true;$path}
    if(-not$Arguments){return}
    foreach($argument in [StealthPrivesc.NativeInspection]::CommandArguments('placeholder.exe '+$Arguments)){
        $candidate=[Environment]::ExpandEnvironmentVariables(($argument-split',',2)[0])
        if($candidate-notmatch'(?i)\.(exe|dll|ps1|psm1|vbs|vbe|js|jse|bat|cmd|config|xml|ini|json)$'){continue}
        if(-not[IO.Path]::IsPathRooted($candidate)){
            if($WorkingDirectory){$candidate=Join-Path $WorkingDirectory $candidate}
            else{Set-CheckPartial 'A referenced relative script/module requires an execution working directory.';continue}
        }
        if(-not$seen.ContainsKey($candidate)){$seen[$candidate]=$true;$candidate}
    }
}
function Get-RegistryTree {
    param([string[]]$Roots,[int]$Depth=64)
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    foreach($root in $Roots){$queue.Enqueue(@($root,0))}
    while($queue.Count-and$script:RegistryVisited-lt$script:Context.MaxItems){
        $entry=$queue.Dequeue()
        foreach($key in Get-RegistryChildren $entry[0]){
            $key
            if($entry[1]-lt$Depth){$queue.Enqueue(@($key.PSPath,($entry[1]+1)))}
            else{Set-CheckPartial 'Registry traversal depth limit reached.'}
        }
    }
    if($queue.Count){Set-CheckPartial 'Registry traversal item limit reached.'}
}
function Get-FilePresence {
    param([string]$Path)
    if(-not(Test-AllowedLocalPath $Path)){return 'Unknown'}
    try{$null=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;return 'Present'}
    catch [System.Management.Automation.ItemNotFoundException]{return 'Missing'}
    catch{Set-CheckPartial "Cannot determine target existence: $Path";return 'Unknown'}
}
function Get-ImagePublisher {
    param([string]$Path)
    if(-not$Path-or-not(Test-AllowedLocalPath $Path)){return $null}
    try{
        $file=Get-Item -LiteralPath $Path -ErrorAction Stop
        $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        [pscustomobject]@{Company=$file.VersionInfo.CompanyName;Product=$file.VersionInfo.ProductName;Version=$file.VersionInfo.FileVersion;SignatureStatus=[string]$signature.Status;Signer=$(if($signature.SignerCertificate){$signature.SignerCertificate.Subject});MicrosoftSigned=($signature.Status-eq'Valid'-and$signature.SignerCertificate.Subject-match'(^|, )O=Microsoft Corporation(,|$)')}
    }catch{Set-CheckPartial 'Some executable publisher/signature metadata is unavailable.';$null}
}
function Add-LoadedModuleAccess {
    param([int]$ProcessId,[string]$Context)
    try{
        $process=Get-Process -Id $ProcessId -ErrorAction Stop
        foreach($module in Get-Limited @($process.Modules)){Add-ExecutableAccess $module.FileName "$Context loaded DLL/executable."}
    }catch{Set-CheckPartial 'Some process module lists are inaccessible or the process exited.'}
}
function Get-DefaultDllSearchDirectories {
    param([string]$Executable)
    $candidates=@()
    if($Executable-and[IO.Path]::IsPathRooted($Executable)){$candidates+=[IO.Path]::GetDirectoryName($Executable)}
    $candidates+=@([Environment]::SystemDirectory,$env:SystemRoot)
    $candidates+=@([Environment]::GetEnvironmentVariable('Path','Machine')-split';')
    $candidates|Where-Object{$_}|ForEach-Object{[Environment]::ExpandEnvironmentVariables($_.Trim('"'))}|Select-Object -Unique
}
