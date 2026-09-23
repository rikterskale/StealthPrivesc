function Invoke-RecentArtifactCheck {
    $shell=New-Object -ComObject WScript.Shell
    try{foreach($profile in Get-ProfileRoots){
        foreach($file in Get-BoundedFiles @("$profile\AppData\Roaming\Microsoft\Windows\Recent") -Depth 2){
            if($file.Extension-eq'.lnk'){$shortcut=$null;try{$shortcut=$shell.CreateShortcut($file.FullName);Add-Evidence $file.FullName 'Recent-file shortcut target and redacted invocation.' @{Target=$shortcut.TargetPath;Command=(Get-CommandShape ('"'+$shortcut.TargetPath+'" '+$shortcut.Arguments));LastWriteUtc=$file.LastWriteTimeUtc}}finally{if($shortcut){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)}}}
            else{Add-Artifact $file.FullName 'Recent-file/jump-list artifact'}
        }
    }}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
    foreach($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU','HKCU:\Software\Microsoft\Office')){
        $keys=@();try{$keys+=Get-Item -LiteralPath $root -ErrorAction Stop}catch [System.Management.Automation.ItemNotFoundException]{}
        if($root-like'*Office'){$keys+=@(Get-RegistryTree @($root) -Depth 6|Where-Object{$_.Name-match'MRU|Recent'})}
        foreach($key in $keys){foreach($name in $key.GetValueNames()){if($name-in@('MRUList','MRUListEx')){continue};$value=$key.GetValue($name);if($key.Name-like'*RunMRU'){Add-Evidence ($key.Name+'/'+$name) 'Explorer Run history; arguments redacted.' (Get-CommandShape ([string]$value))}else{Add-Evidence ($key.Name+'/'+$name) 'Office recent-item entry; stored value redacted.' @{Present=(-not[string]::IsNullOrEmpty([string]$value));Value='[REDACTED]'}}}}
    }
    foreach($drive in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop){foreach($file in Get-BoundedFiles @($drive.DeviceID+'\$Recycle.Bin') -Depth 1 -Pattern '^\$I'){
        if($file.Length-gt$script:Context.MaxFileBytes-or$file.Length-lt24){continue}
        try{$bytes=[IO.File]::ReadAllBytes($file.FullName);$version=[BitConverter]::ToInt64($bytes,0);$size=[BitConverter]::ToInt64($bytes,8);$deleted=[DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes,16));$offset=if($version-eq2){28}else{24};if($version-notin@(1,2)-or$bytes.Length-lt$offset){Set-CheckPartial 'Unsupported Recycle Bin metadata format.';continue};$path=[Text.Encoding]::Unicode.GetString($bytes,$offset,$bytes.Length-$offset).TrimEnd([char]0);Add-Evidence $file.FullName 'Recycle Bin metadata record; deleted file contents not read.' @{OriginalPath=$path;OriginalBytes=$size;DeletedUtc=$deleted;FormatVersion=$version}}
        catch{Set-CheckPartial 'Recycle Bin metadata record unreadable or malformed.' -ErrorRecord $_}
    }}
}
