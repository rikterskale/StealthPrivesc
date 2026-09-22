function Invoke-HandleCheck {
    # A process boundary also bounds path-resolution callbacks on unusual file systems.
    $source64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Join-Path $script:ModuleRoot 'NativeHandles.cs')))
    $code=@'
$ErrorActionPreference='Stop'
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
Add-Type -Path $source
[StealthPrivesc.NativeHandles]::Inspect(__MAX__,200000)|ConvertTo-Json -Depth 6 -Compress
'@
    $code=$code.Replace('__SOURCE__',$source64).Replace('__MAX__',[string]$script:Context.MaxItems)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $result=Invoke-ReadOnlyCommand $hostPath "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"|ConvertFrom-Json
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$userSid=$identity.User.Value}finally{$identity.Dispose()}
    foreach($item in $result.Items){
        $evidence=@{SourceProcessId=$item.SourceProcessId;Handle=$item.HandleValue;GrantedAccess=('0x{0:X8}'-f[uint32]$item.GrantedAccess);ObjectType=$item.ObjectType;TargetProcessId=$item.TargetProcessId;TargetOwnerSid=$item.TargetOwnerSid}
        if($item.ObjectType-in@('Process','Thread')){
            if($item.TargetOwnerSid-and$item.TargetOwnerSid-ne$userSid){Add-Evidence "PID $($item.SourceProcessId)/handle $($item.HandleValue)" 'An accessible handle refers to a different user process/thread with potentially controlling rights; no action performed through the handle.' $evidence $(if($script:Context.Elevated){'Information'}else{'Medium'})}
        }elseif($item.Descriptor){
            $direct=[StealthPrivesc.Native]::CheckAccess([byte[]]$item.Descriptor,2,$false)
            if($direct.Error){Set-CheckPartial 'Some file-handle DACLs could not be evaluated.'}
            elseif(($item.GrantedAccess-band2)-and-not$direct.Allowed){$evidence.Path=$item.Path;Add-Evidence $item.Path 'Accessible file handle grants write-data access denied by the current-token DACL evaluation.' $evidence 'High'}
        }else{Set-CheckPartial 'Some file handles did not expose readable security descriptors.'}
    }
    if($result.Status){Set-CheckPartial ('System handle query failed (NTSTATUS 0x{0:X8}).' -f $result.Status)}
    if($result.InaccessibleSources-or$result.UnresolvedObjects){Set-CheckPartial "Handle coverage limited: $($result.InaccessibleSources) inaccessible source processes; $($result.UnresolvedObjects) unresolved handles."}
    if($result.Truncated){Set-CheckPartial 'Handle inspection reached its item/time budget.'}
}
