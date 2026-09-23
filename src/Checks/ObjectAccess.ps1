function Add-DescriptorRights {
    param([string]$Target,[byte[]]$Descriptor,[hashtable]$Rights,[uint32[]]$Mapping,[object]$Context=@{})
    foreach($right in $Rights.Keys){
        $access=[StealthPrivesc.Native]::CheckObjectAccess($Descriptor,[uint32]$Rights[$right],$Mapping[0],$Mapping[1],$Mapping[2],$Mapping[3])
        if($access.Error){Set-CheckPartial "Security descriptor evaluation failed for $Target (Win32 $($access.Error))."}
        elseif($access.Allowed){Add-Evidence $Target 'Current-token access permitted by the object security descriptor.' @{Right=$right;Context=$Context;Method='AccessCheck';ElevatedToken=$script:Context.Elevated} $(if($script:Context.Elevated){'Information'}else{'Medium'})}
    }
}
function Invoke-ObjectAccessCheck {
    param([int]$Id)
    switch($Id){
        24 {
            $scheduler=New-Object -ComObject Schedule.Service
            try{
                $scheduler.Connect()
                foreach($task in Get-Limited @(Get-Tasks)){
                    if($task.Principal.UserId-notin@('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18')-or$task.State-eq'Disabled'){continue}
                    $folder=$null;$registered=$null
                    try{
                        $folder=$scheduler.GetFolder($task.TaskPath);$registered=$folder.GetTask($task.TaskName)
                        $sddl=$registered.GetSecurityDescriptor(7)
                        $sd=New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
                        $bytes=New-Object byte[] $sd.BinaryLength;$sd.GetBinaryForm($bytes,0)
                        Add-DescriptorRights ($task.TaskPath+$task.TaskName) $bytes @{UpdateTask=2;WriteDacl=0x40000;WriteOwner=0x80000} @(0x120089,0x120116,0x1200a0,0x1f01ff) @{Account=$task.Principal.UserId;Enabled=$true;Source='IRegisteredTask.GetSecurityDescriptor'}
                    }catch{Set-CheckPartial "Cannot read registered task security: $($task.TaskPath)$($task.TaskName)" -ErrorRecord $_}
                    finally{if($registered){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($registered)};if($folder){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($folder)}}
                }
            }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($scheduler)}
        }
        44 {
            $clock=[Diagnostics.Stopwatch]::StartNew()
            foreach($pipe in Get-Limited @([IO.Directory]::GetFiles('\\.\pipe\'))){
                if($clock.Elapsed.TotalSeconds-ge60){Set-CheckPartial 'Pipe inspection reached its 60-second budget.';break}
                try{$result=Invoke-IsolatedNativeQuery Pipe $pipe}catch{Set-CheckPartial 'A pipe metadata query failed or timed out.' -ErrorRecord $_;continue}
                if($result.OpenError){Set-CheckPartial 'Some pipes were busy, inaccessible or disappeared before inspection.';continue}
                $context=@{ServerProcessId=$result.ServerProcessId;ServerOwnerSid=$null;ServerQueryError=$result.ServerError}
                if($result.ServerProcessId){try{$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($result.ServerProcessId)" -ErrorAction Stop;$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue-eq0){$context.ServerOwnerSid=$owner.Sid}else{Set-CheckPartial 'Some pipe server owners are inaccessible.'}}catch{Set-CheckPartial 'Some pipe server owners are inaccessible.' -ErrorRecord $_}}
                Add-Evidence $pipe 'Pipe security inspected through a metadata-only identification-level connection; no data exchanged.' $context
                if($result.Descriptor){Add-DescriptorRights $pipe $result.Descriptor @{WriteData=2;CreateInstance=4;WriteDacl=0x40000;WriteOwner=0x80000} @(0x120089,0x120116,0x1200a0,0x1f01ff) $context}
                else{Set-CheckPartial 'Some pipe security descriptors could not be read.'}
            }
        }
        45 {
            $clock=[Diagnostics.Stopwatch]::StartNew()
            $entries=[StealthPrivesc.NativeObjects]::Directory('\Device',$script:Context.MaxItems)
            if($entries.Status){Set-CheckPartial ('Cannot enumerate device namespace (NTSTATUS 0x{0:X8}).' -f $entries.Status)}
            if($entries.Truncated){Set-CheckPartial 'Device namespace enumeration exceeded MaxItems.'}
            foreach($entry in $entries.Entries){
                if($clock.Elapsed.TotalSeconds-ge60){Set-CheckPartial 'Device inspection reached its 60-second budget.';break}
                if($entry.Type-ne'Device'){continue}
                $path='\Device\'+$entry.Name
                try{$security=Invoke-IsolatedNativeQuery Device $path}catch{Set-CheckPartial 'A device descriptor query failed or timed out.' -ErrorRecord $_;continue}
                if($security.Descriptor){Add-DescriptorRights $path $security.Descriptor @{WriteData=2;WriteDacl=0x40000;WriteOwner=0x80000} @(0x120089,0x120116,0x1200a0,0x1f01ff)}
                else{Set-CheckPartial 'Some device descriptors are inaccessible or the device does not support metadata opens.'}
            }
        }
        65 {
            foreach($path in @('\','\BaseNamedObjects','\RPC Control','\Sessions',('\Sessions\'+[Diagnostics.Process]::GetCurrentProcess().SessionId+'\BaseNamedObjects'))){
                $security=[StealthPrivesc.NativeObjects]::Security($path,$true)
                if($security.Descriptor){Add-DescriptorRights $path $security.Descriptor @{CreateObject=4;CreateSubdirectory=8;WriteDacl=0x40000;WriteOwner=0x80000} @(0x20003,0x2000c,0x20003,0xf000f) @{Meaning='Namespace access capability only; no race, symlink or object creation attempted.'}}
                else{Set-CheckPartial "Namespace descriptor unavailable: $path"}
            }
        }
    }
}
