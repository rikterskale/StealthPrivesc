function Invoke-ExecutionAnalysisCheck {
    param([int]$Id)
    switch($Id){
        19 {
            if(-not('StealthPrivesc.NativeServices'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'Native/NativeServices.cs')}
            foreach($service in Get-Limited @(Get-Services|Where-Object StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM'))){
                try{$settings=[StealthPrivesc.NativeServices]::Recovery($service.Name);if(3-in$settings.ActionTypes){Add-Evidence $service.Name 'SYSTEM service has a run-command recovery action.' @{Command=(Get-CommandShape $settings.Command);ActionTypes=$settings.ActionTypes;DelaysMilliseconds=$settings.Delays;NonCrashFailures=$settings.NonCrashFailures;ResetSeconds=$settings.ResetSeconds};foreach($path in Get-ReferencedPaths (Get-ExecutablePath $settings.Command) $settings.Command ([Environment]::SystemDirectory)){Add-ExecutableAccess $path 'Writable SYSTEM service recovery command target.'}}}
                catch{Set-CheckPartial 'Some service recovery settings are inaccessible.' -ErrorRecord $_}
            }
        }
        22 {
            foreach($task in Get-Limited @(Get-Tasks)){
                $actions=@(foreach($action in $task.Actions){
                    if($action.PSObject.Properties['Execute']){@{Type='Execute';Command=(Get-CommandShape ('"'+$action.Execute+'" '+$action.Arguments));WorkingDirectory=$action.WorkingDirectory}}
                    elseif($action.PSObject.Properties['ClassId']){@{Type='ComHandler';ClassId=$action.ClassId;Data='[REDACTED]'}}
                    else{@{Type=$action.CimClass.CimClassName}}
                })
                Add-Evidence ($task.TaskPath+$task.TaskName) 'Registered task principal, actions, triggers and settings; argument values and COM data redacted.' @{Account=$task.Principal.UserId;Group=$task.Principal.GroupId;RunLevel=[string]$task.Principal.RunLevel;LogonType=[string]$task.Principal.LogonType;State=[string]$task.State;Actions=$actions;Triggers=@($task.Triggers|Select-Object Enabled,StartBoundary,EndBoundary);Settings=($task.Settings|Select-Object Enabled,AllowDemandStart,Hidden,ExecutionTimeLimit)}
            }
        }
        27 {
            $data=Get-ReferenceDocument $script:Context.VulnerabilityDatabasePath 'MSRC'
            $assessment=if($data){@(Get-WindowsPatchAssessment $data.Entries (Get-WindowsVersionContext) @('CVE-2025-60710'))}else{@()}
            foreach($task in Get-Limited @(Get-Tasks|Where-Object{($_.TaskPath+$_.TaskName)-match'(?i)Recall|PolicyConfiguration'})){
                $system=$task.Principal.UserId-in@('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18')
                Add-Evidence ($task.TaskPath+$task.TaskName) 'Recall task configuration correlated with published CVE-2025-60710 fixed-build rules.' @{SystemPrincipal=$system;Enabled=($task.State-ne'Disabled');RunLevel=[string]$task.Principal.RunLevel;PatchAssessment=$assessment} $(if($system-and$task.State-ne'Disabled'-and'BelowPublishedFix'-in$assessment.State){'High'}else{'Information'})
            }
            if(-not$assessment.Count-or'NoMatchingProductRule'-in$assessment.State){Set-CheckPartial 'Recall CVE applicability could not be established for this OS branch.'}
        }
        30 {
            foreach($process in Get-Limited @(Get-CimInstance Win32_Process -ErrorAction Stop)){
                try{$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue-ne0){Set-CheckPartial 'Process owner unavailable.';continue};$context="PID $($process.ProcessId), owner $($owner.Sid)";Add-LoadedModuleAccess $process.ProcessId $context;foreach($directory in Get-DefaultDllSearchDirectories $process.ExecutablePath){Add-WritablePath $directory "Writable default DLL search directory ($context); custom loader flags can change applicability."}}
                catch{Set-CheckPartial 'Some processes exited or could not be inspected.' -ErrorRecord $_}
            }
        }
        42 {
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$self=$identity.User.Value}finally{$identity.Dispose()}
            foreach($process in Get-Limited @(Get-CimInstance Win32_Process -ErrorAction Stop)){
                try{
                    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
                    if($owner.ReturnValue-ne0){Set-CheckPartial 'Process owner unavailable.';continue};if($owner.Sid-eq$self){continue}
                    foreach($right in @(@('CreateThread',2),@('VmOperation',8),@('VmWrite',0x20),@('DuplicateHandle',0x40),@('WriteDacl',0x40000),@('WriteOwner',0x80000))){$access=[StealthPrivesc.Native]::ProcessAccess($process.ProcessId,$right[1]);if($access.Allowed){Add-Evidence "Process $($process.ProcessId)" 'Cross-user process control right; handle closed without mutation.' @{OwnerSid=$owner.Sid;Right=$right[0]} 'Medium'}}
                    foreach($thread in Get-Limited @((Get-Process -Id $process.ProcessId -ErrorAction Stop).Threads)){foreach($right in @(@('SetContext',0x10),@('SetInformation',0x20),@('Impersonate',0x100),@('DirectImpersonation',0x200),@('WriteDacl',0x40000),@('WriteOwner',0x80000))){$access=[StealthPrivesc.Native]::ThreadAccess($thread.Id,$right[1]);if($access.Allowed){Add-Evidence "Thread $($thread.Id)" 'Cross-user thread control right; handle closed without mutation.' @{ProcessId=$process.ProcessId;OwnerSid=$owner.Sid;Right=$right[0]} 'Medium'}}}
                }catch{Set-CheckPartial 'Some process/thread owners or objects were inaccessible or exited.' -ErrorRecord $_}
            }
        }
    }
}
