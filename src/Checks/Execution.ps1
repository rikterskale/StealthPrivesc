function Invoke-ExecutionCheck {
    param([int]$Id)
    if($Id -in @(11,12,14,15,16,17,18,19,20,21,31)){
        foreach($s in Get-Limited @(Get-Services)){
            $key="HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
            switch($Id){
                11 { $executable=Get-ExecutablePath $s.PathName;Add-Evidence $s.Name 'Service inventory and executable publisher; raw command-line arguments omitted.' @{DisplayName=$s.DisplayName;Executable=$executable;Publisher=(Get-ImagePublisher $executable);Account=$s.StartName;StartMode=$s.StartMode;State=$s.State;ProcessId=$s.ProcessId} }
                12 {
                    foreach($right in @(@('ChangeConfig',2),@('WriteDacl',0x40000),@('WriteOwner',0x80000))){
                        $r=[StealthPrivesc.Native]::ServiceAccess($s.Name,$right[1])
                        if($r.Allowed){Add-Evidence $s.Name 'Current token can open the service with a control right.' @{Right=$right[0];Account=$s.StartName;ElevatedToken=$script:Context.Elevated} $(if($script:Context.Elevated){'Information'}else{'High'}) 'Restrict service configuration, ownership and DACL modification to administrators.'}
                        elseif($r.Error -notin @(0,5)){Set-CheckPartial "Cannot assess service $($s.Name) (Win32 $($r.Error))."}
                    }
                }
                14 { Add-WritablePath $key 'Writable service registry key.' -Registry }
                15 { foreach($sub in Get-RegistryTree @($key)){Add-WritablePath $sub.PSPath 'Writable extended service registry subkey.' -Registry} }
                16 { $executable=Get-ExecutablePath $s.PathName;foreach($path in Get-ReferencedPaths -Executable $executable -Arguments $s.PathName -WorkingDirectory ([Environment]::SystemDirectory)){Add-ExecutableAccess $path "Writable service executable, referenced file or directory candidate ($($s.Name), $($s.StartName))."} }
                17 {
                    foreach($candidate in Get-UnquotedCandidates $s.PathName){
                        Add-Evidence $s.Name 'Unquoted service path with an ambiguous executable prefix.' @{Account=$s.StartName;Executable=(Get-ExecutablePath $s.PathName);InterceptionCandidate=$candidate} 'Low' 'Quote the complete service executable path, leaving arguments outside the quotes.'
                        Add-ExecutableAccess $candidate "Writable unquoted-path interception candidate for $($s.Name)."
                    }
                }
                18 { if($s.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM')){ $dll=Read-Registry "$key\Parameters" 'ServiceDll'; if($dll.State-eq'Present'){Add-ExecutableAccess ([Environment]::ExpandEnvironmentVariables($dll.Value)) "Writable registered LocalSystem ServiceDll ($($s.Name))."};if($s.ProcessId){Add-LoadedModuleAccess $s.ProcessId "LocalSystem service $($s.Name)"} } }
                19 { if($s.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM')){ $cmd=Read-Registry $key 'FailureCommand'; if($cmd.State-eq'Present'){Add-ExecutableAccess $cmd.Value "Writable LocalSystem recovery-command target ($($s.Name))."} } }
                20 { foreach($right in @(@('Start',0x10),@('Stop',0x20))){$r=[StealthPrivesc.Native]::ServiceAccess($s.Name,$right[1]);if($r.Allowed){Add-Evidence $s.Name 'Service control feasibility; no action performed.' @{Right=$right[0];State=$s.State}}elseif($r.Error-notin@(0,5)){Set-CheckPartial "Cannot assess service control for $($s.Name)."}} }
                21 { if($s.StartName -and $s.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)' -and -not $s.StartName.EndsWith('$')){Add-Evidence $s.Name 'Named service account may have a locally stored LSA service secret; storage not verified.' @{Account=$s.StartName;Extracted=$false} 'Low'} }
                31 { $dll=Read-Registry "$key\Parameters" 'ServiceDll';if($dll.State-eq'Present'){ $path=[Environment]::ExpandEnvironmentVariables($dll.Value); if(-not [IO.File]::Exists($path)){Add-Evidence $s.Name 'Registered ServiceDll is missing or inaccessible; requires search-order validation.' @{Path=$path;Account=$s.StartName} 'Low'} } }
            }
        }
        return
    }
    if($Id -eq 13){foreach($right in @(@('CreateService',2),@('WriteDacl',0x40000),@('WriteOwner',0x80000))){$r=[StealthPrivesc.Native]::ServiceAccess($null,$right[1]);if($r.Allowed){Add-Evidence 'Service Control Manager' 'Current token holds an SCM control right.' @{Right=$right[0];ElevatedToken=$script:Context.Elevated} $(if($script:Context.Elevated){'Information'}else{'High'})}elseif($r.Error-notin@(0,5)){Set-CheckPartial "SCM access query failed (Win32 $($r.Error))."}};return}
    if($Id -in @(22,23,24,25,26,27)){
        foreach($task in Get-Limited @(Get-Tasks)){
            $name=$task.TaskPath+$task.TaskName; $account=$task.Principal.UserId
            switch($Id){
                22 { Add-Evidence $name 'Scheduled task; arguments omitted.' @{Account=$account;RunLevel=[string]$task.Principal.RunLevel;LogonType=[string]$task.Principal.LogonType;State=[string]$task.State;Executables=@($task.Actions | ForEach-Object{if($_.PSObject.Properties['Execute']){$_.Execute}})} }
                23 { foreach($a in $task.Actions){if($a.PSObject.Properties['Execute']){$arguments=if($a.PSObject.Properties['Arguments']){$a.Arguments}else{''};$working=if($a.PSObject.Properties['WorkingDirectory']-and$a.WorkingDirectory){[Environment]::ExpandEnvironmentVariables($a.WorkingDirectory)}else{[Environment]::SystemDirectory};foreach($path in Get-ReferencedPaths $a.Execute $arguments $working){Add-ExecutableAccess $path "Scheduled-task executable/script/configuration candidate ($name, $account)."}}} }
                24 { if($account-in@('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -and $task.State-ne'Disabled'){Add-WritablePath (Join-Path "$env:SystemRoot\System32\Tasks" $name.TrimStart('\')) 'Writable enabled SYSTEM task file; scheduler API authorization also requires validation.'} }
                25 { foreach($a in $task.Actions){if($a.PSObject.Properties['Execute']){foreach($candidate in Get-UnquotedCandidates $a.Execute){Add-Evidence $name 'Unquoted task-action candidate; Task Scheduler may treat the entire Execute field as the executable.' @{Executable=$a.Execute;Candidate=$candidate} 'Low'}}} }
                26 { if([string]$task.Principal.LogonType-eq'Password'){Add-Evidence $name 'Password-based task logon indicates locally managed credentials.' @{Account=$account;Extracted=$false} 'Low'} }
                27 { if($name-match'(?i)Recall|PolicyConfiguration'){Add-Evidence $name 'Recall-related task marker; presence is not a vulnerability determination.' @{Account=$account;Build=[Environment]::OSVersion.Version.ToString();State=[string]$task.State}} }
            }
        }
        return
    }
    switch($Id){
        28 {
            foreach($root in @('HKLM:','HKCU:')){foreach($leaf in @('Run','RunOnce')){ $path="$root\Software\Microsoft\Windows\CurrentVersion\$leaf";try{$key=Get-Item -LiteralPath $path -ErrorAction Stop;try{foreach($name in $key.GetValueNames()){ $value=$key.GetValue($name);Add-Evidence "$path/$name" 'Autorun entry; command arguments omitted.' @{Executable=(Get-ExecutablePath $value)};Add-ExecutableAccess $value 'Writable autorun executable or parent directory.' }}finally{$key.Close()}}catch [System.Management.Automation.ItemNotFoundException]{}catch{Set-CheckPartial "Cannot read autorun key: $path"}}}
            $shell=New-Object -ComObject WScript.Shell
            try{foreach($path in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){Add-WritablePath $path 'Writable startup directory.';foreach($file in Get-BoundedFiles @($path) -Depth 0){Add-Artifact $file.FullName 'Startup';if($file.Extension-eq'.lnk'){$shortcut=$shell.CreateShortcut($file.FullName);try{foreach($target in Get-ReferencedPaths $shortcut.TargetPath $shortcut.Arguments $shortcut.WorkingDirectory){Add-ExecutableAccess $target 'Writable startup shortcut target.'}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)}}else{Add-WritablePath $file.FullName 'Writable startup file.'}}}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
        }
        29 { foreach($scope in @('Machine','User')){foreach($path in ([Environment]::GetEnvironmentVariable('Path',$scope)-split';')){if($path){Add-WritablePath ([Environment]::ExpandEnvironmentVariables($path.Trim('"'))) "Writable $scope PATH directory."}}} }
        30 { foreach($p in Get-Limited @(Get-Process -ErrorAction Stop)){try{foreach($m in $p.Modules){Add-WritablePath $m.FileName "Writable loaded module candidate (PID $($p.Id))."}}catch{Set-CheckPartial 'Some process modules could not be enumerated.'}} }
        32 { foreach($app in Get-Limited @(Get-Applications)){if($app.Location){Add-WritablePath $app.Location "Writable installed application directory ($($app.Name)).";foreach($item in Get-BoundedFiles @($app.Location) -Depth 4 -Directories){Add-WritablePath $item.FullName "Writable installed application file/directory ($($app.Name))."}}} }
        33 { foreach($dir in Get-BoundedFiles @($env:ProgramData) -Depth 1 -Directories){if($dir.PSIsContainer){Add-WritablePath $dir.FullName 'Writable application data directory; privileged execution is not established.'}} }
        34 { foreach($drive in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop){$root=$drive.DeviceID+'\';Add-WritablePath $root 'Writable fixed-drive root.';foreach($item in Get-BoundedFiles @($root) -Depth 0 -Directories){Add-WritablePath $item.FullName 'Writable immediate fixed-drive-root item.'}} }
        35 { foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 3 -Pattern '\.(exe|dll|sys|ps1|bat|cmd|vbs)$'){Add-WritablePath $file.FullName 'Writable executable/script in scoped search roots; privileged use not established.'} }
        {$_ -in @(36,37,38,39)} {
            foreach($root in @('HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID','HKCU:\SOFTWARE\Classes\CLSID')){
                foreach($clsid in Get-Limited @(Get-RegistryChildren $root)){foreach($type in @('InprocServer32','LocalServer32')){
                    $key=$clsid.PSPath+'\'+$type; $value=Read-Registry $key ''
                    if($value.State-ne'Present' -or -not $value.Value){continue}
                    $path=Get-ExecutablePath $value.Value
                    switch($Id){
                        36 {Add-WritablePath $key 'Writable COM server registration.' -Registry}
                        37 {Add-ExecutableAccess $value.Value 'Writable COM server executable or directory.'}
                        38 {if(-not[IO.Path]::IsPathRooted($path)){$resolved=@();$directories=@(Get-DefaultDllSearchDirectories);foreach($dir in $directories){$target=Join-Path $dir $path;if((Get-FilePresence $target)-eq'Present'){$resolved+=$target}};Add-Evidence $key 'Relative COM module registration evaluated against system DLL search locations; host-specific loader changes require validation.' @{Module=$path;ResolvedCandidates=$resolved} 'Low';if(-not$resolved.Count){foreach($dir in $directories){Add-WritablePath $dir 'Writable search directory for an unresolved relative COM module.'}}}}
                        39 {if([IO.Path]::IsPathRooted($path) -and (Get-FilePresence $path)-eq'Missing'){Add-Evidence $key 'COM registration references a nonexistent file.' @{Module=$path} 'Low'}}
                    }
                }}
            }
        }
        40 { foreach($root in @('HKLM:\SOFTWARE','HKLM:\SYSTEM\CurrentControlSet\Control','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion')){Add-WritablePath $root 'Writable machine registry key.' -Registry;foreach($key in Get-Limited @(Get-RegistryChildren $root)){Add-WritablePath $key.PSPath 'Writable sampled machine registry key.' -Registry}} }
        41 { $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$currentSid=$identity.User.Value}finally{$identity.Dispose()};foreach($hive in Get-Limited @(Get-RegistryChildren 'Registry::HKEY_USERS')){if($hive.PSChildName-match'^S-1-5-21-'-and$hive.PSChildName-ne$currentSid){Add-WritablePath ($hive.PSPath+'\Software\Microsoft\Input\TypingInsights') 'Cross-user write access to the loaded profile TypingInsights key.' -Registry}} }
        42 {
            $self=[Security.Principal.WindowsIdentity]::GetCurrent();try{$selfSid=$self.User.Value}finally{$self.Dispose()}
            foreach($p in Get-Limited @(Get-CimInstance Win32_Process -ErrorAction Stop)){
                try{$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue-ne0){Set-CheckPartial 'Some process owners could not be resolved.';continue};if($owner.Sid-eq$selfSid){continue}
                    foreach($right in @(@('CreateThread',2),@('VmWrite',0x20),@('DuplicateHandle',0x40),@('WriteDacl',0x40000))){$r=[StealthPrivesc.Native]::ProcessAccess($p.ProcessId,$right[1]);if($r.Allowed){Add-Evidence "$($p.Name) ($($p.ProcessId))" 'Cross-user process access capability; handle immediately closed.' @{OwnerSid=$owner.Sid;Right=$right[0]} $(if($script:Context.Elevated){'Information'}else{'Medium'})}}
                }catch{Set-CheckPartial 'Some processes exited or could not be assessed.'}
            }
        }
        44 { foreach($pipe in Get-Limited @([IO.Directory]::GetFiles('\\.\pipe\'))){Add-Evidence $pipe 'Named pipe exists; no pipe connection or data exchange performed.'} }
        46 { foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 3 -Pattern '\.(config|xml)$'){if($file.Length-le$script:Context.MaxFileBytes){try{$text=[IO.File]::ReadAllText($file.FullName);if($text-match'(?i)system\.runtime\.remoting|SoapClient|SoapFormatter|typeFilterLevel'){Add-Evidence $file.FullName '.NET remoting/SOAP configuration marker; not proof of SOAPwn exposure.' @{Values='[REDACTED]'} 'Low'}}catch{Set-CheckPartial 'Some configuration files were unreadable.'}}} }
    }
}
function Get-SearchRoots {
    if($script:Context.SearchRoot.Count){return $script:Context.SearchRoot}
    @($env:ProgramData,(Join-Path $env:USERPROFILE 'Documents'))
}
