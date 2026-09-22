function Invoke-InventoryCheck {
    param([int]$Id)
    switch($Id){
        {$_ -in @(54,55,56)} {
            Add-Evidence 'Windows build' 'OS/build evidence; hotfix absence alone does not establish a missing security fix.' (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop|Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime)
            Add-RegistryEvidence 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' @('UBR','DisplayVersion','CurrentBuildNumber')
            foreach($fix in Get-Limited @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop)){Add-Evidence $fix.HotFixID 'Installed hotfix inventory; cumulative-update supersedence is not evaluated.' ($fix|Select-Object HotFixID,Description,InstalledOn)}
        }
        {$_ -in @(58,61)} {
            foreach($driver in Get-Limited @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop)){Add-Evidence $driver.DeviceName 'PnP driver signing metadata.' ($driver|Select-Object DeviceName,DriverVersion,DriverDate,DriverProviderName,InfName,IsSigned,Signer) $(if($Id-eq61 -and -not$driver.IsSigned){'Medium'}else{'Information'})}
        }
        59 { foreach($driver in Get-Limited @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)){ $path=Get-ExecutablePath $driver.PathName;if($path -and $path.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$path=$env:SystemRoot+$path.Substring(11)};if($path -and [IO.File]::Exists($path)){try{Add-Evidence $driver.Name 'Installed driver hash for offline reputation comparison.' @{Path=$path;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}}catch{Set-CheckPartial 'Some driver files could not be hashed.'}}} }
        60 { Add-RegistryEvidence 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' @('VulnerableDriverBlocklistEnable');foreach($file in Get-BoundedFiles @("$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active") -Depth 0 -Pattern '\.cip$'){Add-Artifact $file.FullName 'Active Code Integrity policy'} }
        62 { foreach($app in Get-Limited @(Get-Applications|Where-Object{$_.Publisher-match'(?i)Dell|Lenovo|ASUSTeK|GIGABYTE|Micro-Star|Hewlett|HP Inc'})){Add-Evidence $app.Name 'OEM utility inventory heuristic; no vulnerable version determination.' $app} }
        63 { foreach($app in Get-Limited @(Get-Applications)){Add-Evidence $app.Name 'Installed application/version for external vulnerability correlation; no online lookup performed.' ($app|Select-Object Name,Version,Publisher)} }
        124 { Add-Evidence 'Operating system' 'OS and architecture.' (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop|Select-Object Caption,Version,BuildNumber,OSArchitecture,ProductType);Add-Evidence 'Computer' 'Machine role and domain membership.' (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop|Select-Object Name,Domain,PartOfDomain,DomainRole,Manufacturer,Model);Add-Evidence 'Runtime' 'PowerShell/.NET runtime.' @{PowerShell=$PSVersionTable.PSVersion.ToString();CLR=[Environment]::Version.ToString();Is64BitProcess=[Environment]::Is64BitProcess} }
        125 {
            foreach($app in Get-Limited @(Get-Applications)){Add-Evidence $app.Name 'Installed application.' $app}
            foreach($p in Get-Limited @(Get-CimInstance Win32_Process -ErrorAction Stop)){Add-Evidence "$($p.Name) ($($p.ProcessId))" 'Running process; raw command lines omitted to prevent secret disclosure.' ($p|Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,SessionId)}
            try{foreach($feature in Get-Limited @(Get-WindowsOptionalFeature -Online -ErrorAction Stop|Where-Object State -eq Enabled)){Add-Evidence $feature.FeatureName 'Enabled optional Windows feature.'}}catch{Set-CheckPartial 'Optional-feature inventory requires additional access or DISM support.'}
        }
        {$_ -in @(127,128)} {
            $filter=if($Id-eq127){@{LogName='System';Id=@(12,13,41,42,1074,6005,6006,6008)}}else{@{LogName='Security';Id=@(4624,4648)}}
            try{$events=@(Get-WinEvent -FilterHashtable $filter -MaxEvents $script:Context.MaxItems -ErrorAction Stop);foreach($event in $events){Add-Evidence "$($event.LogName)/$($event.RecordId)" 'Event metadata; event payloads omitted.' ($event|Select-Object Id,TimeCreated,ProviderName,RecordId)};if($events.Count-eq$script:Context.MaxItems){Set-CheckPartial 'Only the newest events within MaxItems are included.'}}catch{Set-CheckPartial 'Event log inaccessible or no matching events.'}
        }
        129 {foreach($disk in Get-Limited @(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop)){Add-Evidence $disk.DeviceID 'Logical disk or mapped drive.' ($disk|Select-Object DeviceID,DriveType,FileSystem,Size,FreeSpace,ProviderName)};foreach($share in Get-Limited @(Get-CimInstance Win32_Share -ErrorAction Stop)){Add-Evidence $share.Name 'Local share.' ($share|Select-Object Name,Path,Type,Description)}}
        130 {
            foreach($adapter in Get-Limited @(Get-NetIPConfiguration -ErrorAction Stop)){Add-Evidence $adapter.InterfaceAlias 'Network interface addresses.' @{InterfaceIndex=$adapter.InterfaceIndex;IPv4=@($adapter.IPv4Address|ForEach-Object IPAddress);IPv6=@($adapter.IPv6Address|ForEach-Object IPAddress)}}
            foreach($route in Get-Limited @(Get-NetRoute -ErrorAction Stop)){Add-Evidence $route.DestinationPrefix 'Route.' ($route|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}
            foreach($entry in Get-Limited @(Get-NetNeighbor -ErrorAction Stop)){Add-Evidence $entry.IPAddress 'Neighbor cache.' ($entry|Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State)}
            Add-Artifact "$env:SystemRoot\System32\drivers\etc\hosts" 'Hosts file'
        }
        131 {foreach($tcp in Get-Limited @(Get-NetTCPConnection -ErrorAction Stop)){Add-Evidence "$($tcp.LocalAddress):$($tcp.LocalPort)" 'TCP connection/listener.' ($tcp|Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)};foreach($udp in Get-Limited @(Get-NetUDPEndpoint -ErrorAction Stop)){Add-Evidence "$($udp.LocalAddress):$($udp.LocalPort)" 'UDP endpoint.' ($udp|Select-Object LocalAddress,LocalPort,OwningProcess)}}
        132 {foreach($record in Resolve-DnsName 'www.microsoft.com' -DnsOnly -QuickTimeout -ErrorAction Stop){Add-Evidence 'www.microsoft.com' 'Explicit opt-in external DNS resolution; does not prove general internet connectivity.' ($record|Select-Object Name,Type,IPAddress)}}
        134 {foreach($class in @('__EventFilter','__EventConsumer','__FilterToConsumerBinding')){foreach($item in Get-Limited @(Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction Stop)){Add-Evidence $class 'Permanent WMI subscription object; commands/scripts omitted.' @{Class=$item.CimClass.CimClassName;ObjectPath=[string]$item.CimSystemProperties.Path}}}}
        135 {foreach($printer in Get-Limited @(Get-CimInstance Win32_Printer -ErrorAction Stop)){Add-Evidence $printer.Name 'Printer inventory.' ($printer|Select-Object Name,DriverName,PortName,Shared,ShareName,Network,Local)}}
        139 {foreach($item in Get-BoundedFiles (Get-SearchRoots) -Depth 1 -Directories){Add-Evidence $item.FullName 'Scoped filesystem metadata.' @{Directory=$item.PSIsContainer;LastWriteUtc=$item.LastWriteTimeUtc.ToString('o');Attributes=$item.Attributes.ToString()}}}
        148 {foreach($name in @('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','AWS_WEB_IDENTITY_TOKEN_FILE','IDENTITY_ENDPOINT','MSI_ENDPOINT','GOOGLE_APPLICATION_CREDENTIALS','KUBERNETES_SERVICE_HOST','CONTAINER_SANDBOX_MOUNT_POINT')){$value=[Environment]::GetEnvironmentVariable($name);if($value){Add-Evidence $name 'Cloud/container identity environment marker; value omitted and endpoint not contacted.' @{Value='[REDACTED]'} 'Low'}};Add-Artifact 'C:\.dockerenv' 'Container';Add-Artifact "$env:ProgramData\Google\CredentialProvider" 'Google credential provider'}
    }
}
