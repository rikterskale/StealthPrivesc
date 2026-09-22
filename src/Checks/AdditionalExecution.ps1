function Invoke-AdditionalExecutionCheck {
    param([int]$Id)
    if($Id-eq31){
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop;$version=[version]$os.Version
        $rules=@(
            @{Service='CDPSvc';Dll='cdpsgshims.dll';Major=10;Source='https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html'},
            @{Service='Schedule';Dll='WptsExtensions.dll';Major=10;Source='http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html'},
            @{Service='StorSvc';Dll='SprintCSP.dll';Major=10;Source='https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc'},
            @{Service='IKEEXT';Dll='wlbsctrl.dll';Major=6;Source='https://itm4n.github.io/dll-hijacking-ikeext/'},
            @{Service='NetMan';Dll='wlanhlp.dll';Major=6;Source='https://github.com/itm4n/PrivescCheck'}
        )
        foreach($rule in $rules|Where-Object Major -eq $version.Major){
            $service=Get-Services|Where-Object Name -eq $rule.Service
            if(-not$service-or$service.StartMode-eq'Disabled'){continue}
            $directories=@(Get-DefaultDllSearchDirectories (Get-ExecutablePath $service.PathName));$present=@();$unknown=$false
            foreach($directory in $directories){$candidate=Join-Path $directory $rule.Dll;$state=Get-FilePresence $candidate;if($state-eq'Present'){$present+=$candidate};if($state-eq'Unknown'){$unknown=$true}}
            if(-not$present.Count-and-not$unknown){Add-Evidence $rule.Service 'Known service DLL-search candidate missing from default search locations. The historical OS-family rule is not proof that this serviced binary still loads it.' @{Dll=$rule.Dll;Account=$service.StartName;Build=$os.BuildNumber;Source=$rule.Source} 'Low';foreach($directory in $directories){Add-WritablePath $directory "Writable search directory for known missing service DLL $($rule.Dll)."}}
        }
    }
    if($Id-eq46){
        foreach($file in Get-BoundedFiles (Get-SearchRoots) -Depth 5 -Pattern '\.(config|xml|wsdl|cs|vb)$'){
            if($file.Length-gt$script:Context.MaxFileBytes){Set-CheckPartial 'SOAP configuration/source exceeds MaxFileBytes.';continue}
            try{$text=[IO.File]::ReadAllText($file.FullName);$client=$text-match'(?i)SoapHttpClientProtocol|HttpWebClientProtocol|ServiceDescriptionImporter|WebReference';$url=$text-match'(?i)file://|\\\\[^\\\s]+\\';$defaultCredentials=$text-match'(?i)(UseDefaultCredentials\s*=\s*true|CredentialCache\.DefaultCredentials)';if($client){Add-Evidence $file.FullName 'SOAP HTTP-client proxy/WSDL surface; unsafe URI schemes and default-credential use are independent risk markers. Untrusted input reachability requires application analysis.' @{ClientProxyMarker=$client;FileOrUNCUri=$url;DefaultCredentials=$defaultCredentials;Values='[REDACTED]';Source='https://labs.watchtowr.com/soapwn-pwning-net-framework-applications-through-http-client-proxies-and-wsdl/'} $(if($url-or$defaultCredentials){'Medium'}else{'Low'});Add-WritablePath $file.FullName 'Writable SOAP proxy configuration/source candidate.'}}
            catch{Set-CheckPartial 'SOAP configuration/source could not be inspected.'}
        }
    }
}
