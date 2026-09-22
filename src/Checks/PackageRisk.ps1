function Invoke-PackageRiskCheck {
    param([int]$Id)
    $apps=@(Get-Limited @(Get-Applications))
    if($Id-eq62){
        $services=@(Get-Services)
        foreach($app in $apps|Where-Object{$_.Publisher-match'(?i)Dell|Lenovo|ASUSTeK|GIGABYTE|Micro-Star|Hewlett|HP Inc'}){
            $matches=@($services|Where-Object{$image=Get-ExecutablePath $_.PathName;$app.Location-and$image-and$image.StartsWith($app.Location.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)})
            Add-Evidence $app.Name 'OEM installed utility correlated with its privileged services and executable access.' @{Version=$app.Version;Publisher=$app.Publisher;Location=$app.Location;Services=@($matches|Select-Object Name,StartName,StartMode,State)}
            foreach($service in $matches){Add-ExecutableAccess $service.PathName "OEM utility service target ($($service.Name), $($service.StartName))."}
        }
        $data=Get-ReferenceDocument $script:Context.DriverDatabasePath 'LOLDrivers'
        if($data){foreach($match in Get-DriverHashMatches $data.Entries @(Get-Limited @(Get-InstalledDriverFiles))){Add-Evidence $match.Path 'Known vulnerable OEM/system driver component; exact SHA256 advisory match.' $match 'High'}}
        return
    }
    foreach($app in $apps){Add-Evidence $app.Name 'Installed package identity used for advisory lookup.' ($app|Select-Object Name,Version,Publisher)}
    if(-not$script:Context.IncludeNetwork){Set-CheckPartial 'Online package advisory lookup requires -IncludeNetwork; it sends package names and versions to the public NVD service.';return}
    $queried=0
    foreach($app in $apps){
        if(-not$app.Name-or-not$app.Version){continue}
        if($queried-ge10){Set-CheckPartial 'Public advisory lookup is capped at ten package queries per run to respect NVD rate limits.';break}
        if($queried){Start-Sleep -Seconds 6};$queried++
        $term=$app.Name+' '+$app.Version
        try{
            $url='https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&keywordSearch='+[Uri]::EscapeDataString($term)
            $response=Invoke-RestMethod -Uri $url -TimeoutSec $script:Context.CommandTimeoutSeconds -ErrorAction Stop
            foreach($entry in @($response.vulnerabilities)){$cve=$entry.cve;Add-Evidence $app.Name 'NVD package/version keyword advisory candidate; CPE applicability requires validation and this is not a confirmed vulnerability.' @{Version=$app.Version;Cve=$cve.id;Published=$cve.published;LastModified=$cve.lastModified;Source=('https://nvd.nist.gov/vuln/detail/'+$cve.id)} 'Low'}
            Add-Evidence $app.Name 'Public advisory lookup completed; no keyword match does not establish absence of vulnerabilities.' @{Returned=@($response.vulnerabilities).Count;Total=$response.totalResults}
            if($response.totalResults-gt20){Set-CheckPartial 'NVD candidate results exceeded the per-package result cap.'}
        }catch{Set-CheckPartial 'Public advisory request failed or was rate-limited.';break}
    }
}
