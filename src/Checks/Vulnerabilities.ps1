function Invoke-VulnerabilityCheck {
    param([int]$Id)
    if($Id-in@(54,55)){
        $data=Get-ReferenceDocument $script:Context.VulnerabilityDatabasePath 'MSRC'
        if(-not$data){return}
        $context=Get-WindowsVersionContext
        $cves=if($Id-eq55){@('CVE-2019-0836','CVE-2019-0841','CVE-2019-1064','CVE-2019-1130','CVE-2019-1253','CVE-2019-1315','CVE-2019-1385','CVE-2019-1388','CVE-2019-1405','CVE-2020-0668','CVE-2020-0683','CVE-2020-1013')}else{@()}
        $results=@(Get-WindowsPatchAssessment -Rules $data.Entries -Context $context -Cve $cves)
        if(-not$results.Count){Set-CheckPartial 'No matching OS product/build rules in the selected MSRC snapshot.'}
        foreach($result in Get-Limited $results){
            if($result.State-eq'NoMatchingProductRule'){Set-CheckPartial 'Some CVEs have no matching product rule; their applicability is unknown.'}
            Add-Evidence $result.Cve 'Exact OS servicing-branch comparison against Microsoft-published fixed builds; this is a patch applicability indicator.' $result $(if($result.State-eq'BelowPublishedFix'){'High'}else{'Information'}) 'Install the appropriate supported cumulative security update and reboot as required.'
        }
        return
    }
    if($Id-eq59){
        $data=Get-ReferenceDocument $script:Context.DriverDatabasePath 'LOLDrivers'
        if(-not$data){return}
        $drivers=@(Get-Limited @(Get-InstalledDriverFiles))
        foreach($match in Get-DriverHashMatches $data.Entries $drivers){
            Add-Evidence $match.Path 'Installed driver SHA256 exactly matches the LOLDrivers dataset.' $match 'High' 'Review the matching advisory, update or remove the affected driver, and verify the active driver-blocking policy.'
        }
    }
}
