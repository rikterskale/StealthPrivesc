function Invoke-Check {
    param([int]$Id)
    if($Id-eq147){Invoke-RelayConfigurationCheck;return}
    if($Id-in@(140,148)){Invoke-CloudAndToolsCheck $Id;return}
    if($Id-in@(31,46)){Invoke-AdditionalExecutionCheck $Id;return}
    if($Id-eq137){Invoke-RecentArtifactCheck;return}
    if($Id-in@(95,96)){Invoke-WifiCheck $Id;return}
    if($Id-in@(98,136)){Invoke-BrowserArtifactCheck $Id;return}
    if($Id-in@(62,63)){Invoke-PackageRiskCheck $Id;return}
    if($Id-in@(48,51,52,64,66,104,108,109,114,117,123)){Invoke-PolicyAnalysisCheck $Id;return}
    if($Id-eq60){Invoke-CodeIntegrityCheck;return}
    if($Id-in@(71,80,81,82,85,86,88,89,90,91,92,93,138)){Invoke-ApplicationArtifactCheck $Id;return}
    if($Id-in@(19,22,27,30,42)){Invoke-ExecutionAnalysisCheck $Id;return}
    if($Id-in@(56,58,61)){Invoke-ExtendedInventoryCheck $Id;return}
    if($Id-eq43){Invoke-HandleCheck;return}
    if($Id-in@(73,74,75,76)){Invoke-CredentialStoreCheck $Id;return}
    if($Id-eq139){Invoke-SearchIndexCheck;return}
    if($Id-in@(54,55,59)){Invoke-VulnerabilityCheck $Id;return}
    if($Id-in@(24,44,45,65)){Invoke-ObjectAccessCheck $Id;return}
    if($Id-in@(72,126,133)){Invoke-NativeInspectionCheck $Id;return}
    if($Id-ge1 -and $Id-le10){Invoke-IdentityCheck $Id;return}
    if($Id-ge11 -and $Id-le46){Invoke-ExecutionCheck $Id;return}
    if($Id-in@(49,50)){Invoke-InstallerCheck $Id;return}
    if($Id-in@(47,48,51,52,53,57,64,66,147) -or ($Id-ge100 -and $Id-le123)){Invoke-PolicyCheck $Id;return}
    if(($Id-ge67 -and $Id-le99) -or $Id-in@(136,137,138,140)){Invoke-ArtifactCheck $Id;return}
    if($Id-ge141 -and $Id-le146){Invoke-DomainCheck $Id;return}
    if($Id-in@(54,55,56,58,59,60,61,62,63,124,125,127,128,129,130,131,132,134,135,139,148)){Invoke-InventoryCheck $Id;return}
    throw "No collector registered for check $Id"
}
