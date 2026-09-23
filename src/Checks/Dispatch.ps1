function Get-CheckCollector {
    param([int]$Id)
    if($Id-eq147){return 'Invoke-RelayConfigurationCheck'}
    if($Id-in@(140,148)){return 'Invoke-CloudAndToolsCheck'}
    if($Id-in@(31,46)){return 'Invoke-AdditionalExecutionCheck'}
    if($Id-eq137){return 'Invoke-RecentArtifactCheck'}
    if($Id-in@(95,96)){return 'Invoke-WifiCheck'}
    if($Id-in@(98,136)){return 'Invoke-BrowserArtifactCheck'}
    if($Id-in@(62,63)){return 'Invoke-PackageRiskCheck'}
    if($Id-in@(48,51,52,64,66,104,108,109,114,117,123)){return 'Invoke-PolicyAnalysisCheck'}
    if($Id-eq60){return 'Invoke-CodeIntegrityCheck'}
    if($Id-in@(71,80,81,82,85,86,88,89,90,91,92,93,138)){return 'Invoke-ApplicationArtifactCheck'}
    if($Id-in@(19,22,27,30,42)){return 'Invoke-ExecutionAnalysisCheck'}
    if($Id-in@(56,58,61)){return 'Invoke-ExtendedInventoryCheck'}
    if($Id-eq43){return 'Invoke-HandleCheck'}
    if($Id-in@(73,74,75,76)){return 'Invoke-CredentialStoreCheck'}
    if($Id-eq139){return 'Invoke-SearchIndexCheck'}
    if($Id-in@(54,55,59)){return 'Invoke-VulnerabilityCheck'}
    if($Id-in@(24,44,45,65)){return 'Invoke-ObjectAccessCheck'}
    if($Id-in@(72,126,133)){return 'Invoke-NativeInspectionCheck'}
    if($Id-ge1 -and $Id-le10){return 'Invoke-IdentityCheck'}
    if($Id-ge11 -and $Id-le46){return 'Invoke-ExecutionCheck'}
    if($Id-in@(49,50)){return 'Invoke-InstallerCheck'}
    if($Id-in@(47,48,51,52,53,57,64,66,147) -or ($Id-ge100 -and $Id-le123)){return 'Invoke-PolicyCheck'}
    if(($Id-ge67 -and $Id-le99) -or $Id-in@(136,137,138,140)){return 'Invoke-ArtifactCheck'}
    if($Id-ge141 -and $Id-le146){return 'Invoke-DomainCheck'}
    if($Id-in@(54,55,56,58,59,60,61,62,63,124,125,127,128,129,130,131,132,134,135,139,148)){return 'Invoke-InventoryCheck'}
    throw "No collector registered for check $Id"
}

function Invoke-Check {
    param([int]$Id)
    $collector = Get-CheckCollector $Id
    $arguments = if ($Id -in @(43,60,137,139,147)) { @{} } else { @{Id=$Id} }
    if ($script:Current.Contains('Verification')) {
        $script:Current.Verification.SourceReferences = @(Get-CheckSourceReferences -Collector $collector -Id $Id)
        $script:Current.Verification.CollectorStarted = $true
    }
    $command = if ($arguments.Count) { "$collector -Id $Id" } else { $collector }
    Add-CheckCommand -Kind Collector -Command $command -Detail 'Internal module collector; use RerunCommand to initialize its context and native dependencies.'
    & $collector @arguments
}
