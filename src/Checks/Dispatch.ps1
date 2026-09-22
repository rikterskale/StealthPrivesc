function Invoke-Check {
    param([int]$Id)
    if($Id-ge1 -and $Id-le10){Invoke-IdentityCheck $Id;return}
    if($Id-ge11 -and $Id-le46){Invoke-ExecutionCheck $Id;return}
    if($Id-in@(49,50)){Invoke-InstallerCheck $Id;return}
    if($Id-in@(47,48,51,52,53,57,64,66,147) -or ($Id-ge100 -and $Id-le123)){Invoke-PolicyCheck $Id;return}
    if(($Id-ge67 -and $Id-le99) -or $Id-in@(136,137,138,140)){Invoke-ArtifactCheck $Id;return}
    if($Id-ge141 -and $Id-le146){Invoke-DomainCheck $Id;return}
    if($Id-in@(54,55,56,58,59,60,61,62,63,124,125,127,128,129,130,131,132,134,135,139,148)){Invoke-InventoryCheck $Id;return}
    throw "No collector registered for check $Id"
}
