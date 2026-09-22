#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Drivers,
    [switch]$WindowsUpdates,
    [switch]$Lolbas,
    [string[]]$Month,
    [string]$OutputDirectory=(Join-Path $PSScriptRoot '../data/reference')
)
$ErrorActionPreference='Stop'
if(-not$Drivers-and-not$WindowsUpdates-and-not$Lolbas){throw 'Select -Drivers, -WindowsUpdates and/or -Lolbas.'}
[void][IO.Directory]::CreateDirectory($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory))
function Get-PublicJson([string]$Uri) {
    $result=Invoke-RestMethod -Uri $Uri -Headers @{Accept='application/json'} -TimeoutSec 45
    if($result-is[string]){return ,($result|ConvertFrom-Json -AsHashtable)}
    return ,($result|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable)
}
function Save-Reference([string]$Name,[object]$Data) {
    $target=Join-Path $OutputDirectory $Name
    $temporary=$target+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        $Data|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $temporary -Encoding utf8
        Move-Item -LiteralPath $temporary -Destination $target -Force
    }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
    Write-Host "Updated $target"
}
if($Lolbas){
    $uri='https://lolbas-project.github.io/api/lolbas.json';$source=Get-PublicJson $uri
    $entries=@($source|ForEach-Object{[ordered]@{Name=$_.Name;Paths=@($_.Full_Path|ForEach-Object Path)}})
    if(-not$entries.Count){throw 'LOLBAS returned no discovery records.'}
    foreach($name in @('LICENSE','NOTICE.md')){
        $outputName=if($name-eq'LICENSE'){'LOLBAS-LICENSE.txt'}else{'LOLBAS-NOTICE.md'}
        Invoke-WebRequest ('https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/'+$name) -OutFile (Join-Path $OutputDirectory $outputName) -TimeoutSec 45
    }
    Save-Reference 'lolbas.json' ([ordered]@{SchemaVersion=1;RetrievedUtc=[DateTime]::UtcNow.ToString('o');Source=$uri;Modification='Names and discovery paths only; no commands included.';Entries=$entries})
}
if($Drivers){
    $uri='https://www.loldrivers.io/api/drivers.json'
    $source=Get-PublicJson $uri
    $entries=@(foreach($driver in $source){foreach($sample in $driver.KnownVulnerableSamples){
        if($sample.SHA256-match'^[a-fA-F0-9]{64}$'){
            $certificates=@(foreach($signature in $sample.Signatures){foreach($certificate in $signature.Certificates){if($certificate.IsCodeSigning){[ordered]@{Subject=$certificate.Subject;TBS=$certificate.TBS}}}})
            [ordered]@{SHA256=$sample.SHA256.ToLowerInvariant();SHA1=$sample.SHA1;Authentihash=$sample.Authentihash;Certificates=$certificates;Publisher=$sample.Publisher;FileVersion=$sample.FileVersion;InternalName=$sample.InternalName;ProductName=$sample.Product;FileDescription=$sample.Description;Id=$driver.Id;Category=$driver.Category;Names=@($driver.Tags);Filename=$sample.Filename;OriginalFilename=$sample.OriginalFilename;Resources=@($driver.Resources)}
        }
    }})
    if(-not$entries.Count){throw 'LOLDrivers returned no valid SHA256 records.'}
    $licenseUri='https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/LICENSE'
    $license=Invoke-RestMethod -Uri $licenseUri -TimeoutSec 45
    $license|Set-Content -LiteralPath (Join-Path $OutputDirectory 'LOLDrivers-LICENSE.txt') -Encoding utf8
    Save-Reference 'drivers.json' ([ordered]@{SchemaVersion=1;Source=$uri;RetrievedUtc=[DateTime]::UtcNow.ToString('o');License='Apache-2.0; see LOLDrivers-LICENSE.txt';Modification='Reduced to identity, hashes, signing metadata, category and reference fields. No binaries or commands included.';Entries=$entries})
}
if($WindowsUpdates){
    if(-not$Month){$Month=@(0..2|ForEach-Object{(Get-Date).AddMonths(-$_).ToString('yyyy-MMM',[Globalization.CultureInfo]::InvariantCulture)})}
    $entries=New-Object 'System.Collections.Generic.List[object]'
    $legacyCves=@('CVE-2019-0836','CVE-2019-0841','CVE-2019-1064','CVE-2019-1130','CVE-2019-1253','CVE-2019-1315','CVE-2019-1385','CVE-2019-1388','CVE-2019-1405','CVE-2020-0668','CVE-2020-0683','CVE-2020-1013')
    $kbBuilds=@{}
    $kbCachePath=Join-Path $OutputDirectory 'kb-builds.json'
    if(Test-Path -LiteralPath $kbCachePath){$kbBuilds=Get-Content -LiteralPath $kbCachePath -Raw|ConvertFrom-Json -AsHashtable}
    $branchNames=@{'1507'=10240;'1511'=10586;'1607'=14393;'1703'=15063;'1709'=16299;'1803'=17134;'1809'=17763;'1903'=18362;'1909'=18363;'2004'=19041}
    function Get-LegacyBuild([string]$Product,[string]$KB) {
        $branch=0
        if($Product-match'Windows 10 Version (\d{4})'){$branch=$branchNames[$Matches[1]]}
        elseif($Product-match'^Windows 10 for'){$branch=10240}
        elseif($Product-match'^Windows Server 2016'){$branch=14393}
        elseif($Product-match'^Windows Server 2019'){$branch=17763}
        elseif($Product-match'^Windows Server, version (\d{4})'){$branch=$branchNames[$Matches[1]]}
        if(-not$branch-or$KB-notmatch'^\d{7}$'){return $null}
        if(-not$kbBuilds.ContainsKey($KB)){
            try{$page=Invoke-WebRequest -UseBasicParsing -Uri "https://support.microsoft.com/help/$KB" -TimeoutSec 45}
            catch{Write-Warning "Microsoft KB $KB is unavailable; its legacy build rule will be omitted.";return $null}
            $title=[Net.WebUtility]::HtmlDecode([regex]::Match([string]$page.Content,'(?is)<title>(.*?)</title>').Groups[1].Value)
            $kbBuilds[$KB]=@([regex]::Matches($title,'\b(\d{5}\.\d+)\b')|ForEach-Object{$_.Groups[1].Value})
            $kbBuilds|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $kbCachePath -Encoding utf8
        }
        foreach($build in $kbBuilds[$KB]){if($build.StartsWith("$branch.")){return "10.0.$build"}}
        return $null
    }
    foreach($period in $Month){
        if($period-notmatch'^20\d\d-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$'){throw "Invalid CVRF month: $period"}
        $uri="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$period"
        $document=Get-PublicJson $uri
        $products=@{}
        foreach($product in $document.ProductTree.FullProductName){$products[[string]$product.ProductID]=[string]$product.Value}
        foreach($vulnerability in $document.Vulnerability){
            foreach($remediation in $vulnerability.Remediations){
                if($remediation.Type-ne2){continue}
                foreach($productId in $remediation.ProductID){
                    $name=$products[[string]$productId]
                    if($name-notmatch'^Windows (10 |11 |Server |7 |8\.1 |8 )'){continue}
                    $fixed=$remediation.FixedBuild
                    $sourceUrl=$uri
                    if($fixed-notmatch'^\d+\.\d+\.\d+\.\d+$'-and$vulnerability.CVE-in$legacyCves){
                        $fixed=Get-LegacyBuild $name ([string]$remediation.Description.Value)
                        $sourceUrl="https://support.microsoft.com/help/$($remediation.Description.Value)"
                    }
                    if($fixed-notmatch'^\d+\.\d+\.\d+\.\d+$'){continue}
                    $entries.Add([ordered]@{Cve=$vulnerability.CVE;Title=$vulnerability.Title.Value;Product=$name;ProductId=[string]$productId;FixedBuild=$fixed;KB=$remediation.Description.Value;Source=$sourceUrl;Month=$period})
                }
            }
        }
        Write-Host "Imported $period"
    }
    if(-not$entries.Count){throw 'No Windows OS fixed-build records were returned; previous reference data retained.'}
    $unique=@($entries|ForEach-Object{[pscustomobject]$_}|Sort-Object Cve,ProductId,FixedBuild -Unique)
    Save-Reference 'windows-updates.json' ([ordered]@{SchemaVersion=1;Source='Microsoft Security Response Center CVRF v3';RetrievedUtc=[DateTime]::UtcNow.ToString('o');Months=$Month;Entries=$unique})
}
