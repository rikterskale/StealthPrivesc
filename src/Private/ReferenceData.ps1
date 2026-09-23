function Get-ReferenceDocument {
    param([string]$Path,[string]$Kind)
    if(-not(Test-AllowedLocalPath $Path)){return $null}
    try{
        $file=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($file.Length-gt100MB){throw 'Reference document exceeds size limit.'}
        $document=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
        if($document.SchemaVersion-ne1-or-not$document.PSObject.Properties['Entries']){throw 'Unsupported reference schema.'}
        $retrieved=[DateTimeOffset]::Parse($document.RetrievedUtc,[Globalization.CultureInfo]::InvariantCulture)
        Add-Evidence $file.FullName "$Kind reference snapshot." @{Source=$document.Source;RetrievedUtc=$document.RetrievedUtc;Entries=@($document.Entries).Count;SHA256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
        if(([DateTimeOffset]::UtcNow-$retrieved).TotalDays-gt30){Set-CheckPartial "$Kind reference data is older than 30 days."}
        return $document
    }catch{Set-CheckPartial "$Kind reference data is missing or invalid. Run tools/Update-ReferenceData.ps1 or supply a validated reference path." -ErrorRecord $_;return $null}
}
function Get-WindowsVersionContext {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $ubr=Read-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
    if($ubr.State-ne'Present'){throw 'Cannot determine Windows update build revision.'}
    $base=[version]$os.Version
    $architecture=if($os.OSArchitecture-match'ARM'){ 'arm64' }elseif([Environment]::Is64BitOperatingSystem){'x64'}else{'x86'}
    [pscustomobject]@{Version=[version]::new($base.Major,$base.Minor,[int]$os.BuildNumber,[int]$ubr.Value);IsServer=([int]$os.ProductType-ne1);Architecture=$architecture}
}
function Test-WindowsProductMatch {
    param([string]$Product,[object]$Context)
    if(($Product-match'^Windows Server')-ne$Context.IsServer){return $false}
    if($Product-match'ARM64'){return $Context.Architecture-eq'arm64'}
    if($Product-match'x64'){return $Context.Architecture-eq'x64'}
    if($Product-match'32-bit|x86'){return $Context.Architecture-eq'x86'}
    # Server entries without an architecture are the published x64 server product.
    return ($Context.IsServer-and$Context.Architecture-eq'x64')
}
function Get-WindowsPatchAssessment {
    param([object[]]$Rules,[object]$Context,[string[]]$Cve)
    $selected=if($Cve){@($Rules|Where-Object Cve -in $Cve)}else{$Rules}
    $matching=@(foreach($rule in $selected){
        $fixed=$null
        if(-not[version]::TryParse([string]$rule.FixedBuild,[ref]$fixed)){throw 'Invalid fixed build in reference data.'}
        if($fixed.Build-eq$Context.Version.Build-and$fixed.Major-eq$Context.Version.Major-and$fixed.Minor-eq$Context.Version.Minor-and(Test-WindowsProductMatch $rule.Product $Context)){$rule}
    })
    foreach($group in $matching|Group-Object Cve){
        # Use the earliest published fixing OS build for the exact servicing branch/product.
        $fix=$group.Group|Sort-Object {[version]$_.FixedBuild}|Select-Object -First 1
        [pscustomobject]@{Cve=$fix.Cve;Title=$fix.Title;Product=$fix.Product;InstalledBuild=$Context.Version.ToString();FixedBuild=$fix.FixedBuild;KB=$fix.KB;Source=$fix.Source;State=$(if($Context.Version-lt[version]$fix.FixedBuild){'BelowPublishedFix'}else{'AtOrAbovePublishedFix'})}
    }
    if($Cve){foreach($id in $Cve){if($id-notin@($matching|ForEach-Object Cve)){[pscustomobject]@{Cve=$id;State='NoMatchingProductRule';InstalledBuild=$Context.Version.ToString()}}}}
}
function Resolve-DriverPath {
    param([string]$Path)
    $path=Get-ExecutablePath $Path
    if(-not$path){return}
    if($path.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$path=$env:SystemRoot+$path.Substring(11)}
    elseif($path.StartsWith('\??\')){$path=$path.Substring(4)}
    elseif($path-match'(?i)^System32\\'){$path=Join-Path $env:SystemRoot $path}
    elseif($path-match'(?i)^\\Windows\\'){$path=$env:SystemDrive+$path}
    $path
}
function Get-InstalledDriverFiles {
    Get-Cached 'DriverFiles' {
        foreach($driver in Get-CimInstance Win32_SystemDriver -ErrorAction Stop){
            $path=Resolve-DriverPath $driver.PathName
            if($path){[pscustomobject]@{Name=$driver.Name;Path=$path;State=$driver.State;StartMode=$driver.StartMode;ServiceType=$driver.ServiceType}}
        }
    }
}
function Get-DriverHashMatches {
    param([object[]]$Entries,[object[]]$Drivers)
    $index=@{}
    foreach($entry in $Entries){
        if($entry.SHA256-notmatch'^[a-fA-F0-9]{64}$'){throw 'Invalid SHA256 in driver reference data.'}
        $hash=$entry.SHA256.ToLowerInvariant()
        if(-not$index.ContainsKey($hash)){$index[$hash]=New-Object 'System.Collections.Generic.List[object]'}
        $index[$hash].Add($entry)
    }
    foreach($driver in $Drivers){
        if(-not(Test-AllowedLocalPath $driver.Path)){continue}
        try{$hash=(Get-FileHash -LiteralPath $driver.Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
        catch{Set-CheckPartial 'Some installed driver images could not be hashed.' -ErrorRecord $_;continue}
        if($index.ContainsKey($hash)){foreach($entry in $index[$hash]){[pscustomobject]@{Name=$driver.Name;Path=$driver.Path;State=$driver.State;SHA256=$hash;ReferenceId=$entry.Id;Category=$entry.Category;Resources=$entry.Resources}}}
    }
}
