#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination,[Parameter(Mandatory)][string]$ResultsDirectory)
$ErrorActionPreference='Stop'
[void][IO.Directory]::CreateDirectory($ResultsDirectory)
$state=[ordered]@{Status='NotRun';Reason='Package validation has not started.'}
try {
    $package=& (Join-Path $PSScriptRoot 'Build-Package.ps1') -Destination $Destination
    $archive=Join-Path $ResultsDirectory 'runtime.zip'
    Compress-Archive -Path (Join-Path $package '*') -DestinationPath $archive -Force
    $extracted=[IO.Path]::GetFullPath($Destination+'-extracted')
    if(Test-Path -LiteralPath $extracted){throw 'Use a new extraction destination.'}
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted
    $hashes=@(Get-Content (Join-Path $extracted 'SHA256SUMS.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    foreach($entry in $hashes) {
        $path=[IO.Path]::GetFullPath((Join-Path $extracted $entry.Path))
        if(-not $path.StartsWith($extracted+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid archive manifest path.'}
        if((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.SHA256){throw "Archive hash mismatch: $($entry.Path)"}
    }
    if(@(Get-ChildItem $extracted -File -Recurse).Count -ne $hashes.Count+1){throw 'Unexpected or missing archive files.'}
    $rows=@(& (Join-Path $extracted 'Invoke-StealthPrivesc.ps1') -ListChecks)
    if($rows.Count -ne 148){throw 'Archive catalog selection failed.'}
    foreach($path in @('LICENSE','data/reference/LOLBAS-LICENSE.txt','data/reference/LOLBAS-NOTICE.md','data/reference/LOLDrivers-LICENSE.txt','src/ThirdParty/PrivescCheck/LICENSE')) {
        if(-not (Test-Path -LiteralPath (Join-Path $extracted $path))){throw "Missing distribution notice: $path"}
    }
    $state.Status='Passed'; $state.Reason='Fresh archive extraction, catalog, notices, inventory and SHA256 checks passed.'
    $state.Files=$hashes.Count; $state.ArchiveSHA256=(Get-FileHash $archive -Algorithm SHA256).Hash
} catch {$state.Status='Failed';$state.Reason=$_.Exception.Message;Write-Error $_ -ErrorAction Continue}
finally {$state | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ResultsDirectory 'package.json') -Encoding UTF8}
if($state.Status -ne 'Passed'){exit 1}
