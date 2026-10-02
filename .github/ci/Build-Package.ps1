#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$destinationPath=[IO.Path]::GetFullPath($Destination)
foreach($source in @('src','data','docs','.github')) {
    $sourceRoot=[IO.Path]::GetFullPath((Join-Path $root $source)).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(($destinationPath+[IO.Path]::DirectorySeparatorChar).StartsWith($sourceRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Package destination cannot be inside a copied source directory.'}
}
if(Test-Path -LiteralPath $destinationPath){throw 'Use a new package destination; existing directories are never overwritten.'}
[void][IO.Directory]::CreateDirectory($destinationPath)
foreach($name in @('Invoke-StealthPrivesc.ps1','src','data','LICENSE','README.md','docs')){
    Copy-Item -LiteralPath (Join-Path $root $name) -Destination $destinationPath -Recurse
}
$catalog=@(& (Join-Path $destinationPath 'Invoke-StealthPrivesc.ps1') -ListChecks)
if($catalog.Count -ne 148 -or @(Get-ChildItem $destinationPath -Force | Where-Object Name -in @('.github','tests','tools')).Count){throw 'Runtime package is incomplete or includes CI-only files.'}
$hashes=@(Get-ChildItem $destinationPath -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{Path=$_.FullName.Substring($destinationPath.Length+1).Replace('\','/');SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$hashes | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $destinationPath 'SHA256SUMS.json') -Encoding UTF8
$destinationPath
