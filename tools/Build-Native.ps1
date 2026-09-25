#requires -Version 5.1
<#
.SYNOPSIS
Builds the native scanner payload (dist\stealthnative.dll + dist\scanner.exe).

.DESCRIPTION
Runs the .NET 10 SDK (C:\Program Files\dotnet\dotnet.exe) in Release against
..\stealthnative.csproj (src\Native\*.cs -> dist\stealthnative.dll) and then
..\scanner\scanner.csproj (host + embedded payload -> dist\scanner.exe).
The DLL must build first because the scanner project embeds dist\stealthnative.dll.
#>
[CmdletBinding()]
param([string]$Dotnet = 'C:\Program Files\dotnet\dotnet.exe')
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $Dotnet)) { throw "dotnet.exe not found at $Dotnet." }
$projects = @(
    (Join-Path $repo 'stealthnative.csproj'),
    (Join-Path $repo 'scanner/scanner.csproj')
)
foreach ($project in $projects) {
    Write-Host "Building $project" -ForegroundColor DarkGray
    & $Dotnet build $project -nologo -c Release --verbosity minimal
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed for $project (exit $LASTEXITCODE)." }
}
$dll = Join-Path $repo 'dist/stealthnative.dll'
$exe = Join-Path $repo 'dist/scanner.exe'
foreach ($artifact in @($dll, $exe)) {
    if (-not (Test-Path -LiteralPath $artifact)) { throw "expected artifact missing after build: $artifact" }
}
Write-Host "OK: $dll" -ForegroundColor DarkGray
Write-Host "OK: $exe" -ForegroundColor DarkGray
