#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'NOT RUN: Test-Sources requires Windows for native compilation. Run tools/Test-Project.ps1 on 64-bit Windows with PowerShell 5.1 and 7. This suite did not pass.'
    exit 2
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFiles = @(
    Get-ChildItem -LiteralPath $repoRoot -File
    foreach ($directory in @('src', 'tests', 'tools')) {
        Get-ChildItem -LiteralPath (Join-Path $repoRoot $directory) -Recurse -File
    }
)
$scripts = @($sourceFiles | Where-Object Extension -in @('.ps1', '.psm1', '.psd1'))
$parseFailures = @(
    foreach ($file in $scripts) {
        $tokens = $null; $parseErrors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        foreach ($parseError in $parseErrors) {
            '{0}:{1}: {2}' -f $file.FullName, $parseError.Extent.StartLineNumber, $parseError.Message
        }
    }
)
if ($parseFailures.Count) { throw ($parseFailures -join [Environment]::NewLine) }
Write-Host "PASS: parsed $($scripts.Count) PowerShell files under $($PSVersionTable.PSVersion)."

$manifestPath = Join-Path $repoRoot 'src/StealthPrivesc.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath
Import-Module $manifestPath -Force
$expectedExports = @(Import-PowerShellDataFile -LiteralPath $manifestPath | ForEach-Object FunctionsToExport)
$actualExports = @((Get-Module StealthPrivesc).ExportedFunctions.Keys)
if (Compare-Object $expectedExports $actualExports) { throw 'Module exports do not match the manifest.' }
Write-Host "PASS: module manifest $($manifest.Version) and exported functions."

# Compile every native collector without invoking its APIs. Individual suites
# exercise bounded native behavior and synthetic fixtures separately.
$nativeFiles = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'src/Native') -Filter '*.cs' -File)
foreach ($file in $nativeFiles) {
    if ($file.BaseName -eq 'NativeWifi') {
        & (Get-Module StealthPrivesc) { Initialize-WifiNativeType }
    } else {
        Add-Type -Path $file.FullName -ErrorAction Stop
    }
}
Write-Host "PASS: compiled $($nativeFiles.Count) native C# sources."

$jsonFiles = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'data') -Filter '*.json' -Recurse -File)
foreach ($file in $jsonFiles) {
    Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop | Out-Null
}
Write-Host "PASS: parsed $($jsonFiles.Count) bundled JSON files."
& (Join-Path $repoRoot 'tools/Update-Coverage.ps1') -Check
