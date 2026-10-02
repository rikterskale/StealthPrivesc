#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$pins = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'dependencies.psd1')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[void][IO.Directory]::CreateDirectory($Destination)
foreach ($name in @('Pester', 'PSScriptAnalyzer')) {
    $manifest = Join-Path $Destination "$name/$($pins[$name])/$name.psd1"
    if (-not (Test-Path -LiteralPath $manifest)) {
        Save-Module -Name $name -RequiredVersion $pins[$name] -Repository PSGallery -Path $Destination -Force -ErrorAction Stop
    }
    $data = Test-ModuleManifest -Path $manifest -ErrorAction Stop
    if ($data.Version.ToString() -ne $pins[$name]) { throw "Unexpected $name version." }
}
# Dependencies are installed only into this job's directory, never machine-wide.
$Destination
