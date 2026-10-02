#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Destination,
    [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$runtime=if($PSVersionTable.PSEdition-eq'Desktop'){'Desktop'}else{'Core'}
$architecture=if([Environment]::Is64BitProcess){'x64'}else{'x86'}
$output=Join-Path ([IO.Path]::GetFullPath($Destination)) "$runtime/$architecture"
if(Test-Path -LiteralPath $output){throw 'Use a new destination; native build output is never overwritten.'}
$components=@('Native','NativeInspection','NativeObjects','NativeHandles','NativeServices','NativeSessions','NativeSecrets','NativeSqlite','NativeSspi','NativeVault','NativeWifi','NativeNss','Console')
foreach($component in $components){if("StealthPrivesc.$component"-as[type]){throw 'Build native support in a fresh PowerShell process.'}}
[void][IO.Directory]::CreateDirectory($output)
$manifest=@(foreach($component in $components){
    $source=Join-Path $root ('src/'+$(if($component-eq'Console'){'NativeConsole.cs'}else{"$component.cs"}))
    $assembly=Join-Path $output "$component.dll"
    $options=@{Path=$source;OutputAssembly=$assembly;ErrorAction='Stop'}
    if($component-eq'NativeWifi'-and$PSVersionTable.PSEdition-eq'Desktop'){$options.ReferencedAssemblies=@('System.Xml.dll')}
    Add-Type @options
    $signed=$false
    if($SigningCertificate){
        $signature=Set-AuthenticodeSignature -LiteralPath $assembly -Certificate $SigningCertificate -HashAlgorithm SHA256 -ErrorAction Stop
        if($signature.Status-ne'Valid'){throw 'Native assembly signing did not produce a trusted signature.'}
        $signed=$true
    }
    [ordered]@{Component=$component;SourceSHA256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;AssemblySHA256=(Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash;Signed=$signed;Runtime=$runtime;Architecture=$architecture}
})
$manifest|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding UTF8
Write-Output $output
if(-not$SigningCertificate){Write-Warning 'These assemblies are unsigned build artifacts. The scanner rejects them until they have a valid trusted Authenticode signature.'}
