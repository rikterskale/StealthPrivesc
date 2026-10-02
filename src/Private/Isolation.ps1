function Invoke-IsolatedNativeQuery {
    param([ValidateSet('Pipe','Device','Handles')][string]$Kind, [string]$Target)
    # Passing inputs as a quoted JSON literal keeps paths out of executable syntax.
    $payload = @{Kind=$Kind;Target=$Target;ModuleRoot=$script:ModuleRoot;MaxItems=$script:Context.MaxItems;NativeAssemblyDirectory=$null}
    if ($script:Context.ContainsKey('NativeAssemblyDirectory')) { $payload.NativeAssemblyDirectory = $script:Context.NativeAssemblyDirectory }
    $literal = ConvertTo-VerificationLiteral ($payload | ConvertTo-Json -Compress)
    $code = @'
$ErrorActionPreference='Stop'
$p=ConvertFrom-Json __PAYLOAD__
$script:ModuleRoot=$p.ModuleRoot
. (Join-Path $p.ModuleRoot 'Private/Assessment.ps1')
$script:Context=@{NativeAssemblyDirectory=$p.NativeAssemblyDirectory}
if($p.Kind-eq'Handles'){
    Initialize-RequiredNativeSupport NativeHandles
    [StealthPrivesc.NativeHandles]::Inspect($p.MaxItems,200000)|ConvertTo-Json -Depth 8 -Compress
}else{
    Initialize-RequiredNativeSupport NativeObjects
    if($p.Kind-eq'Pipe'){[StealthPrivesc.NativeObjects]::InspectPipe($p.Target)|ConvertTo-Json -Depth 8 -Compress}
    else{[StealthPrivesc.NativeObjects]::Security($p.Target,$false)|ConvertTo-Json -Depth 8 -Compress}
}
'@
    $code = $code.Replace('__PAYLOAD__',$literal)
    Invoke-BudgetedCollector -Payload $code -HostPath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -TimeoutSeconds (Get-CollectorHelperTimeout) | ConvertFrom-Json -ErrorAction Stop
}
