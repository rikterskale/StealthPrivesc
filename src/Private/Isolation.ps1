function Invoke-IsolatedNativeQuery {
    param([ValidateSet('Pipe','Device')][string]$Kind,[string]$Target)
    # Driver and pipe open callbacks can block in third-party code. Keep them outside the scanner process.
    $payload=@{Kind=$Kind;Target=$Target;Source=(Join-Path $script:ModuleRoot 'NativeObjects.cs')}|ConvertTo-Json -Compress
    $payload64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $code=@'
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
Add-Type -Path $p.Source
if($p.Kind-eq'Pipe'){$result=[StealthPrivesc.NativeObjects]::InspectPipe($p.Target)}
else{$result=[StealthPrivesc.NativeObjects]::Security($p.Target,$false)}
$result|ConvertTo-Json -Depth 5 -Compress
'@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code.Replace('__PAYLOAD__',$payload64)))
    $hostPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if([IO.Path]::GetFileNameWithoutExtension($hostPath)-notin@('pwsh','powershell')){$hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'}
    $json=Invoke-ReadOnlyCommand $hostPath "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $json|ConvertFrom-Json -ErrorAction Stop
}
