function Invoke-IsolatedNativeQuery {
    param([ValidateSet('Pipe','Device')][string]$Kind,[string]$Target)
    if(-not('StealthPrivesc.NativeObjects'-as[type])){Add-Type -Path (Join-Path $script:ModuleRoot 'NativeObjects.cs') -ErrorAction Stop}
    # Native collector in-process; the caller's time budget still caps any slow third-party pipe/device callback.
    if($Kind-eq'Pipe'){$result=[StealthPrivesc.NativeObjects]::InspectPipe($Target)}
    else{$result=[StealthPrivesc.NativeObjects]::Security($Target,$false)}
    $result
}
