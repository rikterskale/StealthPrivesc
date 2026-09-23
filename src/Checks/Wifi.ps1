function Initialize-WifiNativeType {
    if ('StealthPrivesc.NativeWifi' -as [type]) { return }
    $options = @{ Path = (Join-Path $script:ModuleRoot 'NativeWifi.cs'); ErrorAction = 'Stop' }
    # Windows PowerShell's compiler does not reference System.Xml by default.
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $options.ReferencedAssemblies = @('System.Xml.dll') }
    Add-Type @options
}

function Invoke-WifiCheck {
    param([int]$Id)
    Initialize-WifiNativeType
    $result=[StealthPrivesc.NativeWifi]::Inspect($script:Context.MaxItems,($Id-eq95))
    if($result.Status){Set-CheckPartial "WLAN API unavailable (status $($result.Status))."}
    foreach($item in $result.Items){
        if($item.Status){Set-CheckPartial "A WLAN profile could not be queried (status $($item.Status)).";continue}
        $disabled=@($item.Validation|Where-Object{$_-match'(?i)^(PerformServerValidation|DisableUserPromptForServerValidation)=false$'}).Count-gt0
        if($Id-eq95){Add-Evidence $item.ProfileName 'Saved WLAN profile and current-token pre-shared-key recovery check; returned key erased inside collector.' @{Interface=$item.InterfaceId;Authentication=$item.Authentication;KeyPresent=$item.KeyPresent;PlaintextReturned=$item.PlaintextKeyReturned;Value='[REDACTED]'} $(if($item.PlaintextKeyReturned){'Medium'}else{'Information'})}
        elseif($item.Enterprise){Add-Evidence $item.ProfileName 'Enterprise Wi-Fi server-validation policy. Explicitly disabled validation or user prompting can permit unsafe server acceptance.' @{Authentication=$item.Authentication;Validation=$item.Validation;ExplicitWeakValidation=$disabled} $(if($disabled){'Medium'}else{'Information'})}
    }
    if($result.Truncated){Set-CheckPartial 'WLAN profile limit reached.'}
}
