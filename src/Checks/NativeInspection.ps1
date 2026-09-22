function Invoke-NativeInspectionCheck {
    param([int]$Id)
    switch($Id) {
        72 {
            $result=[StealthPrivesc.NativeInspection]::Credentials($script:Context.MaxItems)
            foreach($item in $result.Items) {
                Add-Evidence $item.Target 'Credential Manager entry returned to the current logon session; secret bytes discarded in native code.' $item $(if($item.SecretReturned){'Medium'}else{'Information'}) 'Review whether saved credentials are necessary and restrict access to the logon session.'
            }
        }
        126 {
            $context=[StealthPrivesc.NativeInspection]::Desktop()
            Add-Evidence 'Interactive desktop' 'Foreground window and session-local idle time; title contents never retrieved.' $context
            return
        }
        133 {
            $result=[StealthPrivesc.NativeInspection]::Endpoints($script:Context.MaxItems)
            foreach($item in $result.Items){Add-Evidence ([string]$item.InterfaceId) 'Local RPC endpoint registration.' $item}
        }
    }
    if($result.Error){Set-CheckPartial "Native enumeration failed (error $($result.Error)); returned items may be incomplete."}
    if($result.Truncated){Set-CheckPartial 'Native enumeration exceeded MaxItems.'}
}
