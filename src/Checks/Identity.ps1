function Invoke-IdentityCheck {
    param([int]$Id)
    switch($Id){
        1 {
            $i=[Security.Principal.WindowsIdentity]::GetCurrent()
            try { Add-Evidence $i.Name 'Current effective Windows token.' @{SID=$i.User.Value;AuthenticationType=$i.AuthenticationType;ImpersonationLevel=$i.ImpersonationLevel.ToString();TokenType=[StealthPrivesc.Native]::TokenInteger(8);ElevationType=[StealthPrivesc.Native]::TokenInteger(18);Elevated=[bool][StealthPrivesc.Native]::TokenInteger(20);IntegritySid=@([StealthPrivesc.Native]::Sids(25))[0].Sid;Domain=$env:USERDOMAIN} }
            finally{$i.Dispose()}
        }
        2 { foreach($g in [StealthPrivesc.Native]::Sids(2)){ Add-Evidence $g.Sid 'Token group; enabled and deny-only attributes are reported separately.' @{Attributes=$g.Attributes;Enabled=[bool]($g.Attributes-band 4);DenyOnly=[bool]($g.Attributes-band 16);Administrators=($g.Sid-eq'S-1-5-32-544')} } }
        3 { foreach($g in [StealthPrivesc.Native]::Sids(11)){ Add-Evidence $g.Sid 'Restricted token SID.' @{Attributes=$g.Attributes} } }
        4 {
            $dangerous=@('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeCreateTokenPrivilege','SeLoadDriverPrivilege','SeDebugPrivilege','SeTakeOwnershipPrivilege','SeManageVolumePrivilege','SeRelabelPrivilege','SeTrustedCredManAccessPrivilege','SeEnableDelegationPrivilege')
            foreach($p in [StealthPrivesc.Native]::Privileges()){
                $severity=if($p.Name-in$dangerous -and -not $script:Context.Elevated){'Medium'}else{'Information'}
                Add-Evidence $p.Name 'Assigned token privilege; disabled privileges may be enableable by the token holder.' @{Enabled=$p.Enabled;Attributes=$p.Attributes;PotentiallyDangerous=($p.Name-in$dangerous)} $severity 'Apply least privilege to the account and its groups.'
            }
        }
        5 {
            $i=[Security.Principal.WindowsIdentity]::GetCurrent()
            try { $sids=@($i.User.Value)+@([StealthPrivesc.Native]::Sids(2)|ForEach-Object Sid)
                foreach($sid in $sids){
                    try {
                        foreach($right in [StealthPrivesc.Native]::AccountRights($sid)){ Add-Evidence $sid 'Local LSA account-right assignment; a new logon may be needed.' @{Right=$right} }
                    } catch {
                        $cause=$_.Exception.GetBaseException()
                        if($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -in @(5,1314)){
                            Set-CheckPartial 'LSA account-right enumeration requires access unavailable to the current token.' -ErrorRecord $_
                        } else { throw }
                    }
                }
            } finally{$i.Dispose()}
        }
        6 {
            foreach($u in Get-Limited @(Get-LocalUser -ErrorAction Stop)){ Add-Evidence $u.Name 'Local account.' ($u | Select-Object Name,Enabled,@{n='SID';e={[string]$_.SID}},PasswordLastSet,LastLogon,PasswordExpires,UserMayChangePassword) }
            foreach($g in Get-Limited @(Get-LocalGroup -ErrorAction Stop)){
                try { $members=@(Get-LocalGroupMember -Group $g -ErrorAction Stop | Select-Object Name,@{n='SID';e={[string]$_.SID}},ObjectClass,PrincipalSource); Add-Evidence $g.Name 'Local group membership.' @{SID=$g.SID.Value;Members=$members} }
                catch {Set-CheckPartial "Cannot resolve members of group: $($g.Name)" -ErrorRecord $_}
            }
        }
        7 { Add-Evidence 'Local account policy' 'net accounts output (localized).' @{Policy=(Invoke-ReadOnlyCommand "$env:SystemRoot\System32\net.exe" 'accounts')} }
        8 {
            foreach($s in Get-Limited @(Get-CimInstance Win32_LogonSession -ErrorAction Stop | Where-Object LogonType -in @(2,7,10,11))){ Add-Evidence ([string]$s.LogonId) 'Interactive, unlock, remote-interactive or cached logon session.' ($s | Select-Object LogonId,LogonType,StartTime,AuthenticationPackage) }
            foreach($u in Get-Limited @(Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop)){ Add-Evidence ([string]$u.Antecedent) 'User-to-logon-session association.' @{Session=[string]$u.Dependent} }
            foreach($profile in Get-Limited @(Get-CimInstance Win32_UserProfile -ErrorAction Stop)){Add-Evidence $profile.SID 'Current or previously used local profile.' ($profile|Select-Object SID,LocalPath,Loaded,LastUseTime)}
        }
        9 {
            foreach($p in Get-Limited @(Get-CimInstance Win32_UserProfile -ErrorAction Stop)){
                Add-Evidence $p.LocalPath 'User profile metadata.' @{SID=$p.SID;Loaded=$p.Loaded;Special=$p.Special}
                Add-WritablePath $p.LocalPath 'Current-token write/control permissions on a user profile.'
                try { [void]@(Get-ChildItem -LiteralPath $p.LocalPath -Force -ErrorAction Stop | Select-Object -First 1); Add-Evidence $p.LocalPath 'Directory listing is accessible; file-content readability is not implied.' }
                catch{ Set-CheckPartial "Profile listing unavailable: $($p.LocalPath)" -ErrorRecord $_ }
            }
        }
        10 { foreach($scope in @('Process','User','Machine')){ foreach($pair in [Environment]::GetEnvironmentVariables($scope).GetEnumerator()){$nameMatch=$pair.Key-match'(?i)pass|secret|token|credential|api.?key|connection.?string';$contentMatch=[string]$pair.Value-match'(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]|://[^/@\s:]+:[^/@\s]+@|-----BEGIN .*PRIVATE KEY-----';if($nameMatch-or$contentMatch){ Add-Evidence "$scope/$($pair.Key)" 'Potential credential-bearing environment variable; value redacted.' @{Value='[REDACTED]';NameMarker=$nameMatch;ContentMarker=$contentMatch;NonEmpty=(-not[string]::IsNullOrEmpty($pair.Value))} 'Low' }}} }
    }
}
