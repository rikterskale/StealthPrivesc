function Get-WindowsPowerShellPath {
    param([ValidateSet('x86','x64')][string]$Architecture='x64')
    if ($Architecture -eq 'x86' -and [Environment]::Is64BitOperatingSystem) { $directory = 'SysWOW64' }
    elseif ($Architecture -eq 'x64' -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $directory = 'Sysnative' }
    else { $directory = 'System32' }
    Join-Path $env:SystemRoot "$directory/WindowsPowerShell/v1.0/powershell.exe"
}

function Get-LocalAccountInventory {
    Get-Cached 'LocalAccounts' {
        # LocalAccounts is unavailable in 32-bit PowerShell on 64-bit Windows.
        # Query in a native helper without changing the assessment identity.
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and -not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            $code = @'
$ErrorActionPreference='Stop'
$maximum=__MAX__
$users=@(Get-LocalUser -ErrorAction Stop | Select-Object -First ($maximum+1) | Select-Object Name,Enabled,@{n='SID';e={[string]$_.SID}},PasswordLastSet,LastLogon,PasswordExpires,UserMayChangePassword)
$groups=@(Get-LocalGroup -ErrorAction Stop | Select-Object -First ($maximum+1) | ForEach-Object {
    $group=$_;$errorType=$null;$members=@()
    try {$members=@(Get-LocalGroupMember -Group $group -ErrorAction Stop | Select-Object -First ($maximum+1) | Select-Object Name,@{n='SID';e={[string]$_.SID}},ObjectClass,PrincipalSource)} catch {$errorType=$_.Exception.GetType().Name}
    @{Name=$group.Name;SID=[string]$group.SID;Members=$members;Error=$errorType}
})
@{Users=$users;Groups=$groups}|ConvertTo-Json -Depth 6 -Compress
'@
            (Invoke-ReadOnlyCommand -HostPath (Get-WindowsPowerShellPath -Architecture x64) -Payload ($code.Replace('__MAX__',[string]$script:Context.MaxItems))) | ConvertFrom-Json -ErrorAction Stop
        } else {
            $users=@(Get-LocalUser -ErrorAction Stop | Select-Object -First ($script:Context.MaxItems+1) | Select-Object Name,Enabled,@{n='SID';e={[string]$_.SID}},PasswordLastSet,LastLogon,PasswordExpires,UserMayChangePassword)
            $groups=@(foreach($group in @(Get-LocalGroup -ErrorAction Stop | Select-Object -First ($script:Context.MaxItems+1))) {
                $members=@();$errorType=$null
                try {$members=@(Get-LocalGroupMember -Group $group -ErrorAction Stop | Select-Object -First ($script:Context.MaxItems+1) | Select-Object Name,@{n='SID';e={[string]$_.SID}},ObjectClass,PrincipalSource)}
                catch { $errorType=$_.Exception.GetType().Name;Set-CheckPartial "Cannot resolve members of group: $($group.Name)" -ErrorRecord $_ }
                [pscustomobject]@{Name=$group.Name;SID=[string]$group.SID;Members=$members;Error=$errorType}
            })
            [pscustomobject]@{Users=$users;Groups=$groups}
        }
    }
}

function Get-ImageArchitecture {
    param([string]$Path)
    $stream=$null;$reader=$null
    try {
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $reader=New-Object IO.BinaryReader($stream)
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'Invalid PE image.' }
        $stream.Position=60;$offset=$reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt $stream.Length-6) { throw 'Invalid PE header offset.' }
        $stream.Position=$offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE signature.' }
        switch ($reader.ReadUInt16()) { 0x14c { 'x86' }; 0x8664 { 'x64' }; default { throw 'Unsupported PE machine.' } }
    } finally { if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()} }
}
