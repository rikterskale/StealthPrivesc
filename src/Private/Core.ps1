function Add-Evidence {
    param([string]$Target, [string]$Observation, [object]$Evidence = @{}, [ValidateSet('Information','Low','Medium','High')][string]$Severity = 'Information', [string]$Remediation = '')
    if ($script:Current.Findings.Count -ge $script:Context.MaxItems) { Set-CheckPartial 'Finding limit reached; results are truncated.'; return }
    $script:Current.Findings.Add([pscustomobject]@{ Severity=$Severity; Target=$Target; Observation=$Observation; Evidence=$Evidence; Remediation=$Remediation })
}
function Set-CheckPartial {
    param([string]$Reason)
    if ($script:Current.Status -eq 'Completed') { $script:Current.Status = 'Partial' }
    if (-not $script:Current.Limitations.Contains($Reason)) { $script:Current.Limitations.Add($Reason) }
}
function Set-CheckSkipped { param([string]$Reason) $script:Current.Status='Skipped'; $script:Current.Limitations.Add($Reason) }
function Get-Cached {
    param([string]$Key, [scriptblock]$Factory)
    if (-not $script:Context.Cache.ContainsKey($Key)) {
        $before=@($script:Current.Limitations)
        $data=@(& $Factory)
        $script:Context.Cache[$Key] = @{Data=$data;Limitations=@($script:Current.Limitations|Where-Object{$_ -notin $before})}
    }
    foreach($limitation in $script:Context.Cache[$Key].Limitations){Set-CheckPartial $limitation}
    $script:Context.Cache[$Key].Data
}
function Get-Services { Get-Cached 'Services' { Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,PathName,StartName,StartMode,State,ProcessId } }
function Get-Tasks { Get-Cached 'Tasks' { Get-ScheduledTask -ErrorAction Stop } }
function Get-Applications {
    Get-Cached 'Applications' {
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
            foreach ($key in @(Get-RegistryChildren $root)) {
                $v = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                if ($v.PSObject.Properties['DisplayName']) {
                    [pscustomobject]@{ Name=$v.DisplayName; Version=$(if($v.PSObject.Properties['DisplayVersion']){$v.DisplayVersion}); Publisher=$(if($v.PSObject.Properties['Publisher']){$v.Publisher}); Location=$(if($v.PSObject.Properties['InstallLocation']){$v.InstallLocation}) }
                }
            }
        }
    }
}
function Get-RegistryChildren {
    param([string]$Path)
    if($script:RegistryVisited -ge $script:Context.MaxItems){Set-CheckPartial 'Registry enumeration item limit reached.';return}
    try {
        $remaining=$script:Context.MaxItems-$script:RegistryVisited
        $children=@(Get-ChildItem -LiteralPath $Path -ErrorAction Stop | Select-Object -First ($remaining+1))
        if($children.Count-gt$remaining){Set-CheckPartial 'Registry enumeration item limit reached.'}
        $script:RegistryVisited += [Math]::Min($children.Count,$remaining)
        $children|Select-Object -First $remaining
    }
    catch [System.Management.Automation.ItemNotFoundException] { @() }
    catch { Set-CheckPartial "Cannot enumerate registry key: $Path"; @() }
}
function Read-Registry {
    param([string]$Path, [string]$Name)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        try {
            if ($Name -notin $key.GetValueNames()) { return [pscustomobject]@{ State='Absent'; Value=$null } }
            [pscustomobject]@{ State='Present'; Value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        } finally { $key.Close() }
    } catch [System.Management.Automation.ItemNotFoundException] { [pscustomobject]@{ State='Absent'; Value=$null } }
    catch { Set-CheckPartial "Cannot read registry value: $Path [$Name]"; [pscustomobject]@{ State='Unknown'; Value=$null } }
}
function Add-RegistryEvidence {
    param([string]$Path, [string[]]$Names, [string[]]$SensitiveNames = @())
    foreach ($name in $Names) {
        $r=Read-Registry $Path $name
        $value=$r.Value
        if ($name -in $SensitiveNames -or $name -match '(?i)^(Password|DefaultPassword|PasswordViewOnly)$|secret|token|credential' -or $name -in @('AutoConfigURL','ProxyServer')) { $value=$(if($r.State -eq 'Present'){'[REDACTED]'}) }
        Add-Evidence "$Path\$name" 'Registry configuration; absent values may use OS defaults.' @{ State=$r.State; Value=$value }
    }
}
function Get-Limited {
    param([object[]]$Items)
    if ($Items.Count -gt $script:Context.MaxItems) { Set-CheckPartial 'Item limit reached; results are truncated.' }
    $Items | Select-Object -First $script:Context.MaxItems
}
function Get-BoundedFiles {
    param([string[]]$Roots, [int]$Depth=3, [string]$Pattern='.*', [switch]$Directories)
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    foreach($root in $Roots) { if($root -and (Test-AllowedLocalPath $root)){ $queue.Enqueue(@($root,0)) } }
    $visited=0
    while($queue.Count -and $visited -lt $script:Context.MaxItems) {
        $entry=$queue.Dequeue()
        try {
            $rootItem=Get-Item -LiteralPath $entry[0] -Force -ErrorAction Stop
            if($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint){Set-CheckPartial 'Reparse-point traversal skipped.';continue}
            $children=@(Get-ChildItem -LiteralPath $entry[0] -Force -ErrorAction Stop | Select-Object -First ($script:Context.MaxItems + 1))
        } catch [System.Management.Automation.ItemNotFoundException] { continue }
        catch { Set-CheckPartial "Cannot enumerate directory: $($entry[0])"; continue }
        foreach($item in $children) {
            $visited++
            if($visited -gt $script:Context.MaxItems){ break }
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){ continue }
            if(($Directories -or -not $item.PSIsContainer) -and $item.Name -match $Pattern){ $item }
            if($item.PSIsContainer -and $entry[1] -lt $Depth){ $queue.Enqueue(@($item.FullName,($entry[1]+1))) }
        }
    }
    if($queue.Count -or $visited -ge $script:Context.MaxItems){ Set-CheckPartial 'Filesystem traversal item limit reached.' }
}
function Get-ExecutablePath {
    param([string]$Command)
    if([string]::IsNullOrWhiteSpace($Command)){ return $null }
    $expanded=[Environment]::ExpandEnvironmentVariables($Command.Trim())
    if($expanded -match '^"([^"]+)"'){ return $Matches[1] }
    if($expanded -match '^(.*?\.(?:exe|com|sys|bat|cmd|ps1|vbs|dll))(?=\s|$)'){ return $Matches[1] }
    return ($expanded -split '\s+',2)[0]
}
function Get-UnquotedCandidates {
    param([string]$Command)
    if(-not $Command -or $Command.TrimStart().StartsWith('"')){ return }
    $path=Get-ExecutablePath $Command
    if(-not $path -or $path -notmatch '\s' -or -not [IO.Path]::IsPathRooted($path)){ return }
    foreach($match in [regex]::Matches($path,'\s+')) {
        $candidate=$path.Substring(0,$match.Index)
        if(-not $candidate.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)){ $candidate += '.exe' }
        $candidate
    }
}
function Test-PathAccess {
    param([string]$Path, [switch]$Registry)
    try {
        if(-not $Registry -and -not (Test-AllowedLocalPath $Path)){return $null}
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        $descriptor=$acl.GetSecurityDescriptorBinaryForm()
        $rights=if($Registry){ @{SetValue=2;CreateSubKey=4;WriteDacl=0x40000;WriteOwner=0x80000} } else { @{WriteDataOrAddFile=2;AppendOrAddDirectory=4;Delete=0x10000;WriteDacl=0x40000;WriteOwner=0x80000} }
        $allowed=@()
        foreach($right in $rights.Keys){
            $access=[StealthPrivesc.Native]::CheckAccess($descriptor,[uint32]$rights[$right],[bool]$Registry)
            if($access.Error){ Set-CheckPartial "AccessCheck failed for $Path (Win32 $($access.Error))." }
            elseif($access.Allowed){ $allowed+=$right }
        }
        [pscustomobject]@{ Path=$Path; Rights=$allowed; Owner=$acl.Owner; Method='Windows AccessCheck (DACL); mandatory integrity, locks and execution context require validation.' }
    } catch [System.Management.Automation.ItemNotFoundException] { $null }
    catch { Set-CheckPartial "Cannot assess ACL: $Path"; $null }
}
function Add-WritablePath {
    param([string]$Path, [string]$Reason, [switch]$Registry)
    if(-not $Path){ return }
    if(-not $Registry -and -not [IO.Path]::IsPathRooted($Path)){ Set-CheckPartial "Relative target needs working-directory resolution: $Path"; return }
    $access=Test-PathAccess $Path -Registry:$Registry
    if($access -and $access.Rights.Count){
        $severity=if($script:Context.Elevated){'Information'}else{'Medium'}
        Add-Evidence $Path $Reason $access $severity 'Review the ACL and remove unnecessary write/control rights. Validate the execution account and trigger before treating this as an escalation path.'
    }
}
function Add-ExecutableAccess {
    param([string]$Command, [string]$Reason)
    $path=Get-ExecutablePath $Command
    if(-not $path){return}
    Add-WritablePath $path $Reason
    if([IO.Path]::IsPathRooted($path)){ Add-WritablePath ([IO.Path]::GetDirectoryName($path)) "$Reason (parent directory candidate; replacement semantics require validation)." }
}
function Invoke-ReadOnlyCommand {
    param([string]$FileName, [string]$Arguments)
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$FileName; $info.Arguments=$Arguments; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$info
    try {
        [void]$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($script:Context.CommandTimeoutSeconds*1000)){ $process.Kill(); throw [TimeoutException]::new('Command timeout') }
        if($process.ExitCode -ne 0){ throw [InvalidOperationException]::new('Read-only command returned an error') }
        $stdout.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}
function Find-SecretMarkers {
    param([string]$Path)
    try {
        if(-not (Test-AllowedLocalPath $Path)){return}
        $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){return}
        if($file.Length -gt $script:Context.MaxFileBytes){ Set-CheckPartial 'Some files exceeded MaxFileBytes and were not read.'; return }
        # Content and matched values never enter the report.
        $content=[IO.File]::ReadAllText($file.FullName)
        $patterns=[ordered]@{
            PasswordAssignment='(?i)(?:password|passwd|pwd|cpassword)\s*["'']?\s*[:=]|<Password>|<Value>.*</Value>\s*</Password>'
            TokenAssignment='(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?access[_-]?key)\s*["'']?\s*[:=]'
            PrivateKey='-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
            ConnectionString='(?i)(?:connectionString|AccountKey|SharedAccessSignature)\s*='
        }
        $markers=@($patterns.Keys | Where-Object { [regex]::IsMatch($content,$patterns[$_]) })
        if($markers.Count){ Add-Evidence $file.FullName 'Possible secret-bearing content; values redacted, heuristic requires review.' @{Markers=$markers;Values='[REDACTED]';Bytes=$file.Length} 'Medium' 'Remove embedded secrets, restrict access and rotate exposed credentials after confirming exposure.' }
    } catch [System.Management.Automation.ItemNotFoundException] { }
    catch { Set-CheckPartial "Cannot inspect file: $Path" }
}
function Add-Artifact {
    param([string]$Path,[string]$Kind,[switch]$Inspect)
    try {
        if(-not (Test-AllowedLocalPath $Path)){return}
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        Add-Evidence $item.FullName "$Kind artifact present; presence alone does not prove credential exposure." @{IsDirectory=$item.PSIsContainer;LastWriteUtc=$item.LastWriteTimeUtc.ToString('o');Values='[REDACTED]'}
        if($Inspect -and -not $item.PSIsContainer){ Find-SecretMarkers $item.FullName }
    } catch [System.Management.Automation.ItemNotFoundException] { }
    catch { Set-CheckPartial "Cannot inspect artifact: $Path" }
}
function Test-AllowedLocalPath {
    param([string]$Path)
    # Local Win32 extended/device paths are not UNC shares. Extended UNC stays gated.
    if($Path-match'^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\'){return $true}
    if($Path-match'^\\\\\?\\[A-Za-z]:\\'){$Path=$Path.Substring(4)}
    # Network/domain opt-ins also govern UNC targets embedded in local configuration.
    if($script:Context.IncludeNetwork -or $script:Context.IncludeDomain){return $true}
    if($Path -match '^[\\/]{2}' -or $Path -match '^[^:]+::[\\/]{2}'){
        Set-CheckPartial 'Network filesystem target skipped; use -IncludeNetwork or -IncludeDomain.';return $false
    }
    if($Path-match'^[A-Za-z]:'){
        try{$drive=New-Object IO.DriveInfo($Path.Substring(0,3));if($drive.DriveType-eq[IO.DriveType]::Network){Set-CheckPartial 'Mapped network-drive target skipped.';return $false}}catch{}
    }
    return $true
}
function Export-Assessment {
    param([object]$Report,[string]$Directory)
    $directoryPath=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory)
    [void][IO.Directory]::CreateDirectory($directoryPath)
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6)
    $jsonPath=Join-Path $directoryPath "assessment-$stamp.json"
    $htmlPath=Join-Path $directoryPath "assessment-$stamp.html"
    $Report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $html=New-Object Text.StringBuilder
    [void]$html.Append('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Windows exposure assessment</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;background:#101820;color:#e5edf3}h1,h2{color:#82d4d4}article{border:1px solid #38505c;padding:16px;margin:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#b9cbd5}.High,.Medium{border-left:4px solid #ffbd69}summary{cursor:pointer}table{border-collapse:collapse}td,th{padding:8px;border:1px solid #38505c}</style><h1>Windows exposure assessment</h1>')
    [void]$html.Append('<p>'+[Net.WebUtility]::HtmlEncode($Report.Notice)+'</p><p>'+[Net.WebUtility]::HtmlEncode("$($Report.Computer) | $($Report.User) | Elevated: $($Report.Elevated) | $($Report.StartedUtc)")+'</p>')
    [void]$html.Append('<section aria-labelledby="status-summary"><h2 id="status-summary">Check status summary</h2><table><thead><tr><th scope="col">Status</th><th scope="col">Count</th></tr></thead><tbody>')
    foreach($status in @('Completed','Partial','Skipped','Unsupported','Error')){
        $count=$Report.Summary[$status]
        if($null-eq$count){$count=0}
        [void]$html.Append('<tr><th scope="row">'+[Net.WebUtility]::HtmlEncode($status)+'</th><td>'+[Net.WebUtility]::HtmlEncode([string]$count)+'</td></tr>')
    }
    [void]$html.Append('</tbody></table></section>')
    foreach($check in $Report.Checks){
        [void]$html.Append('<article><h2>'+[Net.WebUtility]::HtmlEncode("$($check.Id). $($check.Title)")+'</h2><p>'+[Net.WebUtility]::HtmlEncode("$($check.Status) / $($check.Coverage) | $($check.Findings.Count) evidence items")+'</p>')
        foreach($limitation in $check.Limitations){[void]$html.Append('<p><small>'+[Net.WebUtility]::HtmlEncode($limitation)+'</small></p>')}
        foreach($finding in $check.Findings){
            [void]$html.Append('<details class="'+$finding.Severity+'"><summary>'+[Net.WebUtility]::HtmlEncode("[$($finding.Severity)] $($finding.Target): $($finding.Observation)")+'</summary><pre>'+[Net.WebUtility]::HtmlEncode(($finding.Evidence | ConvertTo-Json -Depth 12))+'</pre><p>'+[Net.WebUtility]::HtmlEncode($finding.Remediation)+'</p></details>')
        }
        [void]$html.Append('</article>')
    }
    [void]$html.Append('</html>')
    [IO.File]::WriteAllText($htmlPath,$html.ToString())
    Write-Host "Reports: $jsonPath and $htmlPath"
}
function Read-SafeXml {
    param([string]$Path)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=$script:Context.MaxFileBytes
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    try{$document=New-Object Xml.XmlDocument;$document.XmlResolver=$null;$document.Load($reader);return ,$document}
    finally{$reader.Dispose()}
}
